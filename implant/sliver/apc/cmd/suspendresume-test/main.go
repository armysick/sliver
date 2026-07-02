// suspendresume-test is a standalone Windows binary that isolates the
// SuspendThread/ResumeThread interaction with Go's runtime.
//
// It does NOTHING except:
//
//   1. Spawn a few background goroutines so the Go runtime creates
//      several Ms (mirroring a beacon's Go-runtime footprint).
//   2. In a loop:
//      a. Toolhelp32 snapshot.
//      b. SuspendThread on every image-based peer M (start address
//         inside our image, not us).
//      c. Sleep for ~2 seconds (matches beacon interval).
//      d. ResumeThread on the same TIDs, draining any accumulated
//         suspend count with a bounded loop.
//      e. Verify via NtQueryInformationThread(ThreadSuspendCount) that
//         every peer is back to count 0. If any residue is detected,
//         log it and count it.
//      f. Wait a short interval and repeat.
//
// No VirtualProtect. No SystemFunction032. No APC. No trampoline.
// No image encryption. No timer queue.
//
// If this binary leaks suspensions (residue detected in step e) or
// hangs the same way apc.Sleep does, we've proved the incompatibility
// is at the SuspendThread level itself and encryption is irrelevant.
//
// If this binary runs cleanly indefinitely, we've proved that
// SuspendThread/ResumeThread on Go Ms is fine on its own, and the
// beacon hangs are caused by something in the encryption pipeline
// (VirtualProtect, SystemFunction032, NtDelayExecution, or their
// interaction with alertable-wait + APC dispatch).
//
// Logs go to BOTH OutputDebugStringA (viewable in DbgView) AND to a
// file at %USERPROFILE%\Desktop\suspendresume-test.log so we retain
// data even if DbgView drops or the process wedges.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	threadQuerySetWin32StartAddress uintptr = 0x9
	threadSuspendCount              uintptr = 0x23
	maxResumeDrain                          = 1024
	dwordMinusOne                   uintptr = 0xFFFFFFFF

	// Match the beacon's sleep interval so the test experiences a
	// similar suspend duration per cycle.
	sleepDurationMs = 2000
	// Small gap between cycles, like the beacon's checkin-and-decide time.
	interCycleMs = 500
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procGetModuleHandleA         = kernel32.NewProc("GetModuleHandleA")
	procSuspendThread            = kernel32.NewProc("SuspendThread")
	procResumeThread             = kernel32.NewProc("ResumeThread")
	procOutputDebugStringA       = kernel32.NewProc("OutputDebugStringA")
	ntdll                        = syscall.NewLazyDLL("ntdll.dll")
	procNtQueryInformationThread = ntdll.NewProc("NtQueryInformationThread")

	logFile    *os.File
	logMu      sync.Mutex
	logStarted = time.Now()
)

func openLogFile() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	path := filepath.Join(home, "Desktop", "suspendresume-test.log")
	f, err := os.Create(path)
	if err != nil {
		return
	}
	logFile = f
	fmt.Fprintf(f, "suspendresume-test log opened at %s\n", time.Now().Format(time.RFC3339Nano))
}

func logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	elapsed := time.Since(logStarted).Seconds()
	stamped := fmt.Sprintf("[%9.3f] %s", elapsed, msg)

	logMu.Lock()
	defer logMu.Unlock()

	if logFile != nil {
		fmt.Fprintln(logFile, stamped)
		logFile.Sync()
	}

	// OutputDebugStringA, prefixed for DbgView filtering.
	dbg := "[sr] " + stamped + "\n"
	p, _ := windows.BytePtrFromString(dbg)
	if p != nil {
		procOutputDebugStringA.Call(uintptr(unsafe.Pointer(p)))
		runtime.KeepAlive(p)
	}
}

// imageNTHeaders64Prefix is just enough of IMAGE_NT_HEADERS64 to read
// SizeOfImage. Same layout as the beacon uses.
type imageNTHeaders64Prefix struct {
	Signature                   uint32
	Machine                     uint16
	NumberOfSections            uint16
	TimeDateStamp               uint32
	PointerToSymbolTable        uint32
	NumberOfSymbols             uint32
	SizeOfOptionalHeader        uint16
	Characteristics             uint16
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

func imageBounds() (imageBase, imageEnd uintptr) {
	imageBase, _, _ = procGetModuleHandleA.Call(0)
	if imageBase == 0 {
		return 0, 0
	}
	eLfaNew := *((*uint32)(unsafe.Pointer(imageBase + 0x3c)))
	nt := (*imageNTHeaders64Prefix)(unsafe.Pointer(imageBase + uintptr(eLfaNew)))
	imageEnd = imageBase + uintptr(nt.SizeOfImage)
	return
}

// enumeratePeers returns TIDs of image-based, non-current threads.
func enumeratePeers(currentTID uint32, imageBase, imageEnd uintptr) []uint32 {
	hSnap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(hSnap)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	if err := windows.Thread32First(hSnap, &te); err != nil {
		return nil
	}

	currentPID := uint32(windows.GetCurrentProcessId())
	var peers []uint32
	for {
		if te.OwnerProcessID == currentPID && te.ThreadID != currentTID {
			hThread, err := windows.OpenThread(windows.THREAD_QUERY_INFORMATION, false, te.ThreadID)
			if err == nil {
				var startAddr, retLen uintptr
				procNtQueryInformationThread.Call(
					uintptr(hThread),
					threadQuerySetWin32StartAddress,
					uintptr(unsafe.Pointer(&startAddr)),
					unsafe.Sizeof(startAddr),
					uintptr(unsafe.Pointer(&retLen)),
				)
				if startAddr >= imageBase && startAddr < imageEnd {
					peers = append(peers, te.ThreadID)
				}
				windows.CloseHandle(hThread)
			}
		}
		if err := windows.Thread32Next(hSnap, &te); err != nil {
			break
		}
	}
	return peers
}

// querySuspendCount reads the kernel suspend count without perturbing it.
func querySuspendCount(hThread windows.Handle) (uint32, bool) {
	var count uint32
	var retLen uintptr
	status, _, _ := procNtQueryInformationThread.Call(
		uintptr(hThread),
		threadSuspendCount,
		uintptr(unsafe.Pointer(&count)),
		unsafe.Sizeof(count),
		uintptr(unsafe.Pointer(&retLen)),
	)
	return count, status == 0
}

func main() {
	openLogFile()
	logf("test starting, pid=%d", os.Getpid())

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Spin up background goroutines so Go's runtime creates several
	// Ms — the exact target population we care about testing against.
	for i := 0; i < 8; i++ {
		go func(id int) {
			for {
				// Just enough activity to keep the goroutine schedulable
				// but not so much it dominates CPU.
				time.Sleep(50 * time.Millisecond)
			}
		}(i)
	}

	// Let the runtime settle: create Ms, park them on notes.
	time.Sleep(2 * time.Second)

	imageBase, imageEnd := imageBounds()
	if imageBase == 0 {
		logf("FATAL: GetModuleHandleA returned NULL")
		return
	}
	logf("image base=0x%x end=0x%x size=0x%x", imageBase, imageEnd, imageEnd-imageBase)

	currentTID := windows.GetCurrentThreadId()
	logf("currentTID=%d", currentTID)

	residueCyclesTotal := 0

	for cycle := 1; ; cycle++ {
		// Snapshot peers.
		peers := enumeratePeers(currentTID, imageBase, imageEnd)
		logf("cycle=%d enumerated peers=%d %v", cycle, len(peers), peers)

		// Suspend each peer.
		type suspEntry struct {
			tid     uint32
			hThread windows.Handle
			suspErr string
		}
		suspended := make([]suspEntry, 0, len(peers))
		for _, tid := range peers {
			hT, err := windows.OpenThread(
				windows.THREAD_SUSPEND_RESUME|windows.THREAD_QUERY_INFORMATION,
				false, tid,
			)
			if err != nil {
				logf("cycle=%d tid=%d SUSPEND_OPEN_FAIL err=%v", cycle, tid, err)
				continue
			}
			r, _, callErr := procSuspendThread.Call(uintptr(hT))
			if r == dwordMinusOne {
				logf("cycle=%d tid=%d SUSPEND_FAIL err=%v", cycle, tid, callErr)
				windows.CloseHandle(hT)
				continue
			}
			suspended = append(suspended, suspEntry{tid: tid, hThread: hT})
		}
		logf("cycle=%d suspended=%d/%d", cycle, len(suspended), len(peers))

		// Hold suspended for the beacon-like duration.
		time.Sleep(sleepDurationMs * time.Millisecond)

		// Resume each. Drain to zero using the same pattern as apc.Sleep.
		for _, e := range suspended {
			var drainCalls int
			var lastR uintptr
			for i := 0; i < maxResumeDrain; i++ {
				r, _, _ := procResumeThread.Call(uintptr(e.hThread))
				drainCalls++
				lastR = r
				if r == 0 || r == 1 || r == dwordMinusOne {
					break
				}
			}
			if drainCalls >= 2 || lastR == dwordMinusOne {
				logf("cycle=%d tid=%d DRAIN drainCalls=%d lastR=%d",
					cycle, e.tid, drainCalls, lastR)
			}
			windows.CloseHandle(e.hThread)
		}

		// VERIFY: query suspend count on every peer we touched.
		// If any is > 0, we've leaked a suspension in this exact cycle.
		leaks := 0
		for _, e := range suspended {
			hT, err := windows.OpenThread(windows.THREAD_QUERY_INFORMATION, false, e.tid)
			if err != nil {
				// Thread may have exited between resume and verify; skip.
				continue
			}
			count, ok := querySuspendCount(hT)
			if ok && count > 0 {
				leaks++
				logf("cycle=%d tid=%d RESIDUE_AFTER_RESUME count=%d", cycle, e.tid, count)
			}
			windows.CloseHandle(hT)
		}
		if leaks > 0 {
			residueCyclesTotal++
			logf("cycle=%d LEAK_SUMMARY leaks=%d residueCyclesTotal=%d",
				cycle, leaks, residueCyclesTotal)
		}
		if cycle%10 == 0 {
			logf("cycle=%d OK (residueCyclesTotal=%d)", cycle, residueCyclesTotal)
		}

		time.Sleep(interCycleMs * time.Millisecond)
	}
}
