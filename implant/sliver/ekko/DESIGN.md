# ekko v3 — what changed relative to the previous Ekko, and why

Reference for the old implementation: branch `claude_ekko`, last revision
`1b961b83c` ("add debug output and probes"), which built on `2b36897fa`
("claude ekko v2"). Read it with:

```
git show 1b961b83c:implant/sliver/ekko/ekko.go
```

The motivation is documented in `Archive/ROOTCAUSE/INVESTIGATION.md`
(root-cause analysis of the sleep-mask hangs, with dumps and a confirmed
mechanism). This file maps each old failure mode to the specific change
that addresses it.

## 0. The structural change in one picture

OLD (`EkkoSleep`, `1b961b83c`) — the destructive span runs in Go:

```
Go:  enumerate threads, SuspendThread each (+ GetThreadContext to commit)
Go:  build 6 CONTEXTs + Img/Key/keybuf/OldProtect ON THE GOROUTINE STACK
Go:  arm 6 timers: RW -> encrypt -> delay -> decrypt -> RX -> SetEvent
Go:  WaitForSingleObject(hEvent)
Go:  resume loop: OpenThread each TID, ResumeThread drain (while prev>1)
     [bounded wait: sleepTime + 5s, then the Go resume loop runs anyway]
```

NEW (`Sleep`) — the destructive span runs entirely on the timer thread:

```
Go:  arm capture-probe timer, wait 100ms, validate   (nothing suspended)
Go:  enumerate + OpenThread peers only               (still nothing suspended)
Go:  build N+7 CONTEXTs + Img/Key/keybuf in ONE VirtualAlloc BLOCK
Go:  arm chain of NtContinue timers:
       SuspendThread x N, VirtualProtect(image,RW), encrypt,
       NtDelayExecution(sleepMs), decrypt,
       VirtualProtect(.text,RX), NtResumeProcess, SetEvent
Go:  WaitForSingleObject(hEvent, sleepMs + chain + 5s)   <- the whole span
     timeout -> one NtResumeProcess, return ErrChainTimeout
```

The invariant the new layout buys: **no Go code and no scheduler P is
required between the first SuspendThread and the final resume.** Every
observed hang lived in Go code that had to run inside that span.

## 1. The hang (~1/2200 cycles): the Go suspend/resume loops

Mechanism (confirmed twice from dumps + live experiments; INVESTIGATION
§3): while `resumeAndClose` resumes peers one at a time, sysmon — resumed
early in the enumeration order — preempts the beacon goroutine
(`schedtick` is stale by the whole multi-second sleep, so its first
`retake` pass past the 10ms threshold always fires). The preempted
goroutine yields; because it is `LockOSThread`-pinned, its thread parks in
`stoplockedm` and hands its P off; `handoffp`/`startm` hand the Ps to
*idle* threads — which `apc.go`/old Ekko still has suspended
(`SuspendThread` count 1, invisible to the scheduler, indistinguishable
from a normally parked thread). Both Ps are now owned by frozen threads;
the only code that would resume them can no longer run. sysmon cannot
rescue it: `retake` ignores Ps handed out via `nextp`.

- OLD: suspend loop and resume loop are Go code — both sides of the span
  are exposed (the old commit messages report "hangs in the suspend loop,
  hangs in the resume loop").
- NEW: both loops are chain steps on the timer-queue thread, which is not
  a Go thread and needs no P. The beacon goroutine is in one plain
  syscall (`WaitForSingleObject`) with its P in `_Psyscall` for the whole
  span; if sysmon takes the P and hands it to any thread, that is fine —
  no thread needs a P until `NtResumeProcess` has already run.

`LockOSThread` is kept, but only for a narrow reason: it keeps
`GetCurrentThreadId` stable so the enumeration's self-exclusion filter
cannot race a goroutine migration.

## 2. The resume path: drain loop -> one NtResumeProcess

OLD resumed with a per-thread drain loop (added in your last revision
because sysmon's async preemption can stack an extra suspend count):

```go
for i := 0; i < maxResumeDrain; i++ {
    r, _, _ := procResumeThread.Call(uintptr(p.hThread))
    if r == 0 || r == 1 || r == dwordMinusOne { break }
}
```

Two problems, one shared with `apc.go` (INVESTIGATION §5.1):

- The drain drives counts to zero even when the count belongs to Go's own
  async-preemption sequence. Since Go 1.14 on Windows, sysmon's `retake`
  → `preemptone` (proc.go:6942) sets the cooperative flag
  (`gp.preempt`, `stackguard0 = stackPreempt`) *and* calls `preemptM`,
  which holds the target thread suspended across
  `SuspendThread → GetThreadContext → SetThreadContext → ResumeThread`
  under `suspendLock` (os_windows.go:1179-1263). A concurrent
  `ResumeThread` from the drain lands inside that window: the thread
  starts running while `preemptM` is still about to patch its context —
  rare context corruption, then a crash. (Note the runtime releases
  `suspendLock` right after `GetThreadContext`, before the
  `SetThreadContext` — nothing else is allowed to touch the suspend
  count in that window.) This interleaving is an unobserved candidate
  (INVESTIGATION candidate 2d); the *observed* reason to delete the
  drain is simply the next bullet.
- The whole resume loop is Go code, so it is itself subject to the
  mechanism-#1 deadlock above.

NEW: `NtResumeProcess` as a chain step (and on the timeout path). It
decrements every thread exactly once — it *composes* with any outstanding
`suspendLock`-protected pair instead of clobbering it, and it is one
syscall, so preemption cannot interrupt a partial resume.

## 3. The timer-thread crashes: chain data moved off the goroutine stack

OLD kept `CtxThread`, `RopProtRW` … `RopSetEvt`, `Img`, `Key`, `keybuf`,
`OldProtect` as Go stack variables and baked their **addresses** into the
contexts as integers. Six `CreateTimerQueueTimer` calls run before the
wait, and each is a call site where Go may grow (move) the stack
(`morestack`). If that happens, the timer thread later dereferences
addresses of the *old* stack copy — jumping to garbage or decrypting with
a stale key: the "NtContinue-hijacked timer thread crashes during the
encrypted window" you reported. (Same bug class as `apc.go` §5.2: the RC4
key escaped to the heap but its address was a raw `uintptr`.)

NEW: one `VirtualAlloc` block holds everything the chain references
(`chainState` + one CONTEXT per step). Contexts point only into the block
or at system memory; nothing points at a Go stack, so stack growth is now
irrelevant. This is also why there is no `runtime.KeepAlive` dance: the
block is foreign memory with an explicit lifetime.

## 4. Ordering: capture-probe before enumeration (the new-thread gap)

Any thread created after the snapshot but before the chain suspends it
will execute the encrypted `.text` and fault (DEP) — a crash, not a hang.

- My first draft enumerated *then* waited 100ms for the probe: the
  process ran fully alive for 100ms with a stale snapshot, and the
  harness crashed instantly, twice (0xC0000005). 
- NEW order: probe first (100ms validation window while nothing is
  enumerated — threads born in it are caught by the snapshot below),
  then enumerate, then arm with the first due time only 20ms out. The
  gap is now arming time plus one step spacing. After the reorder: 500+
  harness cycles clean, including a 2000-cycle soak.

In a steady-state beacon the thread set is stable (the dumps show ~6-7
threads), so the gap is negligible there; heavy thread churn can hit it.

## 5. Timeout recovery: bounded wait + NtResumeProcess replaces "resume anyway"

OLD's bounded wait (`sleepTime + 5s`, `ErrEkkoTimeout`) fell through to
the Go resume loop — which, in a stall, is exactly the wrong medicine:

- if the stall happened mid-suspend, running Go code needs a P, and
  `exitsyscall` will hand Ps to the still-suspended idle Ms — mechanism
  #1 again, so the "recovery" hangs;
- if the stall happened after encryption but before decryption, the
  waking goroutine executes encrypted `.text` — the "recovery" crashes.

NEW: on timeout, one `NtResumeProcess` and return `ErrChainTimeout`. The
safety argument: this code is executing at all, so `.text` is executable
(either it was never encrypted, or the decrypt + RX steps already ran and
only `SetEvent` was lost); and the single decrement composes with any of
Go's own outstanding suspend/resume pairs. There are no watchdog timers
anywhere — the old design's per-peer "rescue" could resume peers into an
encrypted image, a guaranteed crash.

Related: every failure before the first timer due time (probe failure,
arming failure, peer cap exceeded) now aborts *before anything is
suspended* — nothing to rescue, the cycle is simply skipped. The old code
called `log.Fatalln()` (empty message, kills the beacon) on capture
failure; that is now an error return.

## 6. CONTEXT layout: full amd64 CONTEXT with init-time asserts

goEkko's `CONTEXT` omitted the 512-byte XMM save area: 720 bytes, with
`VectorRegister` at offset 256 instead of 768 and every later field
shifted. It worked by accident: the chain only sets fields below offset
256, NtContinue loads the garbage XMM into registers the chain never
uses, and `GetThreadContext` was only ever called with `CONTEXT_CONTROL`,
which writes nothing past offset 256. A full-context call would have
overflowed the struct.

NEW: full 1232-byte layout (`types.go`), asserted at `init` (size 1232;
Rsp at 152, Rip at 248, FltSave at 256; ustring 16 bytes). Layout drift
now panics at startup instead of corrupting state inside the encrypted
window.

## 7. Smaller changes

- Restore only `.text` to `PAGE_EXECUTE_READ` (old restored the whole
  image to `PAGE_EXECUTE_READWRITE` — broader detection surface, and it
  left `.data`/`.rdata` executable).
- No `OutputDebugStringA` probes compiled in (your last revision shipped
  `ekkoDebug = true` with format strings in `.data`).
- Peer cap (64) with safe refusal; all handles closed on every path,
  including enumeration errors.
- `DeleteTimerQueueEx(hQueue, INVALID_HANDLE_VALUE)` waits out in-flight
  callbacks before the block is freed (old used non-waiting
  `DeleteTimerQueue`).
- Step spacing 20ms with `NtDelayExecution(FALSE, …)` for the sleep —
  spacing replaces the per-peer `GetThreadContext` commit sync (and the
  guessed `commitDelayMs`): each suspension has long committed by the
  time any later step touches memory. The wait is non-alertable, so no
  unrelated APC can fire inside the window.

## 8. What was deliberately NOT changed

- The `NtContinue`-as-timer-callback ROP idiom: each context clones the
  captured timer-thread context, `Rsp -= 8` places the return slot on the
  captured dispatcher stack so each step returns into timer dispatch,
  `WT_EXECUTEINTIMERTHREAD` serializes all steps onto the thread whose
  stack the contexts share. This is the proven core of Ekko.
- Whole-image encryption with a random 16-byte RC4 key via
  `SystemFunction032` (double-XOR restores the plaintext).
- Toolhelp enumeration + `NtQueryInformationThread`
  (ThreadQuerySetWin32StartAddress) start-address filter.
- The main-executable assumption (`GetModuleHandleA(NULL)`) — still
  `--format exe` only.

## 9. Residual risks (documented, accepted)

- The new-thread gap (§4): window ≈ arming + 20ms; negligible for a
  steady beacon, real under thread churn.
- Ordering relies on distinct timer due times; a stalled timer thread
  stretches the cycle rather than reordering it, and the bounded wait
  turns a true stall into `ErrChainTimeout`.
- Timer-queue/NtContinue call stacks are heavily signatured by EDRs —
  that trade-off is inherent to the no-private-executable-memory design
  (INVESTIGATION §7.4).

## 10. Validation so far

`Archive/ROOTCAUSE/tools/harness-ekko` (calm = beacon-like, storm =
deliberate thread churn): 20 + 300 + 2000 calm and 200 storm cycles
clean; the two pre-fix crashes act as the negative control. At the old
~1/2200 hang rate this is suggestive (~68% chance of ≥1 hang if the old
rate still applied), not conclusive — the §8 bar is ≥20k cycles, ideally
a real beacon at a 5s interval (~28h).
