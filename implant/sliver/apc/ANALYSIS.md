# Sleep obfuscation on Go: what we learned

Notes on why full-image sleep obfuscation (Ekko / APC style) is
fundamentally fragile on a Go implant, based on the extensive debugging
campaign that culminated in a control experiment isolating the root
cause.

## Executive summary

**The failure mode has nothing to do with encryption or the ROP chain or
NtContinue or any of the specific things we spent weeks chasing. It is a
deadlock between Windows' `SuspendThread` and Go's scheduler
P-handoff mechanism.** Every fix we tried up to and including a
self-heal sweep addressed symptoms; the underlying cause is a race that
we cannot eliminate from user code, only paper over.

## The observed behaviour

Across ~a dozen soak runs, both Ekko-based and APC-based:

- The beacon runs cleanly for anywhere from 5 to 500+ cycles.
- Then some peer OS threads end up permanently `Suspended` in
  Get-Process, `apc.Sleep` never returns, `beaconMain` never completes,
  and the beacon appears dead from the C2 side while the process itself
  is still alive.
- Manually calling `ResumeThread` on suspended threads via Process
  Hacker unsticks the process cleanly and it resumes normal operation.

That last fact is the whole diagnostic. **If the process were truly
frozen inside a `NtDelayExecution` call waiting for its own timer,
externally resuming an unrelated thread could not possibly help.** The
fact that it does means the process was not stuck in the sleep — it
was stuck in the Go scheduler, waiting for something that only another
running Go thread could produce.

## The mechanism

Every `windows.WaitForSingleObject`, `procNtDelayExecution.Call`,
`procResumeThread.Call`, `windows.OpenThread` — every single call into
a Windows API from Go — routes internally through
`syscall.SyscallN`. That function does three things:

1. `runtime.entersyscall()`: marks the current M (OS thread) as being
   in a syscall, and **releases its P (processor slot) into an idle pool
   where any other M may grab it.**
2. The actual kernel syscall.
3. `runtime.exitsyscall()`: tries to re-acquire a P. If the old P is
   still available it takes it back immediately (fast path). Otherwise
   it goes into a slow path that ultimately parks the M until sysmon
   or another M hands it a P.

Under normal conditions this is invisible. Under our conditions it is
lethal:

- Some other M grabs our P during `entersyscall` — most likely Go
  sysmon, doing routine work every ~20 ms.
- Between us releasing the P and us calling `SuspendThread` on peer
  Ms, that other M got scheduled. Now the M holding our P is one of
  the Ms we are about to freeze.
- We suspend it (along with everything else we suspend).
- Our next `exitsyscall` cannot get its P back — the owner is
  suspended. Slow path.
- Slow path parks our M, waiting for sysmon or some other M to hand
  us a P. **Sysmon is one of the Ms we suspended.** Nobody can hand
  us anything. We wait forever.

Manually resuming any suspended thread (as the operator did with
Process Hacker) frees the M that was holding our P — sysmon wakes up,
does its P-handoff routine, and everything moves again. The manual
resume works because it comes from *outside* our suspended set: the
operator's action is a thread that wasn't frozen.

## Why the beacon fails so much faster than the control test

We built a control experiment that does nothing but SuspendThread /
NtDelayExecution / ResumeThread on Go peer Ms in a loop. It survived
**377 cycles** (~15 minutes) before hitting this race, with
`residueCyclesTotal=0` throughout — meaning the suspend counters
themselves were clean; the hang wasn't a leaked count.

The beacon typically fails within 5–56 cycles. Why the gap?

**The beacon issues 20-30x more syscalls per cycle than the control
test.** Multiple SuspendThreads, OpenThreads, NtQueryInformationThreads
(for start address and suspend-count queries), VirtualAlloc,
VirtualFree, QueueUserAPC, NtWaitForSingleObject (alertable),
NtDelayExecution (for commit delay), self-heal probes,
ResumeThread drain loops, dozens more. Every one is a chance to lose
the P-handoff race described above.

So the race probability per syscall pair is small — call it 0.05% —
and the beacon simply rolls the dice enough times per cycle to
approach the "certain to happen every N minutes" regime.

**The beacon does not have a fundamentally different bug than the
control test. It just triggers the same race dozens of times more per
cycle.**

## Things that didn't work, and why

Every fix we tried before understanding this addressed a symptom:

- **LockOSThread**: prevented one specific self-suspension pattern
  (goroutine migrating between calling `GetCurrentThreadId` and
  `SuspendThread`). Fixed a real bug but didn't touch the P-handoff
  race.
- **Watchdog on the alertable wait**: bounds the wait but doesn't
  help when the deadlock is in `exitsyscall` after an unrelated
  syscall.
- **Drain-resume up to 1024 iterations**: fixes suspend-count
  accumulation, which turned out to not be happening (the control
  test proved counts stay at 0).
- **`GetThreadContext` to force-commit suspension**: worked around a
  different bug (asynchronous SuspendThread) but introduced its own
  hang path.
- **Self-heal sweep with `ThreadSuspendCount` query**: solves a
  problem that doesn't exist. `residueCyclesTotal=0` across 377
  cycles proves no leak accumulates.
- **Direct APC on our thread** (removed the Ekko timer-queue /
  NtContinue chain): eliminated an entire class of hangs but left the
  P-handoff race untouched.

Each was still a real fix for a real (or perceived) problem. But none
was the disease.

## Options for actually shipping this

We can't eliminate `entersyscall`/`exitsyscall` from user Go code —
the runtime routes every `LazyProc.Call` through it and there's no way
to bypass it without patching the Go runtime.

Given that, the options are:

**1. External watchdog (safety net).** Register a Windows
thread-pool timer *before* starting a sleep cycle. The callback runs
on a thread-pool worker — NOT an image-based thread, so we don't
suspend it. If the beacon's sleep runs longer than expected, the
timer fires and forcibly resumes every image-based thread. This
converts a permanent hang into a "beacon skips one cycle and
self-recovers" event. **This is the option we're implementing.**

  Important pitfall: the callback CANNOT be a `syscall.NewCallback`
  Go function, because Go's callback dispatch path
  (`cgocallback → needm → acquirep`) needs a P to run the callback's
  Go code — and if every Go M is suspended, no Ps are available. The
  callback deadlocks in the exact same way as the caller. **The
  callback must be a raw Windows API function pointer** (e.g.
  `procResumeThread.Addr()`), passed to `CreateTimerQueueTimer` with
  a Windows HANDLE as `lpParameter`. Windows will then call
  `ResumeThread(hThread)` directly with zero Go involvement.
  Implementation uses one one-shot timer per suspended peer thread;
  each timer's parameter is that peer's handle.

  Second pitfall (found in resc_att2): the watchdog must be armed
  BEFORE each SuspendThread, not after the whole suspend loop.
  The P-handoff deadlock is triggered by the very SuspendThread that
  captures the M holding our P, and it manifests in the exitsyscall
  frame of that call — so if we arm the watchdog only after the loop
  completes, the loop never completes and no timer is ever registered.
  The correct order is interleaved: per peer, OpenThread →
  CreateTimerQueueTimer → SuspendThread. Now the first Suspend that
  could deadlock already has its rescue timer ticking.

  Third pitfall (also found in resc_att2 via manual experimentation):
  when the watchdog fires and resumes a peer, that peer is running
  again. Proceeding to the encryption phase (which strips `.text` of
  its execute bit) while any peer is running WILL crash the process
  the moment that peer fetches its next instruction from `.text`.
  Manually resuming stuck peers via Process Hacker demonstrated the
  exact pattern: beacon unwedged, ran for a few seconds while more
  peers were suspended, then crashed once encryption started with a
  running peer that shouldn't have been.

  So the watchdog is only safe if we DETECT its firing and abort
  the encryption cycle. Implementation:
    1. After the suspend loop, cancelWatchdogs(peers) — waits for any
       in-flight callback so peer suspend counts are stable.
    2. verifyAllPeersSuspended(peers): NtQueryInformationThread(
       ThreadSuspendCount) on each. If any returns 0, a watchdog fired.
    3. If any peer isn't suspended → drain-resume everyone and return
       without encrypting. Beacon loses one cycle of memory
       obfuscation but survives.
    4. Otherwise → proceed to encryption normally.

  This makes the watchdog behave as a safety net that trades one
  obfuscation cycle for stability, rather than trading a permanent
  hang for a delayed crash.

  Fourth pitfall (found in resc_att3): the resume loop is ALSO a
  P-handoff race site. Every ResumeThread in the loop is a
  LazyProc.Call that does entersyscall/exitsyscall. If a just-resumed
  peer starts running (particularly with sysmon still among the
  suspended set and unable to do handoff), it can hold a P and
  deadlock our subsequent resume calls in exitsyscall. Cycle 85 of
  resc_att3 wedged with peer 6176 (freshly resumed, spinning CPU per
  operator observation) holding a P while peers 296, 5860, 8128,
  6672 remained suspended.

  Fix: arm resume-phase watchdogs BEFORE the resume loop. Symmetric
  with the suspend-phase inline arming. If the resume loop deadlocks,
  each peer's timer independently fires ResumeThread; whichever
  currently-suspended peer resumes first (e.g. sysmon among them)
  eventually releases a P for our stuck M. Timers are cancelled
  inline by resumeAndClose during its per-peer cleanup, so normal-
  path fast resumes never see them fire.

**2. Reduce per-cycle syscall count.** Fewer syscalls = fewer chances
to lose the race. Cache peer TID lists across cycles. Drop workarounds
that solve non-problems (self-heal). Skip debug probes in production.
Each removal reduces exposure probabilistically but doesn't fix the
race.

**3. Change primitive entirely.** Give up on `.text` encryption.
Encrypt only sensitive heap data (C2 URLs, session keys, config).
Peer-thread suspension becomes unnecessary. Cleaner, more reliable —
but loses code-signature protection against YARA. Right answer if
option 1+2 don't get us to acceptable stability.

## The takeaway

If you're building sleep obfuscation on Go and considering full-image
encryption:

- You *will* need to suspend peer threads to prevent Go's runtime from
  crashing on encrypted `.text`.
- You *will* eventually hit the Go P-handoff race.
- No amount of clever ROP chains, timer queue tricks, self-healing,
  or drain loops will fix it — the race is structural.
- Plan for it: build the safety net from the start, or use a design
  that doesn't need peer suspension.

Cobalt Strike / Havoc / other C-beacon Ekko implementations don't hit
this because C programs don't have a scheduler. Go does. Everything
downstream flows from that.


HUMAN NOTE:
"TID 6176 spinning is the villain. It's a Go M we just resumed (first in the resume list). Freshly running, holding a P, apparently in a tight loop somewhere in the Go runtime (probably scheduler-related since sysmon is one of the suspended peers and can't preempt anything). Our next ResumeThread call can't get its P back — deadlock."


## The watchdog design in one page

A walkthrough of `apc.Sleep`, in reading order, showing where each
rescue mechanism plugs in.

### The pieces, in `apc.go`

1. **Constants** (in the `const (...)` block near the top):
   - `watchdogMarginMinMs = 5000` / `watchdogMarginMaxMs = 15000` —
     floor/cap on the suspend-phase timeout. The actual timeout is
     `sleepMs + clamp(sleepMs, 5s..15s)` so short-interval beacons
     recover fast and long-interval beacons don't wait forever.
   - `resumeWatchdogMs = 8000` — fixed timeout for the resume-phase
     timers.
   - `wtExecuteOnlyOnce = 0x00000008` — Windows flag telling the
     timer to fire once and self-delete.

2. **The proc pointers** (in the `var (...)` block):
   - `procCreateTimerQueueTimer` — register a Windows thread-pool
     timer.
   - `procDeleteTimerQueueTimer` — cancel one.
   - `procResumeThread` — used as the *callback target itself* on
     the rescue path, not as something we call directly.

3. **`peerState` struct** — one row per suspended peer, carrying
   its TID, an open handle, and a timer handle.

4. **`watchdogTimeoutMs(sleepMs)`** — the proportional-margin
   formula.

5. **`suspendAndArmPeers()` — where the *suspend-phase* watchdogs
   get armed.** Look for:

   ```go
   // Arm the watchdog BEFORE the SuspendThread that
   // might deadlock us.
   var hTimer uintptr
   wdRet, _, _ := procCreateTimerQueueTimer.Call(
       uintptr(unsafe.Pointer(&hTimer)),
       0,                            // default timer queue
       procResumeThread.Addr(),      // <-- KEY LINE: raw API pointer
       uintptr(hThread),             // arg passed to ResumeThread
       uintptr(wdTimeoutMs),         // deadline
       0,                            // period (0 = one-shot)
       wtExecuteOnlyOnce,
   )
   r, _, _ := procSuspendThread.Call(uintptr(hThread))
   ```

   The critical thing: the timer's *callback* is
   `procResumeThread.Addr()` itself. When the timer fires, Windows
   calls `ResumeThread(hThread)` directly — no Go code involved.
   That's what makes the rescue work when Go's runtime is
   deadlocked.

6. **`cancelWatchdogs(peers)`** — right after the suspend loop
   returns, cancels all suspend-phase watchdogs so they can't fire
   during encryption. Passes `INVALID_HANDLE_VALUE` as
   `CompletionEvent`, which makes `DeleteTimerQueueTimer` block
   until any callback that's mid-flight finishes.

7. **`verifyAllPeersSuspended(peers)`** — queries
   `NtQueryInformationThread` with class `ThreadSuspendCount`
   (`0x23`) for each peer. Returns `false` if any peer's count is 0,
   meaning its watchdog fired and un-suspended it. This is the
   "abort encryption" check.

8. **`armResumeWatchdogs(peers)` — the *resume-phase* watchdogs.**
   Same shape as the arming inside `suspendAndArmPeers`, called
   just before `resumeAndClose`:

   ```go
   armResumeWatchdogs(peers)
   resumeAndClose(cycle, peers)
   ```

9. **`resumeAndClose()`** — for each peer: cancel its timer
   (blocking wait for in-flight callback), drain-resume, close
   handle. Same order for suspend-phase timers (already cancelled
   by `cancelWatchdogs` earlier, so cheap no-op) and for
   resume-phase timers (the important ones).

10. **The rescue-detection log line** at the end of `Sleep()`:

    ```go
    elapsedMs := uint64(time.Since(sleepStart).Milliseconds())
    if elapsedMs > sleepMs+watchdogMarginMinMs {
        dbg("cycle=%d WATCHDOG likely RESCUED (elapsedMs=%d intendedMs=%d)",
            cycle, elapsedMs, sleepMs)
    }
    ```

### The overall flow, once through `Sleep`

1. `LockOSThread` + logging + setup.
2. `suspendAndArmPeers` — enters iteration; for each peer, **arms
   suspend-phase watchdog, then `SuspendThread`**. If any Suspend
   deadlocks, its own peer's watchdog fires and un-suspends it,
   breaking the deadlock.
3. `cancelWatchdogs` — kill all suspend-phase timers before we
   enter the encrypted window.
4. `verifyAllPeersSuspended` — did any watchdog fire during step
   2? If yes, some peer is running; abort encryption (safe-abort
   path also arms resume-phase watchdogs before its resume).
5. `NtDelayExecution` commit delay.
6. `QueueUserAPC` + alertable wait — the encrypt/sleep/decrypt
   trampoline runs.
7. `armResumeWatchdogs` — arms resume-phase timers before the
   vulnerable resume loop.
8. `resumeAndClose` — for each peer: cancel its resume-phase
   timer, drain-resume, close. If the resume loop deadlocks,
   resume-phase timers fire and un-suspend other peers, freeing a
   P and breaking the deadlock.
9. Rescue detection via elapsed-time comparison.

### The key insight, in one sentence

**The rescue mechanism works precisely because Windows timer
callbacks execute on thread-pool workers whose start address lives
in `ntdll` — not in our image — so our own peer-suspension filter
always excludes them, and they can always run even when every Go M
is frozen.** That, combined with the callback being a raw Windows
API pointer (not a Go callback that would need a P to dispatch), is
what makes the whole design possible.


## TODO — future work

### 1. Full per-section protection restore

The trampoline currently restores only `.text` to `PAGE_EXECUTE_READ`
at the end of each cycle. `.rdata` and `.data` (and everything else
past `.text`) are left as `PAGE_READWRITE` — the state they were
temporarily raised to for the encryption pass. There is no RWX
anywhere in the image, which is the primary OPSEC goal, but `.rdata`
being writable in between cycles is a smaller signal that a
suspicious scanner could still pick up.

The complete fix walks the section headers at init, captures each
section's `(VirtualAddress, VirtualSize, Characteristics)`, and
during decrypt restores each section to its original protection
derived from `Characteristics` bits (`IMAGE_SCN_MEM_READ` / `_WRITE`
/ `_EXECUTE`).

Complication: the trampoline is a single hand-encoded x64 blob with
hard-coded offsets. Iterating over N sections means either a loop
in the machine code or N unrolled `VirtualProtect` calls. Probably
cleaner to precompute a small array of `{addr, size, encProt,
decProt}` tuples in Go and iterate it in a tight ASM loop.

Verification: `moneta -pid <beacon>` while idle should show `.text`
as `RX`, `.rdata` as `R`, `.data` as `RW`, and no `RWX` anywhere in
the image mapping. The 96-byte trampoline RWX region outside the
image will still show up but is far less signature-worthy.

### 2. Backport the watchdog to the Ekko branch — YOLO

We deferred Ekko as unsalvageable, but the watchdog design is
orthogonal to the encryption mechanism. The P-handoff race — which
is the *only* thing the watchdog fixes — exists identically in Ekko:
same peer-suspend loop, same LazyProc.Call syscall churn, same
sysmon-and-M-hold-our-P deadlock.

Concretely, port to `claude_ekko`:
- `suspendAndArmPeers` (inline arm-before-Suspend).
- `cancelWatchdogs` + `verifyAllPeersSuspended` before Ekko's
  timer-queue kicks off.
- `armResumeWatchdogs` before Ekko's resume loop.
- Same rescue-detection log line.

Prediction: **this will improve Ekko's stability but won't fully
fix it**, because Ekko's other failure modes (NtContinue-hijacked
thread-pool worker corrupting its stack, `RtlCaptureContext`
priming-wait timing out) are independent of the P-handoff race and
aren't in the watchdog's coverage.

But if it turns 5-minute hangs into 30-minute hangs, that's still
interesting data — it tells us how much of Ekko's failure surface
is P-handoff vs how much is ROP-chain-specific. And if by some
miracle Ekko becomes usable with the watchdog, we have a second
option for hosts where APC misbehaves.

Belt-and-braces value only; not on the critical path for shipping
APC.
