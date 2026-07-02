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
