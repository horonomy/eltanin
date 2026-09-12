# Privileged Enforcement Testing — Blast-Radius Control (HORO-1018)

This document is a **mandatory pre-test gate**, not background reading.
Read and satisfy it — in full, every time — before running any test
that touches privileged enforcement: cgroups, eBPF, device-node access
or revoke, `CONTROLLED_LAUNCH`, `DEVICE_ENFORCE`/`DEVICE_REVOKE`,
adversarial denial paths, or any physical-hardware E2E scenario
(Linux/NVIDIA or Apple Silicon).

North Star: **no protected compute without authorization**
([`docs/product/NORTH_STAR.md`](../product/NORTH_STAR.md)). This
document exists to make sure *proving* that invariant never itself
becomes an incident — a test that kills the wrong process is not a
smaller violation of "no protected compute without authorization," it's
a different failure entirely: unauthorized denial of *innocent* compute,
inflicted by the test harness itself.

Founder safety directive, 2026-09-12. This is additive governance: it
does not reinterpret or rewrite any already-completed ticket, ADR, or
Feature Verification Record. A historical record that predates this
document is not deficient for not having cited it.

## The core rule

> **Only a NEW disposable workload, created specifically for the test,
> may ever be denied, killed, or resource-constrained. Never test
> enforcement against the orchestrator, the current agent process or
> session, any other agent/sub-agent process, the current shell/tmux/
> SSH session, the Eltanin dev session itself, an unrelated Docker
> container or system service, or any other pre-existing process.**

If a test's only way to produce evidence is to attach enforcement to
something that already existed before the test started, the test design
is wrong — redesign it around a disposable workload (see "Safe
escalation order" below) rather than running it as-is.

## Blast-radius model

Before enforcement is attached to anything, the following must be true
and verified, not assumed:

- The safe/orchestrator context (this agent's own process tree, the
  terminal/tmux/SSH session running it, any supervising watchdog) is
  **outside** the cgroup/namespace/policy boundary the test will
  govern. It observes and can kill the test target; it must never be a
  descendant of, or share a controller with, the governed boundary.
- The governed boundary contains **exactly** the disposable test
  workload — nothing else was already running inside it, and nothing
  the test spawns escapes it.

**Forbidden ancestor scopes** — never attach `DEVICE_ENFORCE`,
`DEVICE_REVOKE`, or a governing cgroup to any of these, even
transiently:

- the root cgroup, or any cgroup that is an ancestor of the current
  shell/tmux/SSH session;
- the cgroup or process group containing the current Claude Code /
  agent orchestrator process;
- any cgroup shared with another running agent, sub-agent, or Codex
  session;
- `system.slice`, `user.slice` as a whole, or any pre-existing
  systemd unit not created by the test itself;
- any container/service that was running before the test started,
  Docker or otherwise.

## Mandatory preflight checklist (ABORT on any failure)

Every item below must pass before enforcement is attached. A failure
here **aborts the test** — it does not downgrade to a warning, and it
does not proceed with reduced scope.

1. The target workload is confirmed to be a process this test itself
   spawned in this run (its PID was captured from the spawn call, not
   guessed from `ps`).
2. The target workload's cgroup is a fresh leaf cgroup created by this
   test run, not an existing one.
3. No unrelated process is present in that leaf cgroup (enumerate its
   `cgroup.procs` and confirm the only PID is the test's own child).
4. The current orchestrator/agent process is confirmed to be outside
   the target cgroup (walk `/proc/self/cgroup` and compare).
5. The current shell/tmux/SSH session's controlling process is
   confirmed outside the target cgroup.
6. A watchdog/cleanup path exists and is confirmed reachable
   independent of the test target's own health (see "Watchdog and
   recovery," below).
7. The test has a hard timeout after which it force-cleans regardless
   of outcome.
8. Root/capability requirements for this specific test are the minimum
   needed (no blanket `sudo` for the whole test session) and are
   documented in the test itself.
9. If NVIDIA device nodes are involved, the specific device node(s) the
   test will touch are enumerated in advance and confirmed to not be
   in use by any pre-existing process (`fuser`/`lsof` on the node).
10. If eBPF is involved, the program/map being attached is scoped to
    the test's own cgroup (`BPF_CGROUP_*` attach types), never a
    system-wide attach point.
11. A rollback/detach step exists for every attach step, and is proven
    idempotent (safe to run twice, safe to run if the attach never
    happened).
12. The operator (human or agent) has confirmed which of the "safe
    escalation" levels below this test run is operating at, and has
    not skipped a level without documented justification.

## Disposable-workload test patterns

**DENY pattern**: spawn a new, purpose-built, harmless workload (e.g. a
tiny loop or a real GPU/CUDA kernel launch, per the escalation level),
attach the governing policy to *its* fresh cgroup only, assert it is
denied/killed, then tear down the cgroup. The workload must do nothing
of value outside the test — it exists to be denied.

**ALLOW pattern**: same shape, but assert the workload runs to
completion inside the authorized boundary. An ALLOW test that reuses an
already-running process as its "authorized" subject is invalid — it
must still be a fresh disposable spawn, so a false ALLOW can't hide
behind a process that would have kept running regardless of the policy.

## Safe escalation order

Move up a level only after the lower level has passed cleanly, with no
collateral-damage findings (see checklist below):

1. **Level 0 — fake backend.** No real device or kernel primitive
   involved; the `eltanin-backend` fake/simulation path only (this is
   the existing E1 evidence class). No blast radius beyond the test
   process itself.
2. **Level 1 — harmless canary in a disposable cgroup.** A trivial
   spawned process (e.g. `sleep`, a no-op busy-loop) governed by a real
   cgroup/eBPF policy on a freshly created leaf cgroup. Proves the
   enforcement mechanism attaches and detaches correctly with no real
   hardware risk.
3. **Level 2 — real NVIDIA device-node helper.** A small
   purpose-built helper that opens `/dev/nvidia*` without doing
   meaningful GPU work, governed the same way. Proves device-node-level
   access control without running an actual workload that could hang
   the GPU.
4. **Level 3 — real CUDA/GPU workload.** A real compute kernel launch,
   still on a freshly spawned disposable process, still in its own leaf
   cgroup. This is the level that produces genuine F-M1-007/HORO-841-844
   evidence.

Do not jump straight to Level 3 to save time — a Level 0/1 failure is
much cheaper to diagnose than a Level 3 one, and a Level 3 test run
under an unverified harness is exactly the scenario this document exists
to prevent.

## No spawn-then-restrict race

A workload spawned first and then moved into a governing cgroup has a
window, between spawn and attach, where it runs ungoverned — a real gap
an adversarial workload could exploit, and a real risk that a fast
workload does meaningful work (or escapes) before enforcement lands. Do
not treat this as an acceptable implementation detail.

Two designs avoid the race:
- **Clone-into-cgroup**: use `clone3` with `CLONE_INTO_CGROUP` so the
  child is placed into the target cgroup atomically at creation, never
  running outside it.
- **Stop-before-exec-then-release**: spawn the child stopped (e.g.
  `posix_spawn` with a held signal, or `PTRACE_TRACEME` before `exec`),
  attach it to the governing cgroup while it is stopped, then release
  it.

Which of these Eltanin adopts for real device-enforcement launches is a
design decision for HORO-841 to make and document (in an ADR, not only
in code comments) — this document requires that the decision be made
and recorded there, not that one specific mechanism is mandated here.

## Watchdog and recovery

- The watchdog/cleanup process must live **outside** the governed test
  scope at all times — it cannot itself be subject to the enforcement
  it is meant to recover from.
- Cleanup (cgroup removal, eBPF detach, device-node release) must be
  idempotent: safe to invoke whether or not the attach step succeeded,
  and safe to invoke twice.
- The watchdog must survive the test target's own failure — a target
  that hangs, panics, or is killed mid-test must not take the cleanup
  path down with it.

## Already-open-handle / revoke testing

`DEVICE_REVOKE` evidence (revoking access to an already-running,
already-authorized workload) requires a **dedicated sacrificial
helper** created solely to hold the handle being revoked. Never test
revoke against a real tool, a real running service, or any process not
purpose-built for this test. The helper should do nothing except hold
the resource open and report whether it was cut off.

## Apple Silicon specifics

- Never attach any test-time restriction to WindowServer, the current
  Claude Code process, or any existing running application — there is
  no OS-level mechanism on this platform this project has validated as
  safe to use for that, and per the E2 evidence-class definition,
  `DEVICE_ENFORCE`/`DEVICE_REVOKE` are **UNSUPPORTED/NOT_PROVEN** on
  Apple Silicon in this project's current scope. Apple Silicon tests
  under this document are functional (Metal compute runs, ALLOW/DENY
  application-level flow), never device-level enforcement claims.
- Any Metal/GPU test workload used for Apple Silicon evidence must be a
  new disposable process created by the test, exactly as on Linux — the
  "only a new disposable workload" rule is platform-independent.

## Linux/NVIDIA specifics

- Prefer a dedicated lab/test host with no other tenants. If the host
  is shared (e.g. the founder's own workstation, per the hardware
  validation runbook), the test must still confine itself to a fresh
  leaf cgroup and must verify the health of unrelated processes both
  immediately before and immediately after the test (see collateral-
  damage checklist).
- `nvidia-smi` (or equivalent) output before and after is part of the
  minimum evidence bundle for any test at Level 2 or Level 3 — not
  optional post-hoc diagnostics.

## Collateral-damage assertion checklist

A test is not PASS merely because the intended target was denied. It
must additionally demonstrate, with evidence (not assumption):

- [ ] The current agent/orchestrator session is unaffected and still
      responsive after the test.
- [ ] Any other agent/sub-agent session running concurrently is
      unaffected.
- [ ] The controlling shell/tmux/SSH session is unaffected.
- [ ] Any supervising watchdog process is unaffected and was never
      itself inside the governed boundary.
- [ ] Unrelated PIDs and host services present before the test are
      still present and healthy after the test (a before/after process
      list diff, not a spot check).
- [ ] All temporary policy/cgroup/eBPF state created for the test has
      been removed — `cgroup.procs` is empty and the cgroup itself is
      gone, eBPF programs are detached, any device-node lock is
      released.

A test report that omits this checklist, or checks only the target
outcome, is incomplete and must not be cited as HORO-841/844/1015
evidence.

## When to stop and ask the founder

Escalate rather than proceed if the only available evidence path for a
ticket requires any of the following:

- attaching enforcement to a broad existing cgroup because no
  narrower boundary is achievable on the available hardware;
- any action that risks the control plane (the machine running the
  agent orchestrator itself);
- interrupting an unrelated workload already running on shared
  hardware;
- rebooting or otherwise destabilizing the primary dev machine;
- a destructive, unrecoverable kernel or driver configuration change;
- disabling an existing security control (SELinux/AppArmor, Secure
  Boot, etc.) to make the test possible;
- relying on an undocumented or private platform hook (especially on
  Apple Silicon) with no public, supported API;
- a blast radius that cannot be bounded by the patterns in this
  document.

Use the standard escalation format (evidence, violated assumption,
options, recommendation, security/product/schedule impact) and continue
other unblocked work while waiting.

## Where this applies

This document governs, at minimum: HORO-841, HORO-844, HORO-790 (the
MVP 1.0 release gate's NVIDIA scenario), and HORO-1015 (physical M3 Max
QA — the Apple Silicon specifics section above, in particular). Any
future privileged-enforcement test in this repository is in scope by
default, whether or not the ticket that adds it explicitly says so.
