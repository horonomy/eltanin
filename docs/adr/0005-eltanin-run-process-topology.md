# ADR 0005: `eltanin run` stays alive as the lease-holding supervisor

## Status

Accepted (MVP 1.0, F-M1-008, HORO-845).

## Context

`eltanin run --profile <name> -- <program> [args...]` must request a
`ComputeLease` from the agent before the workload starts, and must be
able to release that lease when the workload exits. The agent binds a
lease to the *connecting peer process* (HORO-840's decision, not a
cgroup) and validates release via `WorkloadIdentity::compare_process`
(pid + `ProcessStartToken`, both survive `execve()`) and
`compare_executable` (`/proc/<pid>/exe`, which does **not** survive
`execve()` — it becomes the newly exec'd binary).

`docs/architecture/domain-model.md` (HORO-840) and
`docs/qa/feature-verification/F-M1-006.md` (HORO-840's QA record) named
a forward obligation for this ticket: *"`eltanin run` must connect as
the workload process itself"* — reasoning that a CLI which connects and
then forks the workload binds the lease to the CLI, "which then exits,"
revoking nothing but leaving no live process to hold it.

Three topologies were considered for *which process is the connecting
peer, and stays that peer for the lease's whole lifetime*:

1. **Exec-in-place**: `eltanin run` connects, gets granted, then
   `execve()`s into the workload — same pid, same `ProcessStartToken`,
   but a different `/proc/self/exe`.
2. **Fork, child connects**: `eltanin run` forks; the child connects,
   gets granted, then `execve()`s into the workload; the parent exits or
   waits.
3. **Supervising launcher**: `eltanin run` connects and stays alive for
   the entire run, holding the lease itself; the workload is a *child*
   it spawns via `Command`, not something it becomes.

## Decision

Use option 3. `eltanin run` never `execve()`s into the workload and
never exits before the workload does.

**Why 1 and 2 are not viable, not merely worse**: in both, the
lease-holding process's `/proc/self/exe` changes to the workload's
binary the instant it `execve()`s. `LeaseIssuer::validate` requires
`compare_executable == IdentityComparison::Same` before `ReleaseLease`
succeeds (`docs/architecture/domain-model.md`'s "Local IPC trust
boundary" section; `crates/eltanin-agent/tests/authz_release.rs`). After
the exec, no process in the system has the pre-exec executable path
anymore, so **no release is ever possible again for that lease** — it
can only lapse at TTL. That fails HORO-823's own security requirement
("signals, exit codes and failure cleanup must not accidentally leave
authorization/enforcement state behind") on the *ordinary success path*,
not just on a crash.

Option 3 keeps `eltanin run`'s pid, `ProcessStartToken`, and
`/proc/self/exe` unchanged for the lease's entire lifetime, so
`compare_process` and `compare_executable` both report `Same` and
`ReleaseLease` succeeds on ordinary exit.

**This changes, rather than ignores, the forward obligation it
supersedes.** The reasoning HORO-840 gave — "the CLI, which then exits"
— assumed a topology where the connecting process does not outlive the
workload. Under option 3 it does. The invariant this ADR commits to in
its place:

> The lease's binding-subject process must remain alive for the entire
> protected-compute window, must be an ancestor of the workload process,
> and any governed execution scope established for it (a future cgroup
> under F-M1-007) must be inherited by the workload before the workload
> is spawned.

## Consequences

- `eltanin run` is a supervisor, not a one-shot launcher-then-disappear:
  it blocks for the workload's entire lifetime, forwards signals,
  performs mid-run lease renewal (MVP has no lease "extend" — a renewal
  is a fresh `RequestLease` over freshly observed context, acquired
  before the old lease is released, so the resource is never
  momentarily unleased), and releases on exit. See
  `docs/product/CLI_CONTRACT.md`'s launch state machine.
- `docs/qa/feature-verification/F-M1-006.md`'s "known limitation" bullet
  on this exact topic is updated to point here rather than restate the
  now-superseded reasoning.
- **A named consequence, not a defect this ADR introduces**: because the
  connecting peer is always `eltanin` itself, the agent's kernel-observed
  `executable_path` evidence at decision time is `eltanin`'s own binary,
  never the workload's — a policy condition on `executable_path` (or a
  future `executable_hash`) cannot discriminate *which workload binary*
  is being run through `eltanin run`. This is a real, named MVP 1.0
  enforcement gap, not a topology defect to be traded away by picking
  option 1 or 2 instead (both of which are simply broken, per above).
  See `docs/product/SECURITY_MODEL.md`'s "Non-goals" section and
  `docs/product/POLICY_EXAMPLES.md` for exactly what MVP 1.0 can and
  cannot express as a result, and `docs/architecture/domain-model.md`'s
  F-M1-008 section for the forward obligation this leaves on F-M1-007+.
- If `eltanin run`'s own process is killed with `SIGKILL`, no cleanup can
  run; the lease persists until its own TTL. This is the accepted
  fail-closed floor (the lease cannot be renewed either, so enforcement
  installed under it cannot be extended past that TTL) — not a defect
  this ADR is responsible for closing.
