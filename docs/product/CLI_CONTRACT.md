# `eltanin run` — CLI Contract (F-M1-008, HORO-845)

This is the user-facing contract for `eltanin run`: exact argv grammar,
the launch state machine, the signal/cleanup contract, and the exit-code
taxonomy. Implementation lives in `crates/eltanin-cli`; the process
topology decision behind this contract is
[ADR 0005](../adr/0005-eltanin-run-process-topology.md).

## MVP 1.0 limitation, stated up front

**`eltanin run` cannot authorize based on which workload binary is being
run.** The agent's kernel-observed evidence at decision time describes
the *connecting peer* — which is always `eltanin` itself (see ADR 0005:
`eltanin run` stays alive as the lease-holding supervisor; it never
`execve()`s into the workload). A policy condition on `executable_path`
or `executable_hash` therefore evaluates against `eltanin`'s own binary,
never the workload's, and cannot distinguish "Alice ran `trusted-tool`"
from "Alice ran anything else" through `eltanin run`. This is a named
MVP 1.0 boundary, not an oversight — see
`docs/product/POLICY_EXAMPLES.md` for exactly what MVP 1.0 policy *can*
express through `eltanin run` (uid, gid, launcher path, process
ancestry, cgroup/governed-context membership) and what it cannot
(workload-executable identity). Closing this gap is a named forward
obligation on F-M1-007+, not scope for this ticket.

## Argv grammar

```text
eltanin run --profile <name> -- <program> [args...]
```

- `--profile <name>` names a client-side intent alias (see "Profiles"
  below) — it never reaches the wire; the agent's `RequestLease` carries
  only `{resource, action}`.
- `--` is **mandatory** and marks the end of `eltanin run`'s own flags —
  everything after it, including anything flag-shaped, is the workload's
  argv verbatim. Missing `--`, or an empty command after it, is a usage
  error (exit 64).
- Argv is read as `OsString` (`std::env::args_os()`), never lossily
  converted to `String` — arbitrary bytes (non-UTF-8 paths, embedded
  shell metacharacters) round-trip unchanged into the child's argv.
- The workload is launched via `std::process::Command` with an explicit
  argv array (`execvp` under the hood) — **no shell is ever invoked**.
  `eltanin run --profile p -- sh -c 'rm -rf /'` runs a program literally
  named `sh` with two literal arguments; nothing re-parses that string.
  Mechanically guarded by `crates/eltanin-cli/tests/architecture_no_shell.rs`.

## Profiles

A profile is a named, versioned document (`Versioned<ProfileDocument>`)
resolving `--profile <name>` to the `(ResourceIdentity, Action)` pair
`RequestLease` needs. It is a *client-side convenience alias only* — it
never selects, narrows, or otherwise influences the agent's `PolicySet`;
`resource`/`action` are ordinary `RequestLease` fields any client could
supply directly, and default-deny policy evaluation is unaffected by how
a client arrived at them.

Profile names are validated defensively (reject empty, `/`, `..`, and
names over 64 characters) since a future profile *loader* will resolve a
name to a file path — HORO-845 defines the name/document shape only; the
filesystem search path and loading is HORO-846's.

## Launch state machine

```
S0  parse argv                                    → exit 64 on failure
S1  resolve --profile → (ResourceIdentity, Action)  → exit 78 on failure
      (client-side only; no agent contact yet)
S2  establish the governed execution context        → exit 74 on failure
      MVP 1.0: the null context — eltanin run's own inherited cgroup.
      F-M1-007: create a per-run cgroup v2 scope and join it *here*,
      before connecting, so the agent's peer-credential collection
      (which already reads the connecting peer's cgroup path) observes
      the governed scope from the very first request.
S3  connect to the agent's Unix Domain Socket        → exit 69 on failure
      (ELTANIN_AGENT_SOCKET, else the agent's documented default path)
S4  send RequestLease{resource, action}; read exactly one response
      LeaseGranted{lease_id, remaining} → continue to S5
      LeaseDenied{reason}               → exit 77, workload never spawned
      Error{code}                       → exit 70, workload never spawned
S5  install signal handlers (before spawning, so no signal delivered
      between spawn and handler installation can skip cleanup)
S6  spawn the workload (Command::new(program).args(args))
      spawn failure → exit 126 (found, not executable) or 127 (not
      found); S9/S10 still run — enforcement was already applied at S4
S7  supervise: wait for the workload to exit while maintaining the
      lease (renewal loop — see below)
S8  the workload exits (normally or via signal)
S9  ReleaseLease{lease_id} — bounded retry; a failure here is a stderr
      warning, never a change to the workload's exit status
S10 tear down the governed execution context (after S9, never before)
S11 exit with the workload's own exit status (or the signal-derived
      status, or 76 if eltanin itself terminated the workload — see
      "Exit codes" below)
```

**Why no globally-permissive access window ever opens**: the workload
process does not exist until *after* S6, and S6 only runs after S4
returns `LeaseGranted`. The agent's own `AuthorizationHandler` calls
`ComputeBackend::enforce()` and grants only on `EnforcementResult::Allowed`
— enforcement precedes the grant in already-merged agent code
(`docs/architecture/domain-model.md`'s "Local authorization agent
integration" section). `eltanin run`'s entire obligation is: no
`Command::spawn` on any path that has not observed `LeaseGranted`.

**Lease renewal (within S7, HORO-846 — not yet implemented)**: like S2's
governed-context establishment, this describes the behavior HORO-846
must build, not something the current placeholder `main.rs` does yet.
MVP 1.0 has no lease "extend" — a renewal
is a fresh `RequestLease` over freshly observed context
(`docs/adr/0003-scoped-expiring-compute-lease.md`). At roughly half the
granted lease's remaining time, `eltanin run` requests a fresh lease; on
grant, it releases the old one (acquire-then-release, so the resource is
never briefly unleased and the old release cannot tear down the new
grant's enforcement — see `docs/qa/feature-verification/F-M1-006.md`'s
conditional-revoke coverage). A renewal that keeps failing is retried
until the current lease's `expires_at`; if no lease covers "now," the
workload is terminated (SIGTERM, a grace period, then SIGKILL if it
hasn't exited) and `eltanin run` exits 76 — fail-closed, never silently
continuing an unauthorized workload.

## Signal and cleanup contract

- Signal handlers are installed before the workload is spawned (S5).
- Every signal that would have reached the workload had `eltanin run`
  not been in the way is forwarded to it exactly once; `eltanin run`
  outlives the workload long enough to run S9/S10 afterward.
- A workload that exits normally (zero or non-zero status) or is
  terminated by a signal always reaches S9/S10 — release is attempted
  regardless of how the workload ended.
- A spawn failure (S6) still runs S9/S10: the lease was already granted
  and enforcement already applied at S4, so it must still be released
  and torn down even though the workload never ran.
- If `ReleaseLease` cannot be completed (agent unreachable, refused), a
  warning naming the `LeaseId` is printed to stderr; this **never**
  changes the workload's own exit status. Recovery/inspection is via
  `eltanin-explain --pid <eltanin-run's own pid>`
  (`eltanin_audit::explain::Selector::Pid`) — not via `RequestId`, per
  F-M1-009's forward obligation that a caller-supplied wire id is never
  used for audit correlation.
- If `eltanin run` itself receives `SIGKILL`, no cleanup can run at all;
  the lease persists until its own TTL. This is the accepted fail-closed
  floor (see ADR 0005).

## Exit codes

| Exit | Meaning |
|---|---|
| 0–125 | the workload's own exit status, passed through verbatim |
| 126 | `eltanin run` found the workload but could not execute it |
| 127 | `eltanin run` could not find the workload |
| 128+N | the workload was terminated by signal `N` |
| 64 | usage error (malformed argv, missing `--`, empty command) |
| 69 | the agent is unavailable (cannot connect / socket error) |
| 70 | the agent returned a protocol or internal error (`Error{code}`) |
| 74 | the governed execution context could not be established |
| 76 | authorization lapsed mid-run; `eltanin run` terminated the workload |
| 77 | the request was denied by policy (`LeaseDenied{reason}`) |
| 78 | `--profile` could not be resolved |

Exit 76 overrides the `128+N` convention when `eltanin run` itself sent
the terminating signal — stderr names the workload's own exit status
that this suppressed, so it's not silently lost.

**64/69/70/74/76/77/78 are disjoint from 126/127 and `128+N`, but not
from `0..=125`.** A workload that itself legitimately exits with status
77 (for example, the GNU Automake test protocol's "skipped" code) is
indistinguishable, by exit code alone, from `eltanin run` reporting a
policy denial — this is an accepted, unavoidable property of any Unix
process wrapper (`timeout`, `ssh`, and `sudo` all have it too), not a
guarantee this taxonomy can make. The stderr message
(`crate::failure::LaunchFailure::message`) is the reliable
disambiguator, always printed for every `eltanin run`-originated
outcome.

**126/127 ambiguity, named rather than hidden**: the table above
describes `eltanin run`'s *own* spawn-failure signal. If the workload's
own program legitimately exits with status 126 or 127 (e.g. a wrapped
shell script's own "command not found"), that status is passed through
via the ordinary `0..=125`-and-beyond passthrough rule above and is
**not** distinguishable from `eltanin run`'s spawn failure by exit code
alone — the same limitation as the 77 case above, stated separately here
since 126/127 is the one place this taxonomy's own codes and the
passthrough convention share a *name*, not just a numeric range.

## Deny and error messages

Every `LeaseDenied` and every internal failure prints a human-readable
message and a concrete next action, never just an exit code. Denial and
connection/protocol failure are always distinguished — `eltanin run`
never presents "the agent is unreachable" and "the request was denied"
as the same outcome, and never fabricates a more specific reason than
the wire actually carries: `AgentResponse::Error{code: ErrorCode::Internal}`
deliberately collapses several distinct internal causes (backend
failure, enforcement refusal, capacity exhaustion) into one wire
variant, by design (`docs/product/SECURITY_MODEL.md`) — `eltanin run`
reports that honestly rather than guessing which one occurred.
