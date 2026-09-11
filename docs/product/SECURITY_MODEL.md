# Security Model — MVP 1.0

This document states, truthfully, what MVP 1.0 does and does not defend
against. A release claim that exceeds this document is false and must be
corrected before it ships.

## Supported platform boundary

- Bare-metal Linux only. No containers-as-the-enforcement-boundary claim,
  no VMs, no Windows/macOS.
- NVIDIA GPUs only. No AMD/Intel.
- Single-host, single-user-session scope for MVP 1.0. Multi-tenant
  fleet/enterprise scenarios are explicitly future stages (HORO-777+).

## Threat levels

Adapted for MVP 1.0's Happy Path scope. Each level states what MVP 1.0
claims to resist, and what it explicitly does not yet resist.

**No claim below is validated yet.** No physical bare-metal Linux/NVIDIA
hardware evidence exists as of this document's initial version — every
"Claimed: denied" here is the *target* F-M1-007 is built to, pending
HORO-841's hardware spike. Treat every claim in this section as
provisional until §"Enforcement mechanism" below is updated with real
hardware evidence.

- **L1 — Unauthenticated/naive access.** A workload with no authorization
  path at all attempting to use the protected GPU. **Claimed (pending
  hardware validation): denied.**
- **L2 — Same-user, non-adversarial misuse.** A legitimate local user
  running a workload without going through the authorized launch path
  (`eltanin run`). **Claimed (pending hardware validation): denied**, on
  the supported enforcement boundary (new device-node opens after
  enforcement is active).
- **L3 — Same-user, mildly adversarial.** A user or process attempting to
  work around the CLI (e.g. invoking the underlying binary directly,
  reusing an inherited file descriptor). **Partially claimed** — new opens
  are denied; behavior for already-open handles inherited across
  cgroup/process boundaries is exactly what HORO-841's hardware spike
  must characterize before F-M1-007 claims anything here. Until that
  evidence exists, this document must not claim inherited-handle
  revocation.
- **L4 — Privileged/root adversarial, kernel-level bypass, hardware
  attestation bypass.** **Explicitly not claimed for MVP 1.0.** A root
  user can disable the agent, unload the eBPF program, or bypass
  enforcement outright. MVP 1.0 does not defend against a fully
  privileged local attacker; it defends against unauthorized *use through
  the normal compute path* by processes that do not already have root.

## What is NOT security in this system

- **GPU utilization ("nvidia-smi shows activity") is not authorization
  evidence and never overrides a deny decision.**
- **A previously-issued lease's mere existence does not extend past its
  expiry**, regardless of whether the underlying device handle is still
  technically open.
- **Process metadata (PID, path, parent, UID) is a signal into workload
  identity/provenance (F-M1-003), never a bypass of policy evaluation
  (F-M1-004).** Implemented as `eltanin_core::identity::Evidence<T>`
  (HORO-831): every field carries an explicit source (kernel-observed /
  best-effort / self-asserted) and can be `Missing`/`Unsupported` — there
  is no type-level way to treat a field as "trusted" without inspecting
  its actual source, and PID reuse has defined semantics
  (`WorkloadIdentity::compare_process`) rather than an implicit assumption.

## Local IPC trust boundary (F-M1-006, HORO-838)

The unprivileged client talking to the local authorization agent over
IPC is **never** trusted to assert its own identity or authorization
state. `crates/eltanin-protocol`'s wire types carry zero identity or
evidence fields — no request or response names a `WorkloadIdentity`,
`ExecutionContext`, or `Evidence<T>` — so there is no wire shape a client
could populate to claim a UID, executable path, or process ancestry
that overrides what the agent observes about the connecting peer itself.
Concretely (HORO-839): the agent reads the peer's `SO_PEERCRED`
credential (effective uid/gid, via `rustix`'s safe wrapper — never
hand-written unsafe `libc` `getsockopt`) and cross-checks it against a
fresh `/proc/<pid>/status` read through `eltanin-linux`'s collector
before treating the peer as authorizable; the two are reconciled rather
than naively compared, since `SO_PEERCRED` reports the peer's
**effective** uid while `/proc/<pid>/status`'s first `Uid:` field is the
**real** uid, and a setuid/setgid peer legitimately differs between
them. A client can name a `resource`/`action` (a request parameter
default-deny policy can only narrow, never widen) and a `lease_id` (a
lookup key, not a capability), and nothing else.

`AgentResponse` derives `Deserialize`, which structurally forbids
embedding `ComputeLease`, `PolicyDecision`, `DecisionReason`, or
`LeaseValidity` in any response — all four are `Serialize`-only by
construction elsewhere in this codebase. A client that fabricates a
`LeaseGranted`-shaped value has fabricated a display string; real
enforcement happens agent-side (cgroup device-BPF, F-M1-007), never by a
client presenting a response it holds. This closes the "no permanent
plaintext local bearer credential merely for convenience" requirement by
construction rather than by convention.

**Discharged by HORO-840**: `ReleaseLease` is a wire operation naming
another lease by id. `eltanin-core`'s `LeaseIssuer::revoke` alone only
checks issuer identity and sequence range — sequence numbers are
enumerable, so nothing in `eltanin-core` alone stops a client from naming
a lease it doesn't own. `eltanin-agent::authz::AuthorizationHandler`'s
release path calls `LeaseIssuer::validate` (which itself calls
`compare_process` and `compare_executable`, both required `Same`) before
ever calling `revoke`, and reports every non-`Valid` case — unknown
lease id, foreign issuer, cross-client mismatch, execve substitution,
already revoked, expired — identically as `ReleaseOutcome::Refused`, so
the wire response can never be used to enumerate other clients' leases.
See `docs/architecture/domain-model.md`'s "Local authorization agent
integration" section and `crates/eltanin-agent/tests/authz_release.rs`.

## Enforcement mechanism (validated, not assumed)

Linux cgroup v2 device-BPF (`BPF_PROG_TYPE_CGROUP_DEVICE` /
`BPF_CGROUP_DEVICE`) denies device-file access with `EPERM`. This is the
enforcement substrate — **not** CUDA API interception or `LD_PRELOAD`,
which are explicitly rejected as the security root (they are
user-space-bypassable by design).

The exact node/major/minor lifecycle for a supported NVIDIA GPU, and the
precise behavior for already-open handles, cgroup movement, and cleanup
on process/agent failure, must be proven on real hardware by HORO-841
*before* F-M1-007's real enforcement implementation claims any of it.
**No physical hardware evidence exists yet as of this document's initial
version** — see `docs/development/campaign-state.md` for current status.
This document will be updated with the actual validated boundary once
HORO-841 completes; until then, §"Threat levels" above states the
intended, not-yet-hardware-verified target.

## Non-goals (explicit, not oversights)

Windows/macOS, AMD/Intel, hardware attestation, retroactive revoke of
already-open GPU handles unless directly proven otherwise by HORO-841,
production-grade L3/L4 bypass resistance, enterprise SSO/RBAC, SaaS
control plane in the per-compute hot path. See HORO-772 for the full
non-goal list.
