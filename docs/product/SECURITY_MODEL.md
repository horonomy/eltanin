# Security Model — MVP 1.0

This document states, truthfully, what MVP 1.0 does and does not defend
against. A release claim that exceeds this document is false and must be
corrected before it ships.

## Supported platform boundary

MVP 1.0 evidence comes from three distinct classes (HORO-1011 scope
amendment; see
[ADR 0006](../adr/0006-cross-accelerator-capability-and-memory-model.md)).
**Compatibility is not protection** — a platform being functionally
supported never by itself means device-level enforcement is claimed for
it:

- **E1 — Fake/simulated (CI).** Deterministic, no real accelerator, no
  device-level claim of any kind.
- **E2 — Apple Silicon (physical MacBook Pro M3 Max).** Real Metal
  accelerator functional evidence only: discovery, observation,
  attribution, and a full ALLOW/DENY application-level flow through a
  real GPU compute path. `DeviceEnforce`/`DeviceRevoke` are
  `Unsupported`/`NotEvaluated` on this platform by definition — this
  class never claims system-wide or kernel-level GPU protection.
- **E3 — Bare-metal Linux + NVIDIA.** The sole device-level enforcement
  evidence class. No containers-as-the-enforcement-boundary claim, no
  VMs. No AMD/Intel. **This is the mandatory hard security gate
  (HORO-841/844, F-M1-007) and is not replaceable by E2 evidence** — an
  Apple-only PASS is `BLOCKED ON E3`, never `READY`.

Single-host, single-user-session scope for MVP 1.0 on every platform.
Multi-tenant fleet/enterprise scenarios are explicitly future stages
(HORO-777+).

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

- **A backend reporting `Capability::ControlledLaunch` as `Supported`
  is not a device-enforcement claim.** `ResourceCapabilities` (HORO-1011,
  ADR 0006) evaluates each of nine capability dimensions independently;
  functional launch/observation support and device-level
  enforce/revoke support are separate dimensions with separate
  `SupportState`s precisely so one can never be silently read from the
  other. Only `Capability::DeviceEnforce`/`DeviceRevoke` at
  `SupportState::Supported`, backed by real E3 (Linux/NVIDIA) hardware
  evidence, is a device-level protection claim.
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

## Audit & explain evidence (F-M1-009, HORO-824) — `eltanin-audit`

**Audit is evidence, not authority.** `crates/eltanin-audit` writes one
append-only NDJSON record per `AuthorizationHandler` decision
(`eltanin-agent::authz::event::EventSink`), and `eltanin-explain`
(`crates/eltanin-audit/src/bin/eltanin-explain.rs`) reads that log back to
answer "what happened for this decision." Neither side may become part of
the ALLOW/DENY/release decision path itself:

- **The writer never reads.** `eltanin-agent` calls only
  `EventSink::record(&self, event) -> ()` — a signature that returns
  nothing and cannot fail the caller. `eltanin-agent` never calls
  `eltanin_audit::explain::{read_log, select, Selector}`; this is
  mechanically enforced by
  `crates/eltanin-agent/tests/audit_reader_isolation.rs`, which fails the
  build if any agent source file names the reader API.
- **A written record cannot become an authorization input.** Every
  authority-bearing type this crate mirrors (`ComputeLease`,
  `PolicyDecision`, `AuthorizationOutcome`, …) is deliberately
  `Serialize`-only or has no `serde` derive at all in `eltanin-core` — see
  `docs/architecture/domain-model.md`'s "Compute Lease" and "Authorization
  policy" sections. `eltanin-audit::record` mirrors each one with a
  hand-written `Recorded*` struct/enum that is `Deserialize`, but nothing
  in the codebase ever constructs a `ComputeLease` or `PolicyDecision`
  from a `RecordedLease*`/`RecordedPolicyDecision` — editing or replaying
  a log line changes what `eltanin-explain` reports, never what the agent
  authorizes.
- **Best-effort durability is an explicit MVP 1.0 limitation, by founder
  decision.** An audit write failure is reported to the caller
  (`AuditSinkError`) and logged to stderr by `eltanin-agent`'s
  `AuditEventSink` adapter, and counted via
  `AuditFileSink::failed_writes()` — but it never changes an
  already-computed `AgentResponse`. Reopening `EventSink::record`'s
  `-> ()` contract to make audit I/O authoritative was explicitly
  rejected: an agent that denies protected compute because its *disk* is
  unhappy is a new, separately-designed failure mode, not an MVP 1.0
  requirement. `failed_writes()` is a plain accessor, not wired into any
  wire-visible `AgentResponse`/`AgentStatusView` field — reopening that
  QA-PASSed protocol schema (HORO-838/839) was equally out of scope for
  this ticket. A future mode such as
  `require_durable_audit_before_commit` may make durability authoritative
  for deployments that need it, but is explicitly **not** implemented
  here.
- **Evidence-exists vs. not-found vs. possibly-lost is honestly
  distinguishable, where it's actually knowable.**
  `AuditFileSink::append` reserves its sequence number *before*
  attempting the write and never reuses it on failure, so a failed write
  leaves a permanent, structural gap in the sequence space rather than a
  silently reused id. `eltanin_audit::explain::LogScan::gaps` detects
  these gaps per issuer instance, ranging from sequence `0` (where every
  instance's sequence space starts) up to the highest sequence actually
  observed; `select()` reports `SelectionResult::Found` (the record
  exists), `PossiblyLost` (the id falls inside an observed gap — it may
  have failed to persist), or `NotFound` otherwise — which ordinarily
  means never issued, but **not always**: an id beyond the highest
  sequence an instance was ever observed to reach also reports
  `NotFound`, even if it was in fact reserved and lost, because nothing
  in a purely local log can tell "reserved then lost at the very end of
  the log" apart from "never issued" without an independent liveness
  signal. This is the honest limit of what a local, best-effort log can
  tell you: it cannot prove a record was never *issued* if persistence
  itself is what failed, and this limit is sharpest at an instance's
  trailing edge.
- **Redaction / log-sensitivity contract.** An audit record may contain
  process ancestry, executable paths, and cgroup/namespace hints — the
  same kernel-observed `ExecutionContext` evidence the authorization
  decision itself used — but never a lease's reusable authorization
  material, raw protected payload content, or secrets. Structurally: no
  `crates/eltanin-linux` collector reads `/proc/<pid>/cmdline` or
  `/proc/<pid>/environ` (only `stat`/`status`/`exe`/`cgroup`), so workload
  argv/env can never reach a record via that evidence path in the first
  place; see `crates/eltanin-audit/tests/redaction.rs`. The log file is
  created at mode `0600` (Unix) — see
  `crates/eltanin-audit/tests/sink_append.rs`.

Regression coverage
(`crates/eltanin-agent/tests/audit_sink.rs::an_audit_write_failure_never_changes_the_already_computed_response`)
proves both a grant and a denial remain unaffected when every audit write
fails, via a deterministic always-failing `Write` implementation injected
through `AuditEventSink::from_writer` — filesystem-based fault injection
(deleting/replacing the log file under an open file descriptor) proved
unreliable across platforms and was rejected as the test mechanism.

## Non-goals (explicit, not oversights)

Windows/macOS, AMD/Intel, hardware attestation, retroactive revoke of
already-open GPU handles unless directly proven otherwise by HORO-841,
production-grade L3/L4 bypass resistance, enterprise SSO/RBAC, SaaS
control plane in the per-compute hot path. See HORO-772 for the full
non-goal list.
