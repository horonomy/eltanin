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

## Trusted Compute Session (F-M2-001, HORO-791) — MVP 2.0

A Trusted Compute Session (`eltanin_core::session::TrustedSession`) lets
a heavy developer prove intent once and then run multiple ordinary
protected workloads without a per-request prompt. It is layered **on
top of** the lease model above, never a replacement for it: a session
narrows *who may even ask* for a `ComputeLease`; it grants nothing by
itself, and `PolicySet::evaluate` still runs, unmodified, on every
`RequestLease`, session or no session.

**Headline trade-off, stated explicitly, not implied**: adopting the
caller's existing POSIX (terminal) session as the trust anchor means
intent is proven once per terminal and thereafter inherited by
everything spawned in that terminal, with no further act of intent — a
`postinstall` script run in the same shell after `eltanin session start`
is a session member exactly as much as the command the user actually
meant to authorize. This is within this document's L2/L3 threat-level
boundary (see "Threat levels" above), stated here so it is never
discovered as a surprise later. See
[ADR 0009](../adr/0009-trusted-compute-session.md) for the full design
record, the rejected alternatives, and the macOS `getsid` measurement.

**What a Trusted Compute Session does NOT prove**: it gates lease
*issuance*, never device-level access itself —
**`UNVERIFIED_ON_BARE_METAL`**. Device-level enforcement remains
F-M1-007/E3, still blocked on unavailable hardware (see
`docs/development/campaign-state.md`'s dependency blockers).

**Membership is kernel-unforgeable, not merely checked**: no syscall on
Linux or macOS lets an unprivileged process *join* an existing POSIX
session it did not create — only leave one. `eltanin_core::session::membership`
is the one function that decides admission, in a single combined check:
freshly collected evidence (not missing, not self-asserted) for the
requesting peer's session key, an exact key match against the session's
anchor, and `WorkloadIdentity::compare_process` reporting the anchor's
original leader process is still the *same* process (not a PID reused
by an unrelated later process). No client-supplied session id is ever
accepted anywhere in this design.

**No long-lived plaintext bearer secret is the trust root**:
`TrustedSession` is `Serialize` but never `Deserialize` (same discipline
as `ComputeLease`); `TerminateSession` carries no session id at all
(avoiding an enumeration oracle); `ListSessions` returns only sessions
the calling peer independently re-verifies membership of, never an
arbitrary lookup by id.

**Cgroup-scoped session membership is a declared, unbuilt seam** —
**`BLOCKED_ON_E3`**. It needs a privileged, non-delegated cgroup subtree
unavailable without bare-metal access. `eltanin_core::session::SessionAssurance`
gets a second variant (`CgroupScope`) only when E3 lands; nothing in
this release implements or assumes cgroup scoping.

**macOS support**: implemented, not deferred — see ADR 0009's measured
finding that `getsid` is unrestricted by session or ownership on this
campaign's Apple Silicon host, for any caller.

## Remembered Authorization Intent (F-M2-002, HORO-792) — MVP 2.0

An `Approval` (`eltanin_core::approval::Approval`) lets a user approve a
stable workload/launcher once and have Eltanin silently issue a fresh,
short-lived lease on every later restart, without re-prompting — only
when the current context still matches. It is a **second, independent**
pre-policy admission gate, layered on top of the lease model exactly
like a Trusted Compute Session is: an approval narrows *who may even
ask* for a `ComputeLease`; it grants nothing by itself, and
`PolicySet::evaluate` still runs, unmodified, on every `RequestLease`,
approval or no approval.

**Headline trade-off, stated explicitly, not implied**: a remembered
authorization records that this user approved this resource/action
through this launcher. It cannot distinguish which workload is launched
through it, and a compromised-but-unchanged binary re-fires its old
approval silently. See
[ADR 0010](../adr/0010-remembered-authorization-intent.md) for the full
disclosure — including that this offers no protection against an
already-approved binary compromised in place, no boundary against the
same user's other processes, and a materially weaker (`BestEffort`, not
`KernelObserved`) executable digest on macOS than on Linux.

**AC4 ("interpreter/container cases are context-scoped") is PARTIALLY
met.** The container/cgroup dimension is real and enforced by
comparison at recall time. The interpreter dimension (binding
authorization to *which script* an interpreter runs) is structurally
impossible today: `eltanin run`'s S4→S6 stage adjacency leaves no point
to attach workload identity before the lease decision, the protocol
carries no client-declared identity field, and
`crates/eltanin-audit/tests/redaction.rs` mechanically forbids reading
`/proc/<pid>/cmdline`. **Do not globally trust an interpreter
(Python/Node/bash/Docker) merely because the executable is trusted** —
this remains true after this ticket exactly as it was before it; a
future workload-attestation ADR-0005 amendment is the prerequisite for
closing this gap, tracked as a follow-up, not attempted here.

**`recall` is the one function that decides admission**, in a single
combined check mirroring `membership`'s own discipline: every material
dimension (owner uid, launcher path, launcher digest, cgroup path,
resource capability state, security posture) is re-observed fresh and
compared together, never as a lookup followed by a separate check.
Candidate lookup is keyed on `(resource, action)` only.

**`Deny` always overrides `Remember`/`Once`** for the same
`(resource, action)`, mirroring `PolicySet`'s own deny-overrides
convention.

**`Approval` is reconstructible from disk, unlike `ComputeLease`/
`TrustedSession`** — a deliberate, disclosed exception (see ADR 0010):
a durable approval must survive a restart to be useful at all, and the
on-disk bytes are only ever evidence to re-validate via `recall`, never
bare authority — a forged or tampered entry only buys the right to
*reach* policy evaluation, which can still independently deny.

**`UNVERIFIED_ON_BARE_METAL`** (gates lease issuance, never device
access) and **`BLOCKED_ON_E3`** (the cgroup dimension is observed and
compared only, never enforced at the device/cgroup layer) apply here
identically to how they already apply to Trusted Compute Session.

## Non-goals (explicit, not oversights)

Windows/macOS, AMD/Intel, hardware attestation, retroactive revoke of
already-open GPU handles unless directly proven otherwise by HORO-841,
production-grade L3/L4 bypass resistance, enterprise SSO/RBAC, SaaS
control plane in the per-compute hot path. See HORO-772 for the full
non-goal list.
