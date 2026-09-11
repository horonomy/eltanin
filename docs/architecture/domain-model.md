# Domain Model

Canonical vendor-neutral types living in `crates/eltanin-core`, defined
Feature-by-Feature as MVP 1.0 progresses. This document tracks what
exists and which ticket owns it — see the crate's own rustdoc for exact
field-level detail.

## Resource domain (F-M1-001, HORO-825) — `eltanin_core::resource`

| Type | Purpose |
|---|---|
| `ResourceVendor` | Opaque string-backed tag for which vendor owns a resource (e.g. `"fake"`; a real vendor's tag is defined by that vendor's own adapter crate, never named here). Round-trips any tag without data loss — no lossy `Unknown` placeholder. |
| `ResourceKind` | Opaque string-backed tag for the resource class (e.g. `"gpu"`), same round-trip guarantee as `ResourceVendor`. |
| `ResourceIdentity` | Stable identity: vendor + kind + opaque `local_id`. |
| `Capability` | One of DISCOVER/OBSERVE/ATTRIBUTE/AUTHORIZE/ENFORCE/REVOKE/ATTEST. |
| `ResourceCapabilities` | The capability set a backend actually supports for a resource — a value type so downgrade is checkable data, not an assumption. |
| `ProtectedResource` | `ResourceIdentity` + `ResourceCapabilities`. |
| `Action` | What a workload asks to do (`Compute`, `Unknown`). |
| `ComputeRequest` | `ResourceIdentity` + `Action` — the seam F-M1-004/005 evaluate against. Carries no caller identity; that's `WorkloadIdentity`/`ExecutionContext` (F-M1-003), composed alongside it. |
| `EnforcementResult` | `Allowed` / `Denied{reason}` / `Unsupported{capability}` / `Error{message}` — `Unsupported` is first-class so a capability downgrade can never masquerade as `Allowed`. |

## Versioned envelope (HORO-825) — `eltanin_core::envelope`

`Versioned<T>` wraps any domain payload with an explicit `version: u16`.
`into_current()` fails explicitly (`UnsupportedVersion`) rather than
silently reinterpreting bytes from a schema this build doesn't
understand. `DOMAIN_SCHEMA_VERSION` is bumped whenever a wrapped type's
wire shape changes incompatibly.

## Backend contract (F-M1-001, HORO-826) — `eltanin_backend::contract`

| Type | Purpose |
|---|---|
| `ComputeBackend` | The trait every backend implements: `discover`, `observe`, `enforce`, `revoke`. Fake (`eltanin_backend::fake`, HORO-827) and, later, the real NVIDIA backend (`crates/eltanin-nvidia`, F-M1-002) both target exactly this trait — no backend-specific method exists outside it. Not a promise of a stable dynamic Rust ABI: if externalized to a separate process, the wire contract is `eltanin-protocol`'s versioned protocol (ADR 0004), not this trait's vtable. |
| `BackendError` | Typed operation failure distinct from `EnforcementResult` (which describes an enforcement *outcome*, not why an attempt couldn't be made): `Unsupported{capability}` (structural — never retry), `Unavailable{resource}`, `PermissionDenied`, `Transient{message}` (retryable), `Invariant{message}` (a bug, not a runtime condition). |

`ComputeBackend::enforce` does not decide authorization (F-M1-004 already
did) — it only reports whether the backend could carry out or verify the
already-decided action. A backend lacking `Capability::Enforce` returns
`Ok(EnforcementResult::Unsupported{..})`, never `Ok(Allowed)`.

## Architecture enforcement

`crates/eltanin-core/tests/architecture_no_vendor_leak.rs` and
`crates/eltanin-backend/tests/architecture_no_vendor_leak.rs` scan all
non-comment source lines in their crate for vendor/platform terms
(`nvidia`, `cuda`, `cgroup`, `nvml`, ...) and fail CI if any appear — this
is HORO-825/826's "architecture test/review rule catches vendor-specific
concepts leaking into core" acceptance criterion, enforced mechanically
rather than by review discipline alone. The backend crate's test also
asserts `eltanin-core` never depends back on `eltanin-backend`, enforcing
HORO-826's required dependency direction (vendor backend → `eltanin-backend`
→ `eltanin-core`).

## Fake Compute Backend (F-M1-001, HORO-827) — `eltanin_backend::fake::FakeBackend`

Deterministic, in-memory `ComputeBackend` implementation for tests/CI —
no special-case logic a real backend couldn't also provide. Resources
are added via `insert`/removed via `remove` (simulating disappearance);
`script_enforcement` pins a specific `enforce` outcome for a resource,
which is how tests simulate an already-decided policy ALLOW/DENY
(F-M1-004) or a lease-expiry denial (F-M1-005) without depending on
either Feature, neither of which exists yet.

`crates/eltanin-backend/tests/fake_backend_scenarios.rs` covers every
scenario named in HORO-827's scope: resource present/absent, a backend
lacking a capability, enforcement success/scripted-failure, resource
disappearance, a lease-expiry stand-in, revoke with/without capability,
and determinism across repeated runs (same script, same result, every
time — no hidden state or ordering dependency).

## Workload identity (F-M1-003, HORO-831) — `eltanin_core::identity`

| Type | Purpose |
|---|---|
| `EvidenceSource` | How a signal was obtained: `KernelObserved` (unforgeable by the observed process), `BestEffort` (unforgeable by the caller, but a narrow TOCTOU race is possible), `SelfAsserted` (the process's own claim, never an authorization basis). |
| `Evidence<T>` | `Present{value, source}` / `Missing{reason}` / `Unsupported` — every field a caller must handle explicitly; there is no default/fallback state, so missing evidence can never be silently treated as present-and-trusted. |
| `ProcessStartToken` | Opaque value paired with a PID to detect PID reuse. |
| `ProcessAncestor` | One entry in a process's parent chain — a contextual signal, never authority. |
| `WorkloadIdentity` | pid, process_start, uid, gid, executable_path/hash, ancestry — all as `Evidence<T>`. |
| `ExecutionContext` | `WorkloadIdentity` + cgroup_path/namespace_hint/container_hint/session_origin, all `Evidence<T>`. |

`WorkloadIdentity::compare_process` defines PID-reuse/restart semantics
(HORO-831 AC) via a three-way `IdentityComparison` result — `Same`,
`Different`, or `Indeterminate` — deliberately not a `bool`: collapsing
"confirmed different" and "insufficient evidence" into one `false` would
let a caller mistake missing evidence for a confirmed answer. `Same`
requires `pid` to match **and** both `process_start` tokens to be
`Present` and equal; either side missing/unsupported is `Indeterminate`,
never silently treated as `Different` or `Same`. This is what keeps
`uid == owner`, `name == trusted`, `path == trusted`, `parent == trusted`
from ever becoming unconditional authorization (North Star invariant 4).

## Linux workload context collection (F-M1-003, HORO-832) — `eltanin_linux`

`collect_workload_identity(pid: u32)` and `collect_execution_context(pid:
u32)` populate the canonical `WorkloadIdentity`/`ExecutionContext` types
above from observed `/proc/<pid>/{stat,status,exe,cgroup}` state. Both
functions take only a `pid` — there is no API surface that accepts a
caller-supplied identity/context to merge or override, so "caller cannot
override locally derivable fields" (HORO-832 AC) is not a convention but
an unexpressable operation.

Every signal is `EvidenceSource::KernelObserved` when read successfully,
or `Evidence::Missing{reason}` on any read failure (permission denied,
process already exited, malformed `/proc` content) — never a panic,
never a silently substituted default. `executable_hash` is deliberately
always `Missing` (hashing a full binary on every collection is an
unbounded-cost operation this collector does not implement); ancestry
walks are bounded (`MAX_ANCESTRY_DEPTH`) and cycle-guarded against a
corrupted `/proc` parent chain.

**Known scope gap**: an ancestry walk that stops early because an
ancestor's `/proc` entry couldn't be read (e.g. permission denied on a
process owned by another UID) is indistinguishable, from the returned
list alone, from genuinely reaching the top of the process tree —
`ProcessAncestor`/`ExecutionContext` have no field to carry "walk
truncated early: evidence unavailable." Closing this needs a contract
change in `eltanin-core`, out of scope for HORO-832. Bounded impact:
ancestry is a contextual signal only, never an authorization basis
(North Star invariant 4), so a short ancestor list can only degrade the
audit trail, never a security decision.

On any non-Linux `target_os`, both functions return `Evidence::Unsupported`
for every field — a documented fallback, not a compile failure — so this
crate builds and unit-tests on any dev machine while the real
`#[cfg(target_os = "linux")]` collection path is compiled and exercised
only on Linux (this repo's `ubuntu-latest` CI runner validates it; local
macOS development cannot).

## Authorization policy (F-M1-004, HORO-834) — `eltanin_core::policy`

`PolicySet` is built only by validating a `PolicyDocument`
(`PolicySet::from_document`/`from_versioned`) — an invalid document
never becomes a `PolicySet`, so it can never deny or allow anything.
`PolicySet::evaluate(&ExecutionContext, &ComputeRequest) -> PolicyDecision`
is a pure function with no caller-supplied override parameter, so
"caller-supplied identity fields must not override observed context"
(HORO-787) is unexpressable, not merely disallowed — the same structural
trick HORO-832's pid-only collector API uses.

| Type | Purpose |
|---|---|
| `PolicyId`/`RuleId` | Opaque string identities, same pattern as `ResourceVendor`. |
| `Effect` | `Allow`/`Deny`. |
| `TrustFloor` | `KernelObserved`/`BestEffort` — deliberately excludes `SelfAsserted`; a rule that trusts a workload's own claim about itself is unrepresentable. |
| `EvidenceMatch<T>` | `expected` value + `min_trust`; matches only `Evidence::Present` clearing the floor. `Missing`/`Unsupported` never match — there is no "field is missing" matcher. |
| `Condition` | `Uid`/`Gid`/`ExecutablePath`/`ExecutableHash`/`CgroupPath`. `pid`, `ancestry`, and the never-populated `namespace_hint`/`container_hint`/`session_origin` are deliberately unmatchable. |
| `Rule` | Exact `resource`+`action` match, AND-only `conditions` (non-empty, one per field — validated). |
| `PolicyDocument` | Authored, not-yet-validated: `id`, author `revision`, `rules`. |
| `PolicyError` | Six variants; validation failure = construction failure, no bypass. |
| `PolicyProvenance` | `policy_id` + `policy_revision` + `schema_version` (from `Versioned<T>`'s `DOMAIN_SCHEMA_VERSION`). |
| `DecisionReason` | `NoMatchingRule` / `ExplicitAllow{matched_rules}` / `ExplicitDeny{matched_rules, overridden_allow_rules}` / `IndeterminateEvidence{rules}` — `BTreeSet<RuleId>` so the explanation is canonical regardless of authoring order. |
| `PolicyDecision` | Private fields, no public constructor outside `evaluate`, `Serialize`-only (not `Deserialize` — nothing should reconstruct an authority-bearing decision from bytes by default). |

**Evaluation semantics**: every rule is always evaluated (no first-match
short circuit). Precedence, most to least authoritative: (1) a `Deny`
rule that definitively matches → `Deny`/`ExplicitDeny`, regardless of
how many `Allow` rules also matched; (2) otherwise, a `Deny` rule whose
match is indeterminate (a condition's evidence is `Missing`/
`Unsupported`) → `Deny`/`IndeterminateEvidence` — this fails closed
rather than letting an unconfirmed deny rule vanish and an unrelated
`Allow` rule win (see "Real finding" below); (3) otherwise, a `Deny`
rule that definitively matches → `Allow`/`ExplicitAllow` (an
`Allow` rule that is merely indeterminate contributes nothing —
default-deny already covers that case); (4) otherwise → `Deny`/
`NoMatchingRule`. This makes default-deny structural: `Effect::Allow`
is reachable only via `DecisionReason::ExplicitAllow` with a
definitively-matched rule, and an empty policy (zero rules) is valid
and denies everything.

**Real finding from independent review, fixed before merge**: the
original design (and first implementation) treated `Missing`/
`Unsupported` evidence on *any* condition as simply "doesn't match,"
uniformly for `Allow` and `Deny` rules. That is safe for `Allow` (a
non-contributing rule just means default-deny still applies) but unsafe
for `Deny`: a deny-on-uid-0 rule whose UID evidence was `Missing` would
silently stop applying, and an unrelated `Allow` rule matched on a
different field (e.g. cgroup path) could then win — a UID-0 process
gets `Allow`ed purely because its UID couldn't be observed, directly
violating HORO-787's "missing evidence cannot silently upgrade trust."
Fixed by distinguishing `ConditionOutcome::NotMatched` (evidence
observed, definitively doesn't satisfy the condition) from
`ConditionOutcome::Indeterminate` (evidence `Missing`/`Unsupported` —
unknown, not false) and giving `Deny` rules with an indeterminate
outcome their own fail-closed `Deny` path, per the precedence above.

**Two design decisions made explicitly, not silently**:
1. No `Principal`/role/group type exists in this domain model (MVP 1.0
   is single-host/single-session per `SECURITY_MODEL.md`) — "principal
   matching" maps onto `uid`/`gid`/`executable_path`/`executable_hash`
   conditions, not a new abstraction.
2. A single-condition rule (e.g. uid-only) is permitted. HORO-787's
   "process... UID... alone cannot imply ALLOW" is read as forbidding
   the *system* inferring trust from context, not forbidding an
   operator-authored explicit rule keyed on uid — requiring ≥2
   conditions would make legitimate policies unwritable.

**Known limitation**: "replayable" (HORO-834 AC) is only partially
delivered. `PolicyProvenance` names a policy by `policy_id` + `revision`,
but nothing enforces that a given `(id, revision)` pair's content is
immutable — an author could edit a policy without bumping `revision`,
and a later replay would then evaluate different rules under the same
provenance. Closing this needs a content digest (a new hashing
dependency), out of scope for HORO-834. Carried forward honestly rather
than overclaimed, following the same pattern as HORO-832's
ancestry-truncation gap above.

## Compute Lease (F-M1-005, HORO-836) — `eltanin_core::lease`

`ComputeLease` is the authorization-capability lifecycle artifact an
ALLOW `PolicyDecision` becomes — never a permanent privilege. The only
way to obtain one is `LeaseIssuer::issue(&PolicySet, ProvenanceRecord,
MonotonicTime, Duration)`, which **re-evaluates** the policy over the
exact `ProvenanceRecord` being bound — `issue` never accepts a
pre-computed `PolicyDecision`, so "issued for context A, bound to
context B" is unexpressable, the same structural trick
`PolicySet::evaluate` and `eltanin-linux`'s pid-only collectors use.

| Type | Purpose |
|---|---|
| `MonotonicTime` | Opaque `u64` nanosecond count, injected at issue and validate — `eltanin-core` never reads a clock. |
| `IssuerInstanceId` | Opaque tag for one live `LeaseIssuer` — its restart epoch; must derive from the agent's own kernel-observed pid/`ProcessStartToken`. |
| `LeaseId` | `{issuer, sequence}` — a correlation identifier, not a capability; carries no entropy. |
| `ComputeLease` | Private fields, no public constructor outside `issue`, `Serialize`-only (never `Deserialize`). |
| `LeaseError` | `Denied`/`NonPositiveTtl`/`TtlExceedsMaximum`/`ExpiryOverflow` — issuance failure. |
| `RevocationOutcome` | `Revoked`/`AlreadyRevoked`/`NotIssued`/`ForeignIssuer`. |
| `LeaseValidity` | `Valid{remaining}`/`ForeignIssuer`/`Revoked`/`ResourceMismatch`/`ActionMismatch`/`WorkloadMismatch`/`WorkloadIndeterminate`/`Expired` — a rich enum, not a bool, following `IdentityComparison`/`DecisionReason`. |
| `LeaseIssuer` | Issues, validates, and revokes leases for one live process instance; `max_ttl` required at construction. |

**Time is injected, never read.** `SystemTime` is wrong here — wall
clock can move backward (NTP, manual change, suspend/resume), which
could un-expire a lease. `Instant` is wrong here — not constructible at
a chosen value or serializable, making deterministic tests impossible.
`MonotonicTime` readings are only meaningful compared within one
`IssuerInstanceId`; the `Instant -> MonotonicTime` adapter belongs to
whichever crate owns a real clock (F-M1-006's agent), not this pure
domain crate.

**Validation check order** (load-bearing, not incidental): issuer
identity → revocation → resource → action → workload identity (via
`WorkloadIdentity::compare_process`, reusing HORO-831's semantics rather
than inventing new ones) → executable identity (via
`WorkloadIdentity::compare_executable`, added by independent review —
`compare_process` alone cannot detect a process staying alive but
`execve()`-ing into a different binary, since neither `pid` nor
`ProcessStartToken` changes across `execve()`) → expiry. Binding checks
precede expiry so a cross-workload/cross-resource replay attempt is
reported as a mismatch, not downgraded into a routine `Expired` audit
line.

**Scope narrowing is structural**: `ComputeLease::narrow_expiry(self,
not_after)` computes `min(current, not_after)` and consumes `self` —
there is no widening counterpart and no `renew`/`extend` anywhere in
this module. Renewal is a fresh `issue` over freshly observed context,
a new authorization act, never an extension.

**Restart/replay semantics** (three cases, three mechanisms):

| Case | Mechanism | Result |
|---|---|---|
| Workload restarts / PID reused | `compare_process` on pid + `ProcessStartToken` | `WorkloadMismatch`, or `WorkloadIndeterminate` when evidence is insufficient |
| Process stays alive, `execve()`s into a different binary | `compare_executable` on hash (falling back to path) | `ExecutableMismatch`, or `WorkloadIndeterminate` when evidence is insufficient |
| Agent/issuer restarts | New `LeaseIssuer` → new `IssuerInstanceId` | Any lease from the old instance → `ForeignIssuer` |
| Serialized lease replayed | No `Deserialize`, no public constructor | Bytes cannot become a `ComputeLease` at all |

Agent restart therefore drops all outstanding leases, fail-closed — the
correct default per ADR 0003 / North Star invariant 5 ("renewal is a new
authorization act, not extension"), confirmed during HORO-836 design
rather than silently assumed.

**Known limitation, a contract on F-M1-006, not a property of this crate
alone**: `LeaseIssuer::validate`'s `presented`/`now` parameters are
caller-supplied and both types are `Deserialize`. The invariant
"possession of lease data alone must not prove identity" therefore
depends on F-M1-006's agent sourcing `presented` from its own collector
and `now` from its own clock, never from anything a client sends over
IPC — named explicitly here since it is the item most likely to be
silently dropped by a future ticket. The same boundary applies to
`LeaseIssuer::issue`'s `now`: this crate cannot verify monotonicity
across successive `issue` calls from inside a single call — that is
F-M1-006's obligation as sole owner of the clock.

**Known limitation**: `narrow_expiry` preserves `LeaseId`, so two
`ComputeLease` values can share an id with different `expires_at` — an
audit trail (F-M1-009) cannot attribute a compute event to one
specifically. Accepted for MVP 1.0 (narrowing restricts one existing
authorization; revoking the id invalidates every value sharing it),
documented rather than silently left unaddressed.

## Local IPC protocol (F-M1-006, HORO-838)

`crates/eltanin-protocol` defines the canonical, platform-neutral wire
types for the local authorization agent's IPC channel — the type
definitions and framing rules only; the actual Unix Domain Socket
listener, peer-credential collection, and agent runtime are HORO-839
(see the section below), and their integration with policy/lease/backend
is HORO-840.

| Type | Purpose |
|---|---|
| `RequestId` | Client-chosen correlation id (`u64`, bounded by construction). No authority. |
| `ClientRequest` | `RequestLease(LeaseRequest) \| ReleaseLease(ReleaseRequest) \| AgentStatus` — exactly three MVP 1.0 operations, no `#[serde(other)]` catch-all. |
| `RequestBody` / `Request` | `{ request_id, body }`, wrapped in `eltanin_core::envelope::Versioned<T>`. |
| `AgentResponse` | `LeaseGranted \| LeaseDenied \| LeaseReleased \| Status \| Error` — derives `Deserialize`, which is the enforcement mechanism (see below). |
| `LeaseView` | Client-facing view of a granted lease: `lease_id` + `remaining: Duration`, never the lease's own `MonotonicTime` fields (meaningless outside the issuing agent). |
| `DenialReason` | A deliberately lossy 3-variant projection of `DecisionReason` — rule ids stay in the audit trail, not on the wire. |
| `ReleaseOutcome` | A deliberately coarser 2-variant projection of `RevocationOutcome` — see the named obligation below. |
| `ErrorCode` | Closed error enum, no free-text field — detail goes to the agent's log, never to the client. |
| `ResponseBody` / `Response` | `{ request_id: Option<RequestId>, body }`, wrapped in `Versioned<T>`. `request_id` is `Option` because correlation is recoverable for a garbage request *body* but not for a non-object request *payload*. |

**Versioning**: reuses `eltanin_core::envelope::Versioned<T>` and
`DOMAIN_SCHEMA_VERSION` rather than minting a separate IPC protocol
version — MVP 1.0 ships one release with one schema version, and a
second version number would be an unearned compatibility promise (same
reasoning as `envelope.rs`'s own docs). No version handshake:
`AgentStatus` is the liveness/version probe, and an unsupported version
fails closed with `ErrorCode::UnsupportedVersion { found, expected }`.

**Framing**: a 4-byte big-endian `u32` length prefix + UTF-8 JSON,
bounded by `MAX_FRAME_BYTES` (64 KiB). `decode_request` checks the
length *before* attempting deserialization. **Discharged by HORO-839**:
`eltanin-agent`'s `connection::serve_connection` calls `decode_frame_len`
on the 4-byte header and rejects an oversized length before allocating a
read buffer for the body — verified by
`agent_request_handling.rs::an_oversized_frame_is_rejected_promptly_before_the_body_is_ever_read`.

**Trust boundary**: zero identity/evidence fields in any wire type. See
`docs/product/SECURITY_MODEL.md`'s "Local IPC trust boundary" section
for the full derived-vs-client mapping and the `AgentResponse`-derives-
`Deserialize` enforcement argument.

**Known limitation, flagged during design, resolved by construction in
HORO-839**: the `eltanin run` launch model (fork+exec vs. exec-in-place)
question is now moot for the transport layer — `eltanin-agent` derives
peer context for *the connecting peer at connect time*, a fact identical
under either launch model, so there is no target-pid field a launch
model could change. **The lease binding-subject question (pid vs.
cgroup) is resolved in HORO-840**: a lease binds to the connecting peer
process (pid + `ProcessStartToken` + executable), via
`LeaseIssuer::validate`'s existing `compare_process`/`compare_executable`
pair — not to a cgroup. See the "Local authorization agent integration"
section below for why, and its named cross-ticket obligation on
F-M1-008.

## Local authorization agent transport (F-M1-006, HORO-839) — `eltanin-agent`, `eltanin_linux::peer`

Implements the Unix Domain Socket listener, peer-credential collection,
and bounded single-request connection lifecycle that HORO-838's protocol
types and framing rules assumed. Contains no policy evaluation or lease
issue/release logic — `eltanin-agent`'s `handler::RequestHandler` is the
seam HORO-840's `authz` module (below) implements that behind;
`tests/agent_architecture_guard.rs` makes the boundary mechanically
checkable.

**Peer credential collection (`eltanin_linux::peer`)**: `SO_PEERCRED`
(via `rustix::net::sockopt::socket_peercred`, a safe wrapper preserving
this workspace's `#![forbid(unsafe_code)]` instead of hand-written
unsafe `libc` `getsockopt` code) reports the peer's **effective** uid/gid
at `connect()` time. `collect_peer_context` cross-checks that against a
fresh `/proc/<pid>/status` read (which reports **real** uid first,
effective second) via `PeerConsistency`, rather than naively assuming
the two uid notions are interchangeable — a naive direct comparison
would false-positive-diverge on any setuid/setgid peer. A match on
either the real or the effective `/proc` value is `Consistent`; both
values unreadable is `Indeterminate`; anything else is
`CredentialDivergence`. pid `0` (an unmappable namespace peer) is
`PeerUnmapped` and `/proc/0` is never read. Only `PeerContext::consistency
== Consistent` is `authorizable()`. Linux-only; every other `target_os`
returns `PeerCredentialError::UnsupportedPlatform` rather than falsely
claiming support.

**Socket lifecycle (`eltanin-agent::listener::BoundSocket`)**: binds only
after validating the parent directory (not a symlink, is a directory,
not group/other-writable, owned by this process's own euid); discriminates
a stale socket file (nothing listening) from a live one via a
connect-probe — `ConnectionRefused` is the only outcome treated as safe
to unlink — before ever removing a pre-existing path; chmods to the
caller's configured mode after bind. `Drop` unlinks the socket path.

**Connection lifecycle (`eltanin-agent::connection::serve_connection`)**:
exactly one request per accepted connection — read one framed request,
dispatch to `RequestHandler` inside `catch_unwind`, write one framed
response, close. No loop, no retry. See that function's own doc comment
for the full failure-to-`ErrorCode` mapping.

**Dependency decision (D1)**: `rustix` was chosen over hand-written
unsafe `libc` `getsockopt`/`geteuid` calls specifically to keep
`#![forbid(unsafe_code)]` intact workspace-wide, at the cost of one
additional (cargo-deny-clean) transitive dependency — a founder decision,
not a default.

## Local authorization agent integration (F-M1-006, HORO-840) — `eltanin-agent::authz`

Implements `RequestHandler` for real: wires `eltanin-core`'s policy
(F-M1-004) and lease (F-M1-005) contracts to an
`eltanin-backend::ComputeBackend` (F-M1-001). This is the one module in
`eltanin-agent` permitted to name `PolicySet`/`LeaseIssuer`/
`ComputeLease`/`.evaluate(`/`.issue(`/`.revoke(` —
`tests/agent_architecture_guard.rs` was rescoped (not removed) to exempt
exactly `src/authz/**`, with a positive assertion that every transport
module file was still actually scanned, so the exemption is a fixed
hole rather than an escape hatch a future commit could quietly widen.

**Request path — issue, then enforce**: `RequestLease` issues a lease
(re-evaluating policy over the exact `ProvenanceRecord` it binds to,
per `LeaseIssuer::issue`'s own contract) *before* calling
`ComputeBackend::enforce` — `enforce`'s docs are explicit that
authorization "has already been made by the time this is called." If
`enforce` does not report `EnforcementResult::Allowed`, the just-issued
lease is compensated with `LeaseIssuer::revoke` and never inserted into
the store.

**Wire mapping rule**: `LeaseDenied` if and only if `PolicySet::evaluate`
itself produced `Effect::Deny`. Every other non-grant condition (backend
failure, enforcement refusal, capacity exhaustion) maps to
`Error { Internal }` — continuing `handler.rs`'s existing
`StatusOnlyHandler` reasoning that "no policy backend decided this" must
never be reported as if policy had denied it.

**Lease binding subject (D-C, resolves the question HORO-838/839 left
open)**: the connecting peer *process* — pid, `ProcessStartToken`, and
executable hash/path — not a cgroup. This was already fixed by merged
`eltanin-core` code: `LeaseIssuer::issue` binds a lease to the exact
`ProvenanceRecord` passed in, and `validate` compares
`origin.context.workload` via `compare_process` then
`compare_executable`. Choosing a cgroup subject for MVP 1.0 would mean
changing `validate`'s comparison set in a QA-PASSed F-M1-005 module —
out of scope for a one-PR integration ticket. `cgroup_path` is still
carried in the bound `ExecutionContext` (so a policy condition can match
on it, and audit preserves it) — it is simply not part of the identity
comparison. **Named forward obligation on F-M1-007**: cgroup-scoped
device-BPF enforcement must reconcile a process-bound lease with a
cgroup-scoped enforcement mechanism; adding a cgroup dimension to
`validate` later is additive. **Cross-ticket obligation on F-M1-008,
resolved by
[ADR 0005](../adr/0005-eltanin-run-process-topology.md)**: `eltanin run`
stays alive as the lease-holding supervisor for the workload's entire
run — it never `execve()`s into the workload — because
`compare_executable` does not survive `execve()`, and a topology where
the lease-holding process does exec would make the lease permanently
unreleasable. See the F-M1-008 section below for the full launch
sequence this produces.

**`ReleaseLease` discharges the `SECURITY_MODEL` named obligation**:
`LeaseIssuer::validate` performs exactly the mandated
`compare_process` + `compare_executable` pair (both required `Same`),
plus issuer/revocation/resource/action/expiry checks, in an order
already merged and QA-verified in `eltanin-core`. Anything but `Valid`
is reported identically as `ReleaseOutcome::Refused` — a client can
never use the wire response to distinguish "unknown lease id" from
"belongs to another client" from "already expired."

**Restart and disconnect semantics**: an agent restart is a fresh
`AuthorizationHandler` — fresh `LeaseIssuer` instance (a distinct
`IssuerInstanceId`, derived by the daemon binary from
`runtime::issuer_instance_id()`), empty in-memory lease store. A lease
naming a prior instance simply misses the store, and would separately
hit `LeaseValidity::ForeignIssuer` even if it didn't. **Lease lifetime
is bound to TTL, never to connection lifetime**: HORO-839's transport is
one-request-per-connection, so "a client disconnects without releasing"
just means no `ReleaseLease` ever arrives — the lease expires at
`expires_at` and is dropped by the next `prune`. Tying lease lifetime to
a connection would revoke a workload's authorization the instant the
CLI process that requested it exits, which is exactly wrong for
`eltanin run`. **Named limitation for F-M1-007**: MVP 1.0 has no
expiry-driven backend teardown — only an explicit `ReleaseLease` calls
`backend.revoke`. A lease that expires unreleased leaves enforcement
applied indefinitely; fail-closed (over-restrictive), not fail-open, and
F-M1-007's to close with real device state.

**Correlation seam for F-M1-009 (`eltanin-agent::authz::event`)**:
`eltanin-protocol`'s wire responses are deliberately lossy (`ErrorCode`
carries no detail, `DenialReason`/`ReleaseOutcome` collapse several
internal outcomes into one wire variant). `AuthorizationEvent` records
full internal fidelity — what was asked, the peer as observed, what
actually happened, what the client actually saw — once per request,
after every internal lock is released. `NullSink` discards; `StderrSink`
Debug-formats to stderr (captured by `journald`/systemd, no new logging
dependency). F-M1-009 owns turning these into a persistent, queryable
audit trail; this seam only guarantees the information needed to do
that already exists.

**Daemon binary (`eltanin-agentd`)**: environment-variable configuration
(`ELTANIN_AGENT_SOCKET`, `ELTANIN_AGENT_SOCKET_MODE`,
`ELTANIN_AGENT_POLICY`, `ELTANIN_AGENT_LEASE_TTL_SECS` — all but the
socket path required, no silent default for a security-relevant value).
Always constructs a `FakeBackend` — F-M1-002's real NVIDIA backend does
not exist yet; swapping it in is additive once it does. `SIGTERM`/
`SIGINT` are wired to `ShutdownHandle::shutdown()` via a dedicated
`signal-hook` iterator thread (`eltanin-agent::daemon::run`) — a founder
decision (D2) made on the same basis as HORO-839's D1: `signal-hook`
over hand-written unsafe `libc` `sigaction`, to keep
`#![forbid(unsafe_code)]` intact workspace-wide.

## Local audit & explain evidence (F-M1-009, HORO-824) — `eltanin-audit`

A dedicated crate, not a module of `eltanin-agent`: `Eltanin::Audit` is
its own Jira Component, and `eltanin-agentd` (a `[[bin]]` inside
`eltanin-agent`) must select the audit sink at startup, so `eltanin-audit`
cannot depend on `eltanin-agent` without a cycle. It also has no
dependency on `eltanin-linux` — its record schema embeds
`eltanin_core::identity::ExecutionContext` directly (already an
observation record, already `Deserialize`), keeping the crate portable
and mechanically unable to leak a vendor/platform concern; enforced by
`crates/eltanin-audit/tests/architecture_no_vendor_leak.rs`.

**Schema (`eltanin_audit::record`)**: `AuditRecord{event_id, recorded_at,
operation, requested, peer, outcome, response}`, wrapped in
`Versioned<T>` (the same envelope from F-M1-001) for forward-compatible
reads. `AuditEventId{instance: IssuerInstanceId, sequence: u64}` is minted
only by the sink — never caller-forgeable. Every authority-bearing
`eltanin-core`/`eltanin-agent` type consumed here
(`PolicyDecision`/`DecisionReason`, `ComputeLease`-derived outcomes,
`AuthorizationOutcome`, `PeerConsistency`) is `Serialize`-only or has no
`serde` derive at all by design (see "Compute Lease" and "Authorization
policy" above) — so `eltanin-audit::record` hand-mirrors each one as a
plain `Deserialize`-safe `Recorded*` type. This is the compiler-enforced
mechanism behind "an edited or replayed log line can never mint
authorization": nothing in the codebase constructs a real `ComputeLease`
or `PolicyDecision` from a `Recorded*` value.

**Sink (`eltanin_audit::sink::AuditFileSink`)**: append-only NDJSON,
opened at file mode `0600` (Unix). `append()` reserves the next sequence
number unconditionally *before* attempting the write, so a failed write
still advances the sequence space — the structural basis for gap
detection below — and is never reused. Best-effort durability is an
explicit founder decision (D-A): a write failure is reported to the
caller and counted (`failed_writes()`), never fed back into the
already-computed `AgentResponse`; see
`docs/product/SECURITY_MODEL.md`'s "Audit & explain evidence" section for
the full rationale and the regression test that proves it
(`crates/eltanin-agent/tests/audit_sink.rs`). Internally the sink writes
through `Mutex<Box<dyn Write + Send>>`, not a concrete `File` — this
generalization exists specifically so a test can inject a writer that
reliably fails (real filesystem fault injection — deleting or replacing
an already-open log file — proved unreliable across platforms, since a
write to an already-open fd doesn't re-check its unlinked path).

**Adapter (`eltanin_agent::authz::audit::AuditEventSink`)**: implements
`eltanin-agent`'s existing `EventSink` trait (the F-M1-009 correlation
seam HORO-840 left open, see above) and converts `AuthorizationEvent` /
`eltanin_linux::peer` types into the `Recorded*` mirrors, since
`eltanin-audit` cannot depend on either crate. `eltanin-agentd` selects
it when `ELTANIN_AUDIT_LOG` is set, falling back to the existing
`StderrSink` otherwise — no behavior change for a deployment that hasn't
opted in.

**Reader (`eltanin_audit::explain`)**: `read_log()` parses every NDJSON
line, reporting a version-mismatched or malformed line as
`UnreadableLine` rather than aborting the scan (checking the envelope's
`version` field via `Versioned<serde_json::Value>` before attempting the
full `AuditRecord` parse, so a version mismatch is never misreported as
generic malformation). `LogScan::gaps` finds, per issuer instance, every
sequence number strictly between the lowest and highest observed that
never appeared as a record — the honest signal that a write may have
failed there. `Selector::{Event, Lease, Pid}` + `select()` resolve to
`Found`/`NotFound`/`PossiblyLost`; a `Lease` selector is how a grant
record and its later release record correlate (both name the same
`LeaseId`, one as the outcome, one as the request — see
`AuditRecord::lease_id()`). The reader never runs inside `eltanin-agent`
— `crates/eltanin-agent/tests/audit_reader_isolation.rs` mechanically
guards that the writer and reader stay separated. A standalone
`eltanin-explain` binary (`--log`/`--event`/`--lease`/`--pid`) exposes
this for interactive inspection.

**Forward obligation on F-M1-008 (`eltanin run`, HORO-823)**:
`eltanin-protocol`'s `RequestId` (the wire correlation id a client
supplies) is deliberately **not** recorded in `AuditRecord` — the agent
mints its own `AuditEventId` instead, since a caller-supplied id is not
authoritative and correlating by it would let a hostile client influence
audit correlation. If F-M1-008 needs to correlate a CLI invocation with
its audit trail, it must do so via the `LeaseId` the grant already
returns, not by threading `RequestId` through the audit schema.

## `eltanin run` controlled launch (F-M1-008, HORO-823/845) — `eltanin-cli`

HORO-845 defines the contract (`docs/product/CLI_CONTRACT.md`); HORO-846
implements the actual agent-connection/spawn/supervise launch path.
Process topology is [ADR 0005](../adr/0005-eltanin-run-process-topology.md):
`eltanin run` stays alive as the lease-holding supervisor, never
`execve()`s into the workload.

**Named MVP 1.0 limitation, founder-acknowledged (not scope for this
ticket, tracked as HORO-988)**: because the connecting peer through
`eltanin run` is always `eltanin`'s own binary, the agent's
kernel-observed evidence at decision time can never describe the
workload's own executable. Policy can discriminate on uid, gid,
launcher path, process ancestry, and cgroup/governed-context membership
through `eltanin run` — but not on which workload binary is actually
run. `docs/product/POLICY_EXAMPLES.md`'s `eltanin run`-specific worked
example deliberately contains no `executable_path`/`executable_hash`
condition, and states why. HORO-988 tracks properly threat-modeling and
designing a closing mechanism (agent-side post-exec verification, a
protocol subject extension with continuous re-validation, or similar) —
none pre-selected.

**Argv/exit contract** (`crates/eltanin-cli::args`/`exit`/`failure`):
`eltanin run --profile <name> -- <program> [args...]`; `--` is
mandatory; argv is read as `OsString` throughout and launched via
`Command`'s explicit argv array — never a shell
(`tests/architecture_no_shell.rs` guards this mechanically). A
`--profile` name resolves, client-side only, to a `(ResourceIdentity,
Action)` pair (`crate::profile::ProfileDocument`) — it never reaches the
wire and never influences policy evaluation; the filesystem loader that
resolves a name to a document is HORO-846's. Exit codes 64/69/70/74/76/
77/78 are a closed, pairwise-distinct taxonomy, disjoint from
spawn-failure (126/127) and signal-terminated (`128+N`) codes
(`tests/exit_code_contract.rs`) — they unavoidably overlap the
workload-passthrough range (`0..=125`), the same property every Unix
process wrapper has, so a workload's own exit status and an `eltanin
run` outcome are not always distinguishable by exit code alone; the
stderr message is the reliable signal (`docs/product/CLI_CONTRACT.md`).

**Launch sequence** (`crate::sequence::LaunchStage`, S0–S11): parse argv
→ resolve profile → establish governed execution context → connect to
the agent → `RequestLease` (spawn only on `LeaseGranted`) → install
signal handlers → spawn → supervise (with lease renewal) → workload
exits → `ReleaseLease` → tear down the governed context → exit. The
workload process does not exist before `LeaseGranted`, and
`AuthorizationHandler` (HORO-840) already calls
`ComputeBackend::enforce()` before granting — so `eltanin run`'s only
obligation for "never start with globally-permissive access before
authorization" is: no `Command::spawn` before an observed
`LeaseGranted`. Full detail: `docs/product/CLI_CONTRACT.md`.

## Not yet implemented

F-M1-001/003/004/005 (`eltanin-core`), all of F-M1-006 (`eltanin-protocol`
HORO-838, `eltanin-agent` HORO-839/HORO-840), and F-M1-009
(`eltanin-audit`, HORO-824) are implemented. F-M1-008's contract
(HORO-845) is defined; its launch path (HORO-846) and E2E fixtures/docs
(HORO-847) are not yet implemented. Remaining work: F-M1-007 enforcement
(including the named cgroup-reconciliation and expiry-driven-teardown
obligations above), F-M1-008's HORO-846/847 subtasks, and HORO-988 (the
workload-executable-identity gap named above) — tracked in
`docs/development/campaign-state.md`.
