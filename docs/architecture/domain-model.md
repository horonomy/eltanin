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
than inventing new ones) → expiry. Binding checks precede expiry so a
cross-workload/cross-resource replay attempt is reported as a mismatch,
not downgraded into a routine `Expired` audit line.

**Scope narrowing is structural**: `ComputeLease::narrow_expiry(self,
not_after)` computes `min(current, not_after)` and consumes `self` —
there is no widening counterpart and no `renew`/`extend` anywhere in
this module. Renewal is a fresh `issue` over freshly observed context,
a new authorization act, never an extension.

**Restart/replay semantics** (three cases, three mechanisms):

| Case | Mechanism | Result |
|---|---|---|
| Workload restarts / PID reused | `compare_process` on pid + `ProcessStartToken` | `WorkloadMismatch`, or `WorkloadIndeterminate` when evidence is insufficient |
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
silently dropped by a future ticket.

**Known limitation**: `narrow_expiry` preserves `LeaseId`, so two
`ComputeLease` values can share an id with different `expires_at` — an
audit trail (F-M1-009) cannot attribute a compute event to one
specifically. Accepted for MVP 1.0 (narrowing restricts one existing
authorization; revoking the id invalidates every value sharing it),
documented rather than silently left unaddressed.

## Not yet implemented

Nothing in `eltanin-core`'s currently-scoped domain — F-M1-001/003/004/005
are all implemented. Remaining Features (F-M1-006 agent/IPC, F-M1-007
enforcement, F-M1-008 CLI, F-M1-009 audit) live in other crates —
tracked in `docs/development/campaign-state.md`.
