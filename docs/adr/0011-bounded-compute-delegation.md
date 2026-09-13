# ADR 0011: Bounded Compute Delegation Across Agents, Tools, and Descendant Workloads

## Status

Accepted (MVP 2.0 — F-M2-003, HORO-793).

## Headline trade-off — read this before anything else

**Bounded delegation constrains the chain of processes that *ask*. It does not observe, confine, or even see the ones that don't.**

Unpacked, each point stated plainly and not softened elsewhere in this document:

1. **A descendant that never calls `eltanin run` is invisible to this
   model entirely** — a background daemon, a detached build server, or
   any process launched outside the `eltanin run` chain never asks this
   agent for anything, so there is nothing for delegation to admit or
   refuse. This is topology, exactly the framing ADR 0010 already used
   for its own gap ("the actual workload/script/argv is invisible to
   this mechanism entirely… this is topology, not a shortcut this
   ticket took") — not an implementation shortcut taken here.
2. **"Parent is trusted" is still not "all descendants trusted
   forever" — but enforcement is admission-side only.** A descendant
   that spawns its own unmanaged children is not tracked past the point
   it stops asking this agent for a lease. Delegation narrows what an
   *asking* descendant may obtain; it enforces nothing about what an
   unmanaged descendant does with device access it already holds.
3. **The requester→holder ancestry span is expected same-uid but NOT
   verified** — `ProcessAncestor` carries no `uid` field (verified
   against current `crates/eltanin-core/src/identity.rs`). A uid
   transition inside the span (between the requester and the grant
   holder) is invisible to `delegated_admission`'s check 4
   (trust-transition scan).
4. **Cross-project delegation is forbiddable only where "project"
   coincides with a cgroup/container boundary** — there is no honest
   cwd-based notion of "project" (ADR 0010 already rejected cwd as
   forgeable). `DelegationBounds::require_same_cgroup` is Linux-only in
   practice: `ExecutionContext.cgroup_path` is `Unsupported` on macOS
   (verified — `libproc`'s `pidcwd`/cgroup-equivalent surface remains
   unimplemented there), so `delegated_admission` fails closed to
   `Indeterminate` on that platform when the bound is set — never
   silently satisfied.
5. **Trust-transition detection is path-only** — `ProcessAncestor` has
   no digest field, so an interpreter's actual script identity stays
   invisible to `DelegationBounds::transition_markers`. This is the
   same limitation ADR 0010 already disclosed for its own
   executable-digest mechanism (interpreter argv is structurally
   unreadable in this workspace — see that ADR's AC4 section for the
   three independently sufficient reasons); carried forward here, not
   reintroduced as new.
6. **`UNVERIFIED_ON_BARE_METAL`** for the whole ticket — this gates
   lease *issuance*, never device access itself, same label ADR 0009
   and ADR 0010 already established.
7. **`BLOCKED_ON_E3`** for cgroup-scoped *containment* of descendants
   (as opposed to mere admission-refusal) — actually confining what a
   descendant process can reach at the cgroup/device layer would need
   the same privileged, non-delegated cgroup subtree as F-M1-007
   (mirrors `SessionAssurance::CgroupScope`'s identical declared seam
   from ADR 0009). Declared seam only; not implemented.
8. **Schema bump 3 → 4 invalidates every existing durable approval** —
   say so plainly: `eltanin-audit`'s `RecordedOutcome` gains three new
   variants under the same internally-tagged, no-`#[serde(other)]`
   discipline that justified the 1→2 and 2→3 bumps, and
   `PolicyProvenance.schema_version` is one of `recall()`'s compared
   security-posture dimensions — every pre-existing `Approval` fails
   that dimension after this ships and must be re-approved.

`docs/product/SECURITY_MODEL.md`'s rule that a claim exceeding what is
documented is false is why this is the ADR's opening section, not a
footnote.

## AC-scope items are honestly partial, not fully met

- **"Plugins/MCP/scripts/build hooks as distinct trust transitions"**
  is met only path-wise: `DelegationBounds::transition_markers` matches
  an ancestor's executable *path* exactly. An interpreter's script
  identity (disclosure 5 above) stays invisible — do not read this as
  "plugin/script trust transitions are fully solved." The interpreter
  case remains open exactly as ADR 0010 left it.
- **"Forbid cross-project delegation"** is met only via
  `require_same_cgroup` on Linux (disclosure 4 above) — do not read
  this as a general "project boundary" concept existing anywhere in
  this codebase. There is none.

## Context

HORO-791 (Trusted Compute Session, ADR 0009) and HORO-792 (Remembered
Authorization Intent, ADR 0010) each added an independent, pre-policy
admission gate that a *human-launched* process can satisfy without
re-prompting. Neither addresses the ordinary developer chain this
ticket's user outcome names directly: `user -> Claude Code -> sub-agent
-> cargo/rustc -> local model`. Every hop in that chain is a distinct
process; without delegation, either every hop must independently pass
the approval gate (defeating the "runs silently" outcome), or approval
requirements must be relaxed in a way that admits *any* process
(defeating the "arbitrary descendants do not receive unlimited
privilege" guardrail).

The ticket's guardrails, restated as constraints this design must
satisfy structurally, not just by convention:

- Child authority cannot exceed parent scope.
- Delegation must be explainable (an audit trail can reconstruct the
  chain) and revocable (revoking a parent invalidates future descendant
  admission).
- Kernel-observed process ancestry — the mechanism HORO-787 already
  ruled out as an authorization basis (`crates/eltanin-core/src/policy.rs`,
  "parent process alone cannot imply ALLOW") — must never become one
  through the back door of this ticket.

## Decision — a delegation edge is an explicit, agent-minted grant, never inferred from ancestry

`eltanin_core::delegation::DelegationGrant` is 1:1 with the parent
`ComputeLease` it narrows, minted only by
`DelegationGrant::mint(lease: &ComputeLease, bounds: &DelegationBounds, …)`
— never from raw fields. `lease_id`, `not_after`, and the grant's scope
seed are all derived from the real, already-issued lease; there is no
public constructor that lets a grant claim authority a lease never
held. `DelegationScope` has no public constructor at all — same
structural trick `LeaseIssuer::issue` and `PolicySet::evaluate` already
use elsewhere in this crate to make a mismatch between "what was
evaluated" and "what was granted" unexpressable rather than merely
disallowed by convention.

Kernel-observed ancestry — `WorkloadIdentity::ancestry`, already
collected on every request by `eltanin-linux`/`eltanin-macos`'s
`collect_workload_identity` (HORO-832/HORO-833) — is consulted by
`delegated_admission` in exactly two places, and both can only
**reject**:

1. **Holder liveness** (`compare_process`): is the process the grant
   names as its holder still the same process it was minted for?
   `Different` or `Indeterminate` both refuse; only a confirmed `Same`
   lets the check pass.
2. **Ancestry linkage** (`compare_ancestor`, new in this ticket): does
   the requester's own freshly observed ancestry actually contain the
   grant's holder? No confirmed match refuses.

Neither check can ever cause an `Admitted` verdict by itself — both
only narrow an already-agent-minted grant's applicability, or reject
it. This is the direct structural continuation of `policy.rs`'s own
rule that `ancestry` is unmatchable by `Condition`: if this ADR's
mechanism ever let ancestry alone produce an `Admitted` result, it
would be HORO-787's bug reappearing one layer up.

## Decision — the one combined verification function, not lookup-then-check

`delegated_admission(grant, bounds, requester, requester_session_key,
observed_holder, request, now) -> DelegationVerdict` mirrors
`crate::session::membership`/`crate::approval::recall`'s established
shape exactly: every dimension (holder liveness, ancestry linkage,
owner uid, trust-transition span, session/cgroup binding when
required, resource/action scope, depth, duration) is checked in one
call, comparable dimensions accumulate into `NotAdmitted { exceeded:
BTreeSet<ExceededBound> }`, and any unusable/missing/self-asserted
evidence needed to decide a dimension makes the whole call return
`Indeterminate` immediately — fail-closed, never silently "that
dimension didn't match." Splitting this into a lookup step and a
separate check would reopen exactly the TOCTOU-shaped bug this crate's
established pattern exists to prevent.

The trust-transition scan (check 4) inspects `requester.workload.ancestry[0..k]`
only — strictly between the requester and the holder at index `k`,
exclusive of the holder itself. A marker at or above the holder is
never inspected. This scoping is the single detail most likely to be
implemented backwards (checking above the holder instead of below it),
and it is pinned by a dedicated regression test
(`transition_marker_above_holder_does_not_prevent_admission`) precisely
because getting it wrong in either direction is a real, silent bug: too
narrow defeats the whole marker mechanism, too wide breaks the ordinary
case where a non-root collector legitimately cannot read a root-owned
ancestor further up the tree.

## Decision — delegation is a third gate, consulted only on the approval gate's refusal

`AuthorizationHandler::handle_request_lease`'s existing gate order —
`peer.authorizable()` → session gate (HORO-791) → approval gate
(HORO-792) → `PolicySet::evaluate` — gains delegation *inside* the
approval gate's own `Refused` arm, before returning
`DenialReason::ApprovalRequired`. Concretely:

- Delegation never runs at all unless the approval gate first refused.
- An explicit `Deny` approval (`ApprovalAdmission::Denied`) returns
  before delegation is ever consulted — deny-overrides is inherited by
  construction, not re-implemented.
- Delegation can only turn a refusal into a bounded admission; it can
  never turn an admission or an explicit deny into a refusal.
- `PolicySet::evaluate` still runs, unmodified, inside
  `LeaseIssuer::issue` for every delegated request exactly as it does
  for an ordinary one — delegation widens *admission* past the approval
  gate, never *authorization* past policy. A delegated request whose
  own observed context fails policy is denied exactly like any other
  request would be.

`AuthorizationConfig::with_delegation(approval_store, bounds)` sets
`approval_requirement = Required`, `approval_store_path`, and
`delegation` together in one call — there is no other way to set the
`delegation` field, so delegation cannot be enabled without approvals
also being required (correct-by-construction, matching
`with_approval_store`'s own established "no default for a
security-relevant choice" convention).

## Decision — structural revocation, plus explicit cascade

Two independent mechanisms enforce AC4 ("revoking parent/session
authority invalidates future delegated lease issue"):

1. **Structural TTL capping**: `mint` derives `not_after` from the
   parent lease's own expiry; `ComputeLease::narrow_expiry` (an
   existing lease API, unmodified) caps every delegated lease at
   `min(parent.not_after, now + bounds.max_child_ttl)` *before*
   `enforce_and_finalize` ever runs. A child's lease can never outlive
   its parent's by construction — there is no code path that issues a
   delegated lease and narrows it afterward.
2. **Explicit cascade**: `authz::delegation_state::DelegationState::remove_cascade`
   recursively removes a revoked lease's grant and every descendant
   grant chained under it, mirroring `SessionState`'s established
   "returns lease ids for the caller to revoke" pattern. Both existing
   revocation paths — an explicit `ReleaseLease` and session-termination
   teardown — now call this cascade after the lease-state layer has
   already revoked the named lease, never while its lock is held (the
   cascade recurses into the same revoke helper, which acquires that
   lock itself).

## Decision — no new wire variant; rich detail stays in audit only

A delegation refusal is client-facing identical to
`DenialReason::ApprovalRequired` — the correct remediation ("run
`eltanin approve`") is the same regardless of which pre-policy gate
refused. The rich `ExceededBound`/`Indeterminate` detail goes to
`eltanin-audit`'s new `RecordedOutcome::{GrantedByDelegation,
DelegationRefused, DelegationIndeterminate}` variants only, mirroring
`ReleaseOutcome::Refused`'s established "coarse client projection, rich
audit" pattern. `AuditRecord::lease_id()` is extended to match
`GrantedByDelegation`, so `Selector::Lease` continues linking a grant
record to its later release record for delegated leases exactly as it
already does for ordinary ones.

## Decision — rejected alternatives

- **Letting kernel-observed ancestry directly imply ALLOW.** Rejected
  outright — this is precisely the HORO-787 bug this ADR's headline
  section exists to avoid reintroducing.
- **A general capability-graph / delegation DSL.** Out of scope. The
  domain here (one resource + one action per lease, per ADR 0003) does
  not need general-purpose graph reasoning; `DelegationScope` derived
  directly from the parent lease's own request is sufficient and keeps
  the same "no independent construction path" guarantee the rest of
  this crate relies on.
- **Persisting `DelegationGrant` to disk.** Rejected — a grant is bound
  to a live process and a live lease, neither of which survives an
  agent restart. Persisting it would either go stale silently or need
  its own liveness-revalidation machinery duplicating what
  `delegated_admission` already does on every use. `DelegationGrant` is
  `Serialize` only, with no `Deserialize` at all, mirroring
  `TrustedSession`'s discipline, not `Approval`'s.
- **A `--delegation-path` CLI convenience.** Out of scope for this
  ticket — `eltanin run`'s argv grammar and the S0–S11 launch sequence
  are completely unchanged; delegation is agent-side deployment
  configuration only.
- **Fixing the `eltanin-linux` ancestry-truncation gap (HORO-832) as
  part of this ticket.** Out of scope, and unnecessary for correctness
  here: a truncated walk just means the ancestry-linkage check misses
  the holder, falling back to the ordinary approval gate/prompt — never
  a false grant. The failure mode is fail-closed, so this ticket
  carries the gap forward rather than fixing it opportunistically.

## Consequences

- Positive: the ticket's own user outcome — a normal `user -> Claude
  Code -> sub-agent -> cargo/rustc -> local model` chain runs silently
  under bounded authority — is satisfied, with every admission
  reconstructible from the audit trail (`GrantedByDelegation`'s
  `parent_lease`/`depth`/`holder_pid`).
- Positive: the guardrail "parent is trusted is never all descendants
  trusted forever" holds structurally — depth, duration, and
  resource/action scope are all bounded per-grant, and revocation
  cascades.
- Negative (accepted, disclosed above): the mechanism's blind spots are
  real and listed exhaustively in the headline section — this ADR does
  not claim more than what is implemented.
- Negative: every pre-existing durable `Approval` requires re-approval
  after this ships (schema bump 3 → 4, disclosure 8).

## AC mapping

| Ticket AC | Status |
|---|---|
| Expected developer descendant chain runs silently under bounded authority | Met — `tests/authz_delegation.rs::descendant_admitted_silently_and_audit_records_granted_by_delegation` |
| A child cannot expand resource/action/duration beyond delegator allowance | Met structurally — `DelegationScope`/`narrow_expiry`, core tests in `delegation_admission.rs` |
| Detached/unexpected descendant is re-evaluated rather than blindly inheriting | Met — every request re-runs `delegated_admission` fresh; an unlinked/foreign process fails ancestry-linkage or holder-liveness |
| Revoking parent/session authority invalidates future delegated lease issue | Met — `tests/authz_delegation.rs::revoking_the_parent_lease_removes_the_descendant_grant`, `::terminating_the_session_cascades_through_the_parent_lease_to_the_descendant` |
| Provenance UI/audit can reconstruct the delegation path | Met — `RecordedDelegation`/`GrantedByDelegation`, `AuditRecord::lease_id()` extension |

## North Star unchanged

`PolicySet::evaluate` is completely untouched by this ticket — no new
allow source exists anywhere in this design. Delegation only narrows
*admission* to already-agent-derived facts (a real, previously issued
lease); the actual authorization decision for every request, delegated
or not, is still made fresh by policy at `LeaseIssuer::issue` time.
"No protected compute without authorization" holds exactly as it did
before this ticket.
