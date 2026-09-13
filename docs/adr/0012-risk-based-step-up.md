# ADR 0012: Risk-Based Step-Up on Compute Trust-Boundary Changes

## Status

Accepted (MVP 2.0 — F-M2-004, HORO-794).

## Headline trade-off — read this before anything else

The set of requests Eltanin refuses is unchanged by this ticket. What
changes is that a refusal now names the trust change that caused it,
and can be configured as step-up-remediable versus hard-denied. The
only genuinely stricter behavior is the new hard-`Deny` class; nothing
that was refused before is admitted now, and nothing that was admitted
before is refused now.

Unpacked, each point stated plainly and not softened elsewhere in this
document:

1. **This is a classification layer over refusals, not a fourth
   admission gate.** `eltanin_core::risk::assess` reads no fresh
   evidence and confers no authority — it only names *why* a refusal
   [`crate::session::membership`] (HORO-791), [`crate::approval::recall`]
   (HORO-792), or [`crate::delegation::delegated_admission`] (HORO-793)
   already produced happened, using verdicts those three functions
   already computed.
2. **`StepUpVerdict` has no admit/proceed variant at all.** Only
   `NoStepUp`/`StepUpRequired`/`RiskDenied` — all three are still
   refusals. `assess` is reachable only from a gate's own refusal arm
   in `eltanin-agent`, never from an admission path. This is a
   structural invariant, not a convention: there is no code path in
   this crate that calls `assess` and then admits the request anyway.
3. **The only strictly new behavior is the hard-`Deny` disposition
   class.** A deployment that configures no `StepUpPolicy` at all (the
   default) gets byte-identical behavior to pre-HORO-794 — proven by a
   dedicated regression test
   (`authz_step_up.rs::default_config_without_step_up_is_byte_identical_to_pre_horo_794`)
   and by every one of the pre-existing 83 `eltanin-agent` tests passing
   unchanged. A deployment that configures `StepUpPolicy` but maps every
   signal to `Informational` also gets byte-identical wire/outcome
   behavior — only the audit trail differs (it now names the fired
   signals). Only a signal explicitly configured `SignalDisposition::Deny`
   can newly refuse a request that would otherwise have surfaced as a
   plain `ApprovalRequired`/delegation refusal.
4. **Remote-origin-launch detection is declared unbuilt, not silently
   dropped.** No collector anywhere in `crates/*/src` collects
   network/remote-origin information for a process launch (verified by
   grep across the workspace as part of this ticket). The signal
   inventory in `eltanin_core::risk::RiskSignal` has no variant for it.
   This is an honest, declared seam — a future ticket's job, not
   something this ADR pretends to cover.
5. **No CPU/GPU-utilization-based signal exists, by hard guardrail from
   the ticket itself.** "GPU usage looks high" is never a risk basis in
   this design — every `RiskSignal` variant composes a discrete,
   already-produced verdict from an existing gate, never a numeric
   utilization threshold.

## AC-scope items are honestly partial, not fully met

- **"Provenance UI/audit can reconstruct the decision reason"** is met
  for the audit trail (`RecordedOutcome::{StepUpRequired, RiskDenied}`
  carry the full `BTreeSet<RiskSignal>`) but the wire response stays
  deliberately lossy — `DenialReason::{StepUpRequired, RiskDenied}`
  carry no signal detail at all, matching every other pre-policy denial
  reason's established "coarse client projection, rich audit" pattern.
  A client-facing "why" still requires `eltanin-explain`, exactly like
  every prior gate.
- **"Policy can tune/disable specific step-up classes"** is met for
  every signal except `UntrustedExecutionPath`, which cannot be mapped
  to `Deny` at all (see the dedicated decision section below) — this is
  a deliberate, structural exception to the tuning guarantee, not an
  oversight.

## Context

HORO-791/792/793 each added an independent pre-policy admission gate
that refuses silently or noisily depending on configuration, but none
of them classifies *why* a refusal happened beyond the rich-but-siloed
detail each gate's own verdict type already carries
(`ChangedDimension`, `ExceededBound`, `MembershipVerdict`). A deployment
that wants "stay silent for an ordinary restart, but demand
re-approval when the executable digest changed, and hard-deny a live
privilege escalation" has no way to express that distinction today —
every refusal from every gate is reported identically as
`DenialReason::ApprovalRequired`.

The ticket's guardrails, restated as constraints this design must
satisfy structurally, not just by convention:

- Normal declared dev chains must stay silent in steady state — no new
  prompt on an admitted request, ever.
- Seeded trust-boundary changes must deterministically trigger the
  configured deny/step-up, not a probabilistic or heuristic decision.
- The decision reason must be inspectable/audited.
- Approval must not mint a permanent transferable token.
- Policy must be tunable/disableable per signal class for controlled
  enterprise use later.
- "GPU usage looks high" must never be a risk basis, and this must
  never cause a prompt storm.

## Decision — a classification layer, never a fourth check

`eltanin_core::risk::assess(verdicts: &GateVerdicts, observed:
&ExecutionContext, policy: &StepUpPolicy) -> StepUpVerdict` takes
borrowed references to verdicts the caller already computed
(`&MembershipVerdict`, `&[RecallVerdict]`, `Option<&DelegationVerdict>`)
and `observed` (the same `ExecutionContext` the refusing gate already
evaluated against) — it collects nothing new. Each of the eleven
`RiskSignal` variants (declaration order is the type's `Ord`, hence its
serialization order — treat reordering later as a golden-churn event,
not a free refactor) composes exactly one existing verdict:

| `RiskSignal` | Composes |
|---|---|
| `UnknownLauncher` | Zero approval candidates, or `RecallVerdict::NotMatched{changed}` containing `ChangedDimension::LauncherPath` |
| `UntrustedExecutionPath` | `observed.workload.executable_path` matches a deployment-configured `BTreeSet<String>` prefix set (never a hardcoded path) |
| `LauncherIdentityChanged` | `ChangedDimension::LauncherDigest` |
| `PrivilegeTransition` | `ChangedDimension::OwnerUid` or `ExceededBound::OwnerUid` |
| `PrivilegeEscalationToRoot` | `PrivilegeTransition`'s trigger **and** observed uid present and `== 0` |
| `DetachedExecution` | `MembershipVerdict::{NotMember, Indeterminate}` |
| `DelegationScopeExpanded` | The **narrowed** (`linked_exceeded`) delegation-exceeded set containing `Resource`/`Action`/`Depth`/`Duration` |
| `SecurityPostureChanged` | `ChangedDimension::{ResourceCapabilityState, PolicyRevision}` |
| `ContextBoundaryChanged` | `ChangedDimension::CgroupPath` or (narrowed) `ExceededBound::{CgroupPath, SessionKey}` |
| `TrustTransition` | (narrowed) `ExceededBound::TrustTransition` |
| `EvidenceIndeterminate` | Any consumed verdict's own `Indeterminate` case |

`StepUpVerdict` has three variants — `NoStepUp`/`StepUpRequired`/
`RiskDenied` — and deliberately no fourth `Indeterminate` case: every
evidence-freshness failure that would need one is already resolved to
a named `Indeterminate` by whichever gate produced the verdict `assess`
is consuming, surfacing here as `RiskSignal::EvidenceIndeterminate`
instead of a separate state callers would have to handle again.

## Decision — `DetachedExecution` is keyed off membership only, not ancestry failure

`ExceededBound::AncestryLinkage`/`ExceededBound::HolderLiveness` can
never appear in the (narrowed) delegation-exceeded set `assess`
consumes — the caller excludes them by construction (see the bug-fix
section below). `DetachedExecution` is therefore keyed off
`MembershipVerdict::{NotMember, Indeterminate}` only. This is a
consistency argument, not an omission: a grant that fails ancestry
linkage isn't about this requester at all (a lookup miss on an
unfiltered candidate list), so it would be wrong to also count it as
"this requester looks detached" — the same reasoning that justifies
excluding it from `DelegationScopeExpanded`.

## Decision — a real bug found and fixed during this ticket's implementation

`eltanin-agent/src/authz/delegation_state.rs`'s `DelegationState::candidates()`
(HORO-793) returns every stored grant with **no** resource/action
filter — unlike `ApprovalSet::candidates(resource, action)`, which is
filtered. Combined with `delegated_admission`'s resource/action
containment check (which inserts `ExceededBound::Resource`/`Action` for
**any** grant whose scope doesn't cover the current request), the
existing `union_exceeded` aggregation in `authz/mod.rs`'s
`delegation_admission` method mixes in `Resource`/`Action` failures
from grants that simply belong to a *different* resource — a lookup
miss being mistaken for a scope-expansion attempt.

The fix, isolated in its own commit: a second, narrower `linked_exceeded`
set is computed alongside the existing `union_exceeded` in the same
aggregation loop, restricted to grants whose own `exceeded` set
contains neither `AncestryLinkage` nor `HolderLiveness` — i.e. grants a
fresh ancestry/liveness check actually confirmed belong to this
requester. `union_exceeded`'s meaning and every existing consumer
(`AuthorizationOutcome::DelegationRefused`'s audit-facing union) are
**unchanged**; `linked_exceeded` is a new, additional signal feeding
only `assess`'s `RiskSignal::DelegationScopeExpanded` classification. A
regression test
(`authz_step_up.rs::unrelated_grant_for_a_different_resource_does_not_leak_into_delegation_scope_expanded`)
proves an unrelated stored grant for a different resource does not
produce `DelegationScopeExpanded`, while a genuinely linked descendant
exceeding a real scope bound
(`::a_genuinely_linked_descendant_exceeding_scope_does_trigger_delegation_scope_expanded`)
does.

## Decision — `UntrustedExecutionPath` can never hard-deny

`StepUpPolicy::new` validates exactly one rule:
`StepUpPolicyError::PathSignalCannotDeny` if `RiskSignal::UntrustedExecutionPath`
is mapped to `SignalDisposition::Deny`. This is stronger than "never the
sole verdict" — it is structural, and for a specific mechanical reason:
the step-up remediation for every other signal is `eltanin approve
--remember`, which re-derives the approval binding from fresh kernel
state (owner uid, launcher path, launcher digest, cgroup, capability
snapshot, policy snapshot). For `UntrustedExecutionPath` specifically,
that remediation records the *same untrusted path* into the binding,
so the very same path becomes the matched, remembered launcher on the
next request — the signal self-extinguishes by the same mechanism every
other step-up signal does. A hard `Deny` mapped to this one signal
would therefore be unremediable by the mechanism this entire ticket
relies on to avoid prompt storms: it would be the one way this feature
could produce a permanent block rather than a step-up. Untrusted paths
are deployment-configured (`StepUpPolicy::untrusted_path_prefixes:
BTreeSet<String>`), never hardcoded `/tmp`/`~/Downloads` guesses inside
`eltanin-core` — a platform-specific temp/download convention belongs
in deployment config, not compiled into a vendor-neutral crate.

## Decision — reuse the shipped `--remember` mechanism; build no new one

Running `eltanin approve --remember`/`--once` **is** the step-up act —
no new CLI subcommand, no GUI, no daemon-side prompt, no second
remember-mechanism. `crates/eltanin-cli/src/approve.rs`'s existing
`Record`/`--remember` handling (HORO-792) is unchanged by this ticket.
`Approval` remains `Serialize`-only, never embedded in `AgentResponse`,
re-verified fresh on every use via `recall()` — confirmed, not rebuilt,
as part of this ticket's AC4 verification (see the AC mapping table
below): approval never mints a permanent transferable token.

## Decision — the risk layer is a third gate consulted only on refusal, mirroring HORO-793's placement

`AuthorizationHandler::approval_and_delegation_gate`'s three refusal
arms — plain `ApprovalAdmission::Refused` with no delegation
configured, `DelegationAdmission::Refused`, `DelegationAdmission::Indeterminate`
— each call a new `refuse_with_risk` helper before returning. `refuse_with_risk`
falls back to the caller's original `(outcome, wire reason)` pair
unchanged whenever `self.step_up` is `None` (not configured) or
`assess` returns `NoStepUp` — both cases are byte-identical to
pre-HORO-794 behavior. `ApprovalAdmission::Denied` (an explicit `Deny`
approval, deny-overrides) and `ApprovalAdmission::ObserveFailed` (an
internal backend error) both return *before* `refuse_with_risk` is ever
called — deny-overrides is inherited by construction exactly as
HORO-793 inherited it from HORO-792, and an internal error is never
classified as if it were a security decision.

`AuthorizationConfig::with_step_up(approval_store, policy)` sets
`approval_requirement = Required` and `approval_store_path` alongside
`step_up` in the same call, mirroring `with_delegation`'s identical
coupling discipline — there is no way to enable the risk layer without
approvals also being required.

`ApprovalAdmission::Refused` now carries every scanned candidate's own
`RecallVerdict` (previously computed and discarded on the floor inside
the loop) so `assess` can classify *why* every candidate missed without
re-deriving evidence.

## Decision — rejected alternatives

- **Adding `Effect::StepUp` to `eltanin_core::policy`.** Rejected — this
  ticket's own headline decision, restated from the design brief this
  ADR implements: `PolicySet::evaluate` takes no caller-supplied
  prior-state parameter, so every HORO-794 signal (a comparison of
  current context against remembered/granted prior state) is
  structurally unrepresentable there. Adding an effect variant would
  not fix that; the comparison inputs still don't exist inside
  `evaluate`'s signature.
- **Adding new `Condition` variants for risk signals.** Rejected for the
  same structural reason — a `Condition` matches only the *current*
  `ExecutionContext`, never a remembered prior binding or another
  gate's verdict.
- **A post-policy downgrade via a second independent `evaluate` call.**
  Rejected — this would mean policy is consulted twice with different
  effective semantics depending on gate history, breaking the "one
  authoritative policy evaluation per request" invariant every prior
  MVP 2.0 ticket has preserved.
- **A GUI/daemon-side prompt.** Rejected — out of scope, and
  unnecessary: `eltanin approve` already is the step-up act.
- **Hardcoding path prefixes like `/tmp`/`~/Downloads` directly in
  `eltanin-core`.** Rejected — `eltanin-core` is vendor/platform-neutral
  by design (see `docs/architecture/domain-model.md`'s resource-domain
  section); a temp/download-directory convention is
  platform/deployment-specific and belongs in `StepUpPolicy::untrusted_path_prefixes`,
  configured by the deployment, exactly like `DelegationBounds::transition_markers`
  already established for HORO-793.
- **A second `--remember`-shaped remembering mechanism specific to
  step-up.** Rejected — `eltanin approve --remember` already closes the
  loop; a second mechanism would be genuine, unjustified scope
  expansion.

## Consequences

- Positive: a refusal now names the trust change that caused it,
  inspectable via the audit trail (`RecordedOutcome::{StepUpRequired,
  RiskDenied}`), satisfying the ticket's "decision reason is
  inspectable/audited" AC.
- Positive: a real bug in HORO-793's delegation aggregation is fixed as
  part of this ticket, with its own regression test, rather than
  carried forward silently.
- Positive: the guardrail "GPU usage looks high is never a risk basis"
  holds structurally — there is no numeric-utilization `RiskSignal`
  variant to add one to.
- Negative (accepted, disclosed above): remote-origin-launch detection
  remains entirely unbuilt — this ADR does not claim otherwise.
- Negative: `DOMAIN_SCHEMA_VERSION` bumps 4 → 5 (two new internally
  tagged `DenialReason`/`RecordedOutcome` variants each), so every
  pre-existing durable `Approval` requires re-approval after this ships
  — the same disclosed side effect every prior MVP 2.0 schema bump has
  had.

## AC mapping

| Ticket AC | Status |
|---|---|
| Normal declared dev chain has no repeated prompts in steady state | Met — `authz_step_up.rs::steady_state_admission_never_consults_the_risk_layer` (a maximally strict all-`Deny` `StepUpPolicy` never affects an admitted request) |
| Seeded trust-boundary changes deterministically trigger configured deny/step-up | Met — `authz_step_up.rs::seeded_digest_change_triggers_step_up_and_audit_names_launcher_identity_changed`, `::uid_transition_to_root_is_risk_denied_naming_privilege_escalation_to_root`, `::capability_drift_triggers_security_posture_changed` |
| Decision reason is inspectable/audited | Met — `RecordedOutcome::{StepUpRequired, RiskDenied}{signals}`; wire stays deliberately lossy, matching every other pre-policy denial reason |
| Approval does not mint a permanent transferable token | Confirmed unchanged, nothing new built — `Approval` remains `Serialize`-only, never wire-embedded, re-verified fresh via `recall()` every use |
| Policy can tune/disable specific step-up classes for controlled enterprise use later | Met for every signal except `UntrustedExecutionPath` (cannot map to `Deny`, by design — see its dedicated decision section); unnamed signals default to `Informational` |

## North Star unchanged

`PolicySet::evaluate` remains completely untouched by this and all
three prior MVP 2.0 tickets (HORO-791/792/793/794). A step-up refusal
only narrows what is silently admitted — it never creates a new allow
source, and the actual authorization decision for every request is
still made fresh by policy at `LeaseIssuer::issue` time, exactly as
before. "No protected compute without authorization" holds exactly as
it did before this ticket.
