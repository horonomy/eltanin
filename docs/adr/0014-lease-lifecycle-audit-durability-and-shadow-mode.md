# ADR 0014: Lease-Lifecycle Audit Durability, Bounded Retention, and Shadow Enforcement Mode

## Status

Accepted (MVP 2.0 — F-M2-006, HORO-796).

## Headline honesty disclosure — read this before anything else

This ticket adds **observability and audit durability**, not a new
authorization decision point. `PolicySet::evaluate` and
`LeaseIssuer::issue`/`revoke` are unchanged by every subtask in this
ticket — stated plainly, not softened elsewhere in this document:

1. **Shadow enforcement mode is not a security control.** It is a
   dry-run/observability posture: every gate and `PolicySet::evaluate`
   runs identically to `Enforce` mode, but a would-be grant is never
   inserted into the lease store and `ComputeBackend::enforce()` is
   never called. An agent deployed in `Shadow` mode enforces **nothing**
   — every workload runs unconstrained regardless of what the shadow
   verdict says. This is stated unambiguously here and again in
   `SECURITY_MODEL.md` because the single most dangerous misreading of
   this feature is mistaking a shadow-mode deployment for a safe or
   partial default.
2. **`DOMAIN_SCHEMA_VERSION` bumps from 5 to 6** — one bump, covering
   every wire-shape change across all five subtasks of this ticket
   (`LogEntry` tagging, `AuditRecord.{mode,session}`,
   `RecordedOutcome::WouldGrant`, `RecordedAgentEvent`,
   `AgentResponse::ShadowObserved`, `AgentStatusView.enforcement_mode`)
   in one place, not five. Same side effect as every prior bump in this
   campaign: every pre-existing durable `Approval` embeds the old
   schema version and now fails `recall()`'s schema check
   (HORO-792) — re-approval is required after this ships. This is the
   **final** `DOMAIN_SCHEMA_VERSION` bump this ticket makes; no
   subsequent subtask bumped it again (confirmed against source at the
   time of writing — see "Verification" below).
3. **Audit log rotation is lossy by design, and that is a real,
   accepted trade-off against the audit trail's own security claims.**
   Bounded retention (default 64 MiB per generation, one retained prior
   generation, ~128 MiB total with zero configuration) means a query
   spanning a discarded generation returns `RetentionDiscarded`, not the
   record. "Audit is evidence, not authority" (the pre-existing founder
   decision D-A, unchanged) means this never affects an authorization
   outcome — but it does mean an operator relying on the audit trail for
   incident forensics, compliance, or dispute resolution can lose
   records that rotated out before anyone looked. This is disclosed
   here and in `SECURITY_MODEL.md`, not hidden behind "bounded" sounding
   purely like a resource-management feature.
4. **The differential shadow/enforce equivalence test suite
   (`authz_shadow.rs`) does not cover `DelegationIndeterminate`.** That
   `RecordedOutcome` variant is reachable only via a candidate already
   in `delegation_admission`'s loop — i.e. only after a real
   `DelegationGrant` already exists — and a real grant can only be
   minted by `enforce_and_finalize` (the real-enforcement path), which a
   shadow-mode handler never reaches by construction (shadow mode never
   calls `backend.enforce()`, so it never mints a grant to delegate
   from). There is no way to construct this bucket on the shadow side of
   a differential pair without a same-mode setup that would silently
   test something other than what the suite's name claims. Noted
   honestly as an actual coverage gap, not papered over.
5. **`AgentResponse::ShadowObserved` is not a new refusal reason** — it
   is returned in place of *both* `LeaseGranted` and `LeaseDenied`
   whenever the agent is running `Shadow` mode, for `RequestLease` only.
   No other operation (`ReleaseLease`, session/approval/delegation
   commands) has a shadow-mode variant; shadow mode's scope is
   deliberately narrow.

## Context

HORO-795 (ADR 0013) closed real fail-open bugs in lease/session
teardown but explicitly deferred two forward obligations rather than
force a second `DOMAIN_SCHEMA_VERSION` bump for marginal completeness:
lease expiry itself emitted no dedicated audit event, and the audit log
had no bound on disk growth. Separately, the roadmap called for a way
to observe what a not-yet-trusted policy change *would* do against real
traffic before flipping a deployment into full enforcement — a
dry-run/shadow mode. Both needs share one wire-shape bump and one
ticket: HORO-796/F-M2-006, split into five subtasks landed in sequence:

1. Audit schema + bounded rotation (`eltanin-audit`): `LogEntry`
   internal tagging (`Decision`/`Agent`), `AuditRecord.{mode, session}`,
   `RecordedAgentEvent::{LeaseExpired, AuditLogRotated}`,
   `RecordedOutcome::WouldGrant`, and `AuditFileSink`'s rotation logic.
   `DOMAIN_SCHEMA_VERSION` bumped 5 → 6 here, covering the whole
   ticket's cumulative wire-shape changes in one bump.
2. Real `LeaseExpired` audit emission (`eltanin-agent::authz`):
   `sweep_expired_leases` now emits one `RecordedAgentEvent::LeaseExpired`
   per lease it sweeps, carrying the real `backend.revoke()` result —
   closing the HORO-795-disclosed gap that lease expiry was audit-silent.
3. Shadow enforcement mode (`eltanin-agent::authz`, `eltanin-protocol`):
   `EnforcementMode::{Enforce, Shadow}` on `AuthorizationConfig`
   (default `Enforce`), `AgentResponse::ShadowObserved{verdict}`,
   `ShadowVerdict::{WouldAllow, WouldDeny, WouldStepUp}`, and the
   differential mode-equivalence test suite proving byte-identical
   `AuthorizationOutcome` across modes for every refusal bucket except
   the disclosed `DelegationIndeterminate` gap above.
4. CLI surface (`eltanin-cli`): `eltanin explain`, `eltanin audit`,
   `eltanin status`, and `eltanin run`'s shadow-mode leg — folding
   `eltanin-explain`'s standalone-binary functionality into the real
   `eltanin` CLI and exposing shadow mode's status/behavior to an
   operator.
5. This subtask: ADR 0014 (this document) and cross-checking
   `SECURITY_MODEL.md`, `docs/architecture/domain-model.md`, and
   `CLI_CONTRACT.md` against the actual shipped source.

## Decision — one wire-shape bump for the whole ticket

Every subtask's wire-shape change (`LogEntry` tagging,
`AuditRecord.{mode,session}`, `RecordedOutcome::WouldGrant`,
`RecordedAgentEvent`, `AgentResponse::ShadowObserved`,
`AgentStatusView.enforcement_mode`) landed under one
`DOMAIN_SCHEMA_VERSION` bump (5 → 6), made in subtask 1 rather than
once per subtask — see `da378d7`'s commit message, which names every
change it covers up front. This follows the same campaign-wide pattern
HORO-792 through HORO-794 already established (one bump per ticket, not
per PR) and avoids invalidating every durable `Approval` five times
instead of once.

## Decision — bounded audit-log retention, one discarded generation

`AuditFileSink` rotates to a new generation once the current file would
exceed a configurable threshold (`with_max_bytes`, default 64 MiB): the
current file is renamed to `<path>.1` — **overwriting and discarding**
any prior `.1` — a fresh file is opened at `<path>`, and a
`RecordedAgentEvent::AuditLogRotated{rotated_at_sequence,
discarded_through_sequence}` marker is written as the new generation's
first entry, recording exactly which sequence range was just discarded.
This bounds total on-disk audit storage at ~128 MiB with zero
configuration (AC6) — a hard requirement given `eltanin run`'s
long-running supervised-workload model, where an unbounded append-only
log is a real disk-exhaustion vector, not a hypothetical one.

The rejected alternative (below) explains why this was chosen over
unbounded retention or an external log-shipping requirement. The
consequence accepted here is stated in the headline disclosure above:
`eltanin_audit::explain::SelectionResult::RetentionDiscarded` is a real,
distinct outcome from `NotFound`/`PossiblyLost`, and a query for a
record that rotated out returns exactly that — evidence that
*may have existed and was intentionally discarded*, not evidence that
never existed.

## Decision — `LeaseExpired` closes the HORO-795 forward obligation

`AuthorizationHandler::sweep_expired_leases` (already existing plumbing
from HORO-795/ADR 0013's Bug B fix, which drops the internal lock before
calling `backend.revoke()`) now also emits one
`RecordedAgentEvent::LeaseExpired{lease_id, resource, expired_at,
backend}` per swept lease, where `backend` is the real
`Option<EnforcementResult>` from that lease's backend teardown attempt
(`None` exactly when no teardown was attempted because another live
lease still names the same resource — identical semantics to the
existing `Released{revocation}` case). This is the one HORO-795 gap this
ticket named as its own forward obligation and now closes: lease expiry
is no longer audit-silent.

## Decision — `EnforcementMode`, gated at exactly one seam

```rust
pub enum EnforcementMode {
    #[default]
    Enforce,
    Shadow,
}
```

lives in `eltanin_protocol::response` (not `eltanin-agent::authz`)
because `AgentStatusView` must report it and `eltanin-protocol` cannot
depend back on `eltanin-agent` — the same dependency-direction reasoning
`RecordedEnforcementMode` follows one crate boundary over, in
`eltanin-audit`. `AuthorizationHandler` holds this type directly (no
separate agent-internal copy), unlike `SessionRequirement`/
`ApprovalRequirement`/`RevocationRequirement`, because — unlike those —
this configuration must already cross the wire via `AgentStatusView`.

The single structural guarantee this ADR wants recorded: `handle_request_lease`
is split into `request_lease_verdict` (shared decision logic — every
gate and the one `PolicySet::evaluate` call, identical regardless of
mode) plus `enforce_and_finalize` (the `Enforce`-mode tail: calls
`backend.enforce()`, inserts the lease into the store on success) and
`shadow_would_grant`/`shadow_project_refusal` (the `Shadow`-mode tail:
on an admit, mints the lease via the exact same `LeaseIssuer::issue`
call, then immediately reverses it — `issuer_mut().revoke()` +
`release_reservation()` — never touching `backend.enforce()` or
`backend.revoke()` at all; on a refusal, reports the same
`AuthorizationOutcome` `Enforce` mode would have produced, projected
through `ShadowVerdict`). There is exactly one function that decides
(`request_lease_verdict`); shadow mode is a different *tail*, not a
different *decision engine*. This is the ticket's own explicit design
constraint, and the differential test suite (`authz_shadow.rs`) exists
specifically to prove it holds, one refusal bucket at a time.

## Decision — `ShadowVerdict` is deliberately as lossy as `DenialReason`

```rust
pub enum ShadowVerdict {
    WouldAllow,
    WouldDeny,
    WouldStepUp,
}
```

The specific gate/policy reason behind a verdict stays in the audit
trail (`RecordedOutcome`) and never crosses the wire in
`AgentResponse::ShadowObserved{verdict}` — the same enumeration
discipline `DenialReason` already established for real denials, applied
consistently to observed-but-not-enforced ones.

## Decision — rejected alternatives

- **Unbounded audit log growth (no rotation).** Rejected — a real
  disk-exhaustion vector given `eltanin run`'s long-running supervised
  model; the accepted trade-off (a discarded generation is
  unrecoverable) is disclosed above rather than avoided by never
  bounding storage at all.
- **A configurable/pluggable number of retained generations.** Rejected
  for this ticket — one retained generation (the renamed `.1`) is the
  simplest bound that still gives an operator *some* look-back past the
  active file, and AC6 asks for "bounded," not "tunable retention
  policy." A richer retention scheme is a separate, larger design
  decision, not folded in here.
- **Making a rotation-discarded record retroactively affect an
  authorization outcome (e.g. refusing renewal if history can't be
  proven).** Rejected — this would invert "audit is evidence, not
  authority" (D-A, HORO-824), the same invariant ADR 0013 and every
  audit-adjacent decision in this campaign holds. Audit gaps are an
  operator-visible signal, never an authorization input.
- **A shadow mode that runs a separate, simplified decision path
  ("preview mode" reusing only policy evaluation, skipping gates).**
  Rejected explicitly — the ticket's own design constraint is that
  shadow and enforce reach identical decisions through identical code,
  proven by differential testing; a simplified preview path would be
  cheaper to build but would let shadow-mode observations silently
  diverge from what `Enforce` mode would actually do, defeating the
  entire purpose of using shadow mode to validate a policy change
  before trusting it.
- **Constructing a real `DelegationGrant` on the shadow handler under
  test, purely to exercise `DelegationIndeterminate` in the differential
  suite.** Rejected — structurally impossible without breaking the
  suite's own premise (shadow mode never mints a real grant by design),
  and any workaround would test something other than what the suite's
  name claims. Left as an honest, disclosed gap instead.
- **A richer `AgentStatusView` for shadow mode (e.g. running
  would-grant/would-deny tallies).** Rejected for this ticket — additive
  and out of scope; `AgentStatusView` reports only `protocol_version`
  and `enforcement_mode`, matching what `eltanin status` needs today.
- **A second `DOMAIN_SCHEMA_VERSION` bump per subtask.** Rejected — see
  "Decision — one wire-shape bump" above; one bump for the whole ticket,
  following this campaign's established per-ticket (not per-PR)
  cadence.

## Consequences

- Positive: lease expiry is no longer audit-silent — the one forward
  obligation HORO-795/ADR 0013 explicitly named is now closed.
- Positive: audit log growth is bounded (~128 MiB, zero configuration)
  without touching authorization decisions at all.
- Positive: a deployment can now validate a policy/config change against
  real traffic in `Shadow` mode, using the identical decision engine
  `Enforce` mode uses, before trusting it.
- Negative (accepted, disclosed above): audit log rotation is lossy — a
  query spanning a discarded generation loses records permanently, with
  no configurable retention depth beyond one prior generation.
- Negative (accepted, disclosed above): the differential shadow/enforce
  equivalence suite does not and structurally cannot cover
  `DelegationIndeterminate`.
- Negative (accepted, disclosed above): `Shadow` mode provides zero
  actual enforcement — this ADR and `SECURITY_MODEL.md` both state this
  without qualification specifically to prevent it from being read as a
  safe or partial default.
- `DOMAIN_SCHEMA_VERSION` bumps from 5 to 6 (one bump, covering this
  entire ticket) — every pre-existing durable `Approval` requires
  re-approval after this ships, the same side effect as every prior
  campaign bump.

## Verification

`crates/eltanin-core/src/envelope.rs`'s `DOMAIN_SCHEMA_VERSION` constant
is `6` at the time of writing (subtask 5), set by subtask 1
(`da378d7`) and confirmed unchanged by every subsequent subtask
(2 through 4) — this document's own honest cross-check, not a code
change.

## AC mapping

| Ticket AC | Status |
|---|---|
| Audit log storage is bounded by default | Met — `AuditFileSink`'s 64 MiB/generation, one retained generation, ~128 MiB total, zero configuration |
| A discarded record's absence is distinguishable from "never happened" | Met — `SelectionResult::RetentionDiscarded` is a distinct outcome from `NotFound`/`PossiblyLost`, surfaced by `eltanin explain`/`eltanin audit` |
| Lease expiry produces an audit trail | Met — `RecordedAgentEvent::LeaseExpired` per swept lease, carrying the real backend teardown result; closes the HORO-795 forward obligation |
| A deployment can observe policy decisions without enforcing them | Met — `EnforcementMode::Shadow`, `AgentResponse::ShadowObserved{verdict}`, proven equivalent to `Enforce` mode's decision engine by differential testing (with the disclosed `DelegationIndeterminate` gap) |
| Shadow mode is clearly distinguishable from real enforcement, operator-visible | Met — `eltanin status`'s explicit `UNENFORCED/OBSERVED-ONLY` phrasing, `eltanin run`'s shadow-mode stderr banner, `AuditRecord.mode` on every record |
| Existing enforcement behavior is unchanged for a deployment that never opts into shadow mode | Met — `EnforcementMode::default() == Enforce`; every pre-HORO-796 construction is byte-identical |

## North Star unchanged

`PolicySet::evaluate` and `LeaseIssuer::issue`/`revoke` remain the sole
authorization decision points, exactly as before. Shadow mode adds a
second *tail* after the identical decision, never a second decision
engine; audit rotation and `LeaseExpired` emission add observability,
never a new allow source. "No protected compute without authorization"
holds exactly as it did before this ticket, with one caveat that must
never be forgotten by an operator: it holds only in `Enforce` mode.
`Shadow` mode, by design, authorizes nothing and enforces nothing.
