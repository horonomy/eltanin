# ADR 0013: Compute Lease Lifecycle Hardening — Renewal, Revocation, Expiry, Offline Failure

## Status

Accepted (MVP 2.0 — F-M2-005, HORO-795).

## Headline trade-off — read this before anything else

Most of this ticket's Acceptance Criteria were already true before this
ticket started. Renewal (AC1) already worked end-to-end via
`crates/eltanin-cli/src/supervise.rs`'s existing loop. Restart/reboot
recovery (AC4) was already structurally guaranteed by `ComputeLease`
being `Serialize`-only and `IssuerInstanceId`-scoped. This ticket's
actual contribution is: two real, disclosed fail-open bugs found and
fixed (a session reaped by expiry/anchor-death never cascaded its lease
revocations to the backend; an expired lease never triggered
`backend.revoke()` at all), one honesty fix (a real backend revoke error
was silently discarded, indistinguishable from a deliberate no-op), one
new opt-in configuration surface (gating a grant on `Capability::DeviceRevoke`),
and test coverage plus honest documentation for behavior that was
already correct. Nothing here is framed as a new authority-granting
feature — every change either closes a gap or makes existing plumbing
honest.

Unpacked, each point stated plainly and not softened elsewhere in this
document:

1. **AC4 (restart/reboot recovery) was already true before this
   ticket.** This ticket's contribution to AC4 is test coverage
   (`authz_lifecycle.rs::a_lease_from_a_prior_agent_instance_does_not_survive_a_restart`,
   pre-existing, plus `eltanin-core`'s own
   `tests/lease_restart.rs::lease_from_a_prior_issuer_instance_is_rejected_as_foreign`)
   and this disclosure — not new restart-recovery machinery. No lease
   provenance/lineage field was added; none was needed.
2. **"Best-effort" backend revoke, undecorated.** This ticket makes the
   *plumbing* honest: lease-layer revocation is structural and always
   succeeds; device-layer teardown is attempted and its outcome —
   including `Unsupported{DeviceRevoke}` and a real `BackendError` — is
   now recorded rather than silently discarded or asserted. It proves
   **nothing** about whether a real NVIDIA backend can actually
   invalidate an already-open device handle on real hardware. This
   remains `BLOCKED_ON_E3`/`UNVERIFIED_ON_BARE_METAL`, the same register
   as HORO-791/792/793's revocation-adjacent claims.
3. **Unbounded renewal in the fully-ungated default.** `max_session_ttl`
   is the renewal window only when sessions are required. A deployment
   that requires no session (the MVP 1.0 default) gets no cumulative
   renewal bound at all, by its own configuration choice — not a gap
   this ticket needs to close, but stated here so it is not
   misread as an oversight.
4. **Policy change requires an agent restart to take effect.** There is
   no hot-reload path (`load_policy` runs once at agent startup;
   `PolicySet` is held immutably for the process lifetime). AC2's
   "policy/session/resource change prevents subsequent renewal" is
   satisfied for a *policy* change only via restart → new
   `IssuerInstanceId` → `ForeignIssuer` rejection of any stale lease —
   never via any live policy-revision tracking. This is not continuous
   policy-drift detection and must not be read as such.
5. **Renewal is not distinguishable from a first grant in the audit
   stream**, accepted as-is. An operator reconstructs a renewal by
   correlating a `Granted{new}` record with the immediately-preceding
   `Released{old}` from the same peer. A client-asserted `supersedes`
   field was considered and rejected — see the rejected-alternatives
   section.
6. **Lease expiry itself emits no dedicated audit event.** This is a
   named forward obligation for HORO-796 (audit/provenance), deliberately
   deferred to avoid forcing a second `DOMAIN_SCHEMA_VERSION` bump /
   re-approval-of-every-durable-approval cycle for one ticket's marginal
   audit completeness.
7. **A doc-comment overclaim was found and fixed.**
   `crates/eltanin-agent/src/authz/session_state.rs`'s module doc
   previously asserted that a not-yet-reaped dead session "can never be
   used, because `membership` would independently reject it" — true for
   anchor-liveness, false for time-based expiry (`membership` takes no
   `now` parameter and never checks `expires_at`). The actual safety
   property — `membership_for_peer` calls `reap` immediately before the
   session lookup, under the same lock — is now stated explicitly in
   that file.
8. **Clock robustness at extreme durations is already correct, not new
   mechanism.** `enforce_and_finalize` already treats a
   `remaining.is_zero()` reading (which a saturated/overflowed
   `MonotonicTime::checked_add` would produce) as a lease-issue failure,
   fail-closed. Verified during this ticket's design pass, not built by
   it.
9. **No new QA feature-verification doc.**
   `crates/eltanin-cli/tests/qa_governance_sync.rs` hardcodes
   `FEATURE_IDS` to `F-M1-001..010` only; HORO-791–794 added none of
   their own. Adding an unguarded `F-M2-005.md` here would be
   inconsistent with all four sibling MVP 2.0 tickets — not added.

## Context

Two real fail-open bugs were found while auditing the existing
issue/renew/revoke/expire lifecycle against this ticket's Acceptance
Criteria, both specifically on the *lazy-reaping/pruning* paths rather
than the explicit-action paths (`TerminateSession`, `ReleaseLease`),
which were already correct:

- **Bug A**: `SessionState::reap` (HORO-791) is documented as returning
  each reaped session's id and associated lease ids "for the caller to
  revoke at the backend/lease-state layer," but both call sites in
  `authz/mod.rs` (`membership_for_peer`, `handle_create_session`)
  discarded that return value entirely. A session dying by *expiry* or
  *anchor-leader death* (as opposed to explicit `TerminateSession`,
  whose own cascade already worked) never revoked its leases at the
  backend layer.
- **Bug B**: `backend.revoke()` was reachable from exactly two places
  (`handle_release_lease` and the session-teardown revoke helper).
  `LeaseState::prune` (the expiry sweep, called at the top of both
  `RequestLease` and `ReleaseLease` handling) drops an expired lease's
  lease-state record via `HashMap::retain` and holds no
  `ComputeBackend` reference — it structurally cannot call `revoke`,
  and neither call site compensated. Concrete consequence: if the
  controlling `eltanin run` process is killed (SIGKILL — a case
  `CLI_CONTRACT.md` already acknowledges as possible), the workload
  could keep running with live backend-side enforcement indefinitely
  after its lease silently expired and was pruned.

A third issue was an honesty gap rather than a fail-open bug:
`handle_release_lease` mapped a real `Err(BackendError)` from
`backend.revoke()` to `.ok()` → `None`, indistinguishable from the
legitimate `None` produced when `any_other_live_lease_for_same_resource`
correctly decides no teardown should be attempted at all.

Finally, the ticket's own AC ("policy/session/resource change prevents
subsequent renewal") surfaced a gap in what is *checked* at grant time:
only `enforce() == Allowed` gated whether a lease was granted;
`Capability::DeviceRevoke` was never consulted, so a resource that
structurally cannot be revoked was silently leasable with no way to
require otherwise.

## Decision — cascade-revoke on lazy session reap (Bug A fix)

`SessionState::reap` is now `#[must_use]`. Both call sites
(`AuthorizationHandler::membership_for_peer`,
`AuthorizationHandler::handle_create_session`) now consume the returned
`Vec<(SessionId, BTreeSet<LeaseId>)>` and cascade each session's lease
ids through a new `cascade_revoke_leases` helper, which calls exactly
the same `revoke_lease_for_session_teardown` mechanism
`handle_terminate_session`'s explicit-termination path already used
(that method itself is now also expressed in terms of the shared
helper, removing the duplication rather than leaving a third copy of
the same loop). No new revocation mechanism was introduced — this is
strictly "consume what was already being computed and thrown away."

Both lazy call sites drop the `sessions` lock before cascading (a
restructure of `membership_for_peer` and `handle_create_session`'s
control flow, not a behavior change to the operations themselves) —
`revoke_lease_for_session_teardown` acquires the independent `state`
lock and calls into the backend, and this handler's established
discipline throughout is to never hold one internal lock across a call
into another subsystem or the backend.

## Decision — a lazy expired-lease sweep, owning no backend reference (Bug B fix)

`LeaseState::sweep_expired(now) -> Vec<(LeaseId, ResourceIdentity)>`
(new, `#[must_use]`) removes every lease whose `expires_at <= now` (as
`prune` already did) and additionally decides, once per distinct
resource named by a just-expired lease, whether any other *still-live*
lease remains for that resource — the same "no other live lease keeps
enforcement needed" rule `any_other_live_lease_for_same_resource`
already encodes for `ReleaseLease`, evaluated fresh against what
remains after the whole expired batch is removed so that N
simultaneously-expiring leases for the same resource are handed back
(and later revoked) exactly once, not N times.

`AuthorizationHandler::sweep_expired_leases` — a new private method —
takes the `state` lock, calls `sweep_expired`, **drops the lock**, and
only then calls `backend.revoke()` for each resource the sweep
identified. It is called at the very top of both `handle_request_lease`
and `handle_release_lease`, *before* either function's own existing
`prune`/capacity logic — a separate step, not threaded through
`issue_reserving_capacity`'s signature (a different function with a
different job: reserving capacity for a lease about to be issued, not
sweeping unrelated already-expired ones).

This mirrors two disciplines already established elsewhere in this
crate: `SessionState::reap`'s "compute what to do under the lock, drop
the lock, then act, owning no backend reference" shape, and this
crate's blanket rule (see `handle_request_lease`/`handle_release_lease`'s
own bodies) that a backend call is never made while an internal state
lock is held.

## Decision — record a real backend revoke error honestly (honesty fix)

`handle_release_lease`'s `backend_result` computation now matches on
`self.backend.revoke(&resource)` explicitly: `Ok(result) => Some(result)`
unchanged, `Err(error) => Some(EnforcementResult::Error { message:
error.to_string() })` instead of `.ok()`'s silent `None`. The existing
`EnforcementResult::Error` variant is reused — no new type. The other
`None`-shaped case (`revoke_backend == false`, because another live
lease on the resource means no teardown should even be attempted) is
untouched and remains `None`; only the *attempted-and-failed* case was
ever wrong. `FakeBackend::revoke`'s existing `Unsupported{DeviceRevoke}`
path (a resource that structurally lacks the capability) was already
correctly preserved as `Some(Unsupported)` and needed no change —
verified by a dedicated regression test alongside the new
`Some(Error)` one.

## Decision — `RevocationRequirement`, an opt-in grant-time capability gate

```rust
pub enum RevocationRequirement { Required, NotRequired }
```

mirrors `SessionRequirement`/`ApprovalRequirement`'s exact shape and
default-`NotRequired` blast-radius discipline. `AuthorizationConfig::with_revocation_requirement`
is the builder method; every pre-HORO-795 construction (none of which
calls it) is byte-identical — proven by
`authz_revocation.rs::revocation_not_required_is_the_default_and_ignores_missing_device_revoke`,
which grants a lease for a `Capability::DeviceRevoke`-lacking resource
with no configuration change at all.

When `Required`, a new `revocation_capability_gate` method — called
once per `RequestLease`, right before capacity is reserved so a refused
request never wastes/holds a reservation — re-observes the resource
(mirroring `approval_admission`'s identical `ComputeBackend::observe`
re-check pattern) and refuses the grant if it does not support
`Capability::DeviceRevoke`. The refusal reuses the existing
`AuthorizationOutcome::EnforcementRefused { result:
EnforcementResult::Unsupported { capability: DeviceRevoke } }` /
`AgentResponse::Error { code: Internal }` wire mapping already
established for "internal/capability-level refusal, not a policy
decision" — **no new wire `DenialReason` variant, no
`DOMAIN_SCHEMA_VERSION` bump.** An `observe` failure itself (a real
backend error, not a gate decision) reuses the existing
`AuthorizationOutcome::BackendFailed` variant rather than a new one —
deliberately, so this ticket's audit-event surface stays inside
`crate::authz`'s own three in-scope files
(`mod.rs`/`state.rs`/`session_state.rs`) and never has to touch
`eltanin-audit`'s `RecordedOutcome` mirror, which lives in a separate
crate outside this ticket's scope.

## Decision — a doc-comment correction, not a behavior change

`session_state.rs`'s module doc previously stated that a not-yet-reaped
dead session "can never be used, because `membership` would
independently reject it" without qualifying which kind of death this
covers. `membership` (`eltanin_core::session::membership`) takes no
`now` parameter and never checks `expires_at` — the claim was true for
anchor-liveness and false for time-based expiry as literally written.
The doc now states the actual invariant: `membership_for_peer` calls
`reap` immediately before the session lookup, under the same lock, and
that ordering — not `membership`'s own logic — is what keeps an expired
session from ever being admitted. No code path changed; only the
documentation of an already-correct property was corrected.

**Superseded (2026-09, ADR 0015/HORO-1278)**: this correction's own
claim is no longer current. `membership()` now takes `now` directly and
checks expiry structurally, inside itself, independent of whether any
`reap` has run first — see
[ADR 0015](0015-trusted-compute-session-anchor-and-binding.md)'s
"Decision — expiry is now structural inside `membership`" section. The
correction above is left as written for historical accuracy; a reader
should follow ADR 0015 for the current mechanism.

## Decision — rejected alternatives

- **A renewal counter, chain-anchor state, or a new `RiskSignal`
  variant.** Rejected — would invert HORO-794's own invariant that
  `assess` only ever runs on a refusal path and never converts an
  admission into a refusal; a renewal-counting mechanism would need to
  gate admissions, which is out of scope and structurally wrong for
  this layer.
- **An admission-provenance/lineage field on `ComputeLease`.** Rejected
  — actively wrong, not merely unnecessary: the correct behavior is
  that *every* gate re-runs on *every* renewal (proven by
  `authz_renewal.rs`'s new renewal re-gating tests), never "skip the
  gate that admitted last time" that a lineage field would invite.
- **A policy hot-reload mechanism.** Rejected — out of scope for this
  ticket; `load_policy` running once at startup with an immutable
  `PolicySet` for the process lifetime is correct existing behavior
  that needs no change, and building reload is a separate, much larger
  design decision.
- **A `DOMAIN_SCHEMA_VERSION` bump / new `LeaseExpired` audit event
  type.** Rejected for this ticket specifically — named as an explicit
  forward obligation for HORO-796 instead, to avoid a second forced
  re-approval-of-every-durable-approval cycle for one ticket's marginal
  audit completeness.
- **`proptest` for the concurrency/race test coverage.** Rejected — no
  new dependency; `std::thread::scope` (stable in this workspace's Rust
  edition) is sufficient and is what `authz_concurrency.rs` uses.
- **A client-asserted `supersedes` field on `LeaseRequest`, to make
  renewal distinguishable from a first grant in the audit stream.**
  Rejected — this would be client-asserted identity, which
  `crates/eltanin-protocol/tests/protocol_no_self_asserted_identity.rs`
  already forbids categorically. A renewal remains reconstructible by
  an operator correlating records, not by trusting a client's claim.
- **Changes to `crates/eltanin-core/src/lease.rs` (a `renew`/`extend`
  method).** Rejected — the existing "renewal is just an ordinary fresh
  `RequestLease`, there is no lease-mutation API" design is correct and
  load-bearing; `supervise.rs`'s existing loop already depends on this
  shape and needed no change.
- **A new QA feature-verification doc (`F-M2-005.md`).**
  Rejected for consistency — `qa_governance_sync.rs`'s hardcoded
  `FEATURE_IDS` list was not extended by any of the four prior MVP 2.0
  tickets either; adding one unilaterally here would be inconsistent,
  not more complete.

## Consequences

- Positive: two real fail-open bugs are closed, each with a regression
  test verified to fail against the pre-fix code before being confirmed
  as a real regression test (temporarily reverting each fix locally and
  observing the new test fail, then reapplying).
- Positive: a real backend-revoke error is now honestly recorded
  instead of silently indistinguishable from a deliberate no-op.
- Positive: a resource's revocability can now be made a hard grant-time
  precondition, opt-in, with a byte-identical default for every
  existing deployment.
- Negative (accepted, disclosed above): "best-effort revoke" is now
  honestly *plumbed* but remains entirely unproven against real
  hardware — this ADR does not claim otherwise.
- Negative (accepted, disclosed above): renewal remains audit-invisible
  as a distinct event (reconstructible only by correlation), and lease
  expiry itself still emits no dedicated audit event — both named as
  HORO-796 forward obligations rather than closed here.
- No `DOMAIN_SCHEMA_VERSION` change — stays at 5, confirmed unchanged by
  this ticket.

## AC mapping

| Ticket AC | Status |
|---|---|
| Long-running authorized workload renews silently while all required conditions remain valid | Already true (`supervise.rs`, unchanged) — confirmed by `authz_renewal.rs::renewal_succeeds_repeatedly_while_every_required_condition_still_holds` and the pre-existing `a_same_peer_second_request_lease_mints_an_independent_lease_and_the_old_one_stays_releasable` |
| Policy/session/resource change prevents subsequent renewal | Met for session (`authz_session.rs::bug_a_a_session_reaped_by_expiry_cascade_revokes_its_leases`, which also proves the renewal itself is refused), approval (`authz_renewal.rs::renewal_is_refused_after_the_approval_is_forgotten`), and resource capability (`::renewal_is_refused_after_the_resource_capability_changes`); policy-change-specific renewal refusal is met only via restart → `ForeignIssuer`, disclosed above, not via live policy-revision tracking |
| Explicit revoke blocks future authorization and has documented active-workload semantics | Already true (`LeaseIssuer::revoke`, `handle_release_lease`); "best-effort device-layer teardown" semantics now honestly recorded (`EnforcementResult::Error` fix) rather than asserted |
| Agent restart/reboot does not convert stale state into unintended access | Already true before this ticket (`ComputeLease` is `Serialize`-only, `IssuerInstanceId`-scoped) — this ticket's contribution is this disclosure plus existing test coverage, not new mechanism |
| Race/property tests cover issue/renew/revoke/expire transitions | Met — `authz_concurrency.rs` (capacity-overshoot, shared-resource release/request race, compensating-revoke leak check, duplicate-lease-id check under concurrency), using `std::thread::scope` |
| Offline/failure behavior is documented and deterministic | Met — this ADR's "best-effort revoke, undecorated" and "unbounded renewal in the fully-ungated default" disclosures, plus the Bug A/B fixes making the killed-process case actually tear down enforcement instead of leaking it |

## North Star unchanged

`PolicySet::evaluate` and `LeaseIssuer::issue` remain the sole
authorization decision points, exactly as before. Every change in this
ticket either closes a real enforcement-teardown gap (Bugs A and B) or
makes an already-correct decision's outcome more honestly recorded
(the `EnforcementResult::Error` fix) — none of it creates a new allow
source or loosens an existing check. "No protected compute without
authorization" holds exactly as it did before this ticket; if anything,
enforcement teardown is now *more* consistent with what was already
claimed.
