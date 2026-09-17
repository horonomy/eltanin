# Test Plan — Eltanin MVP 2.0 (HORO-810, this revision HORO-797)

The versioned Track A (QA/Security engineering) test plan for the
`Eltanin MVP 2.0 — Trusted Local Protection` milestone (HORO-773), per
[`docs/qa/README.md`](../README.md)'s governance. This plan states what
test layer exists, what's genuinely absent, and never claims hardware
evidence this repository does not have. It follows
[`mvp-1.0.md`](mvp-1.0.md)'s exact shape and only restates what actually
changed for MVP 2.0 — where a layer's MVP 1.0 status still holds
unchanged, this plan says so rather than re-deriving it. See
[`docs/qa/e2e/README.md`](../e2e/README.md) for Track B (Product/
Business E2E); this plan does not duplicate that evidence class.

`crates/eltanin-cli/tests/qa_governance_sync.rs` mechanically enforces
that every test file path this plan cites actually exists — see that
file's doc comment for exactly what it checks and doesn't.

## Quality model — 10 layers

| # | Layer | Status | Notes |
|---|---|---|---|
| 1 | Unit tests | REQUIRED | Unchanged from MVP 1.0 — present in every crate; run by `cargo test --workspace` in CI. |
| 2 | Domain/property tests | DEFERRED (partial) | Same deferral as MVP 1.0 (no `proptest`/`quickcheck` anywhere in the workspace, verified: `grep -r proptest\|quickcheck\|arbitrary Cargo.toml` across every crate returns nothing). New golden coverage for MVP 2.0's two new wire-shape domains: `crates/eltanin-core/tests/risk_golden.rs` (`RiskSignal`/`StepUpVerdict` JSON round-trip and snake_case shape, F-M2-004) and `crates/eltanin-core/tests/delegation_golden.rs` (`DelegationGrant` serialize shape and its deliberate non-`Deserialize` derive, F-M2-003). Still deferred, not N/A, for the same reason as MVP 1.0: no incident currently justifies the new dependency. |
| 3 | Protocol/parser fuzzing | DEFERRED | Unchanged from MVP 1.0 — `eltanin-protocol/tests/protocol_fail_closed.rs` remains the hand-written negative-input coverage; no structured fuzzing harness exists. Six `DOMAIN_SCHEMA_VERSION` wire-shape additions (sessions, approvals, delegation, step-up, revocation-adjacent, shadow/audit) since MVP 1.0 have not changed this gap's nature — deferred pending a driving incident, same as before. |
| 4 | Component/integration tests | REQUIRED | The bulk of MVP 2.0's new coverage: `crates/eltanin-agent/tests/{authz_session,authz_approval,authz_delegation,authz_step_up,authz_shadow,authz_concurrency,authz_lifecycle,authz_revocation}.rs`, `crates/eltanin-audit/tests/retention.rs`, `crates/eltanin-cli/tests/{shadow_run_lifecycle,status_binary,explain_audit_binary}.rs` — every one of these paths verified to exist on `next/mvp-2.0` at the time of writing. `authz_shadow.rs` is a differential equivalence suite (shadow vs. enforce mode produce byte-identical outcomes on every gate except the final grant/no-grant step) rather than an ordinary integration file — see layer 6 and the invariant map below for its disclosed coverage gap. |
| 5 | Privileged Linux/cgroup/eBPF integration tests | DEFERRED — blocked on hardware | Unchanged from MVP 1.0. F-M1-007 still owns this layer and has not started. Two MVP 2.0 features declare (not build) a cgroup-scoped seam pending this layer: `SessionAssurance::CgroupScope` (ADR 0009, F-M2-001) and `DelegationBounds::require_same_cgroup`'s actual device/cgroup-layer containment (ADR 0011, F-M2-003, disclosure 7) — both are admission-side-only today, not enforcement. See "Hardware requirement" below. |
| 6 | Adversarial/security regression corpus | REQUIRED | Substantially expanded for MVP 2.0 — see "North Star invariant → defending tests" and the "12-scenario adversarial matrix" section below for the indexed list (HORO-797). |
| 7 | Failure/recovery/upgrade/rollback tests | REQUIRED (partial) | **Upgrade from NOT APPLICABLE.** MVP 1.0 marked this N/A because "there is no shipped prior version to upgrade from or roll back to." That is no longer true: `DOMAIN_SCHEMA_VERSION` bumped 1→2 (ADR 0009) →3 (ADR 0010) →4 (ADR 0011) →5 (ADR 0012) →6 (ADR 0014; ADR 0013 made no bump), and every bump invalidates every pre-existing durable `Approval` (`recall()`'s schema-version comparison, HORO-792 mechanism) — a real, repeatedly-exercised upgrade consequence with no rollback story: there is no downgrade path, and a re-approval is required after every bump. Failure/recovery proper is REQUIRED and extensive: `authz_lifecycle.rs::a_lease_from_a_prior_agent_instance_does_not_survive_a_restart`, `crates/eltanin-core/tests/lease_restart.rs::lease_from_a_prior_issuer_instance_is_rejected_as_foreign`, `authz_session.rs::bug_a_a_session_reaped_by_expiry_cascade_revokes_its_leases` (a real fail-open bug found and fixed during F-M2-005/ADR 0013), `authz_lifecycle.rs::bug_b_an_expired_lease_releases_backend_enforcement_via_the_sweep` (a second fail-open bug, same ticket). Rollback (reverting to an older `DOMAIN_SCHEMA_VERSION` after upgrading) remains untested and undesigned — DEFERRED, no ticket owns it. |
| 8 | Compatibility/hardware matrix tests | DEFERRED — blocked on hardware | Unchanged from MVP 1.0. See "Hardware requirement" below. |
| 9 | Performance/soak tests | **DEFERRED (changed from NOT APPLICABLE)** | MVP 1.0 marked this N/A because MVP 1.0 made no throughput/scale claim. MVP 2.0's own Jira AC (HORO-773) makes a real, user-facing claim instead: a Trusted Compute Session lets a developer "work for hours without prompting" (ADR 0009) with "negligible repetitive prompts" (HORO-797's AC) and asks for "authorization latency/compute overhead" to be measured. Verified: no latency/overhead instrumentation exists anywhere in the workspace today (`grep -rn "instrument\|tracing\|latency\|metrics" crates/*/src` finds only a doc comment in `eltanin-audit/src/sink.rs` explicitly declining to "invent a new metrics subsystem," no working meter). A real, uninstrumented product claim now exists where MVP 1.0 had none — DEFERRED with reason (no instrumentation built yet), not N/A, is the honest status. HORO-797's Developer Dogfood Scenario (prompt/false-block/latency metrics) is the mechanism intended to close this gap; it has not run as of this test plan's writing. |
| 10 | Supply-chain/release integrity tests | REQUIRED (partial), with a known branch gap | `cargo-deny` continues to run in CI on every PR, unchanged from MVP 1.0. **Known gap**: `origin/main` carries two commits not yet merged forward into `origin/next/mvp-2.0` — `34420fc` (CodeQL advanced setup covering Actions and Rust) and `177afa1` (CI workflow `GITHUB_TOKEN` restricted to `contents:read`), landed via PR #58/#59 (HORO-1270) on `main` after `next/mvp-2.0` branched. This means `next/mvp-2.0`'s current CI does not yet run CodeQL and has not yet had its default `GITHUB_TOKEN` scope hardened — a real, stated gap in this branch's security-scan evidence, not a fabricated pass. Closing it is a forward-merge from `main`, not new work. |

## North Star invariant → defending tests

[`docs/product/NORTH_STAR.md`](../../product/NORTH_STAR.md)'s 9 locked
invariants are unchanged by MVP 2.0 (every new gate is additive and
pre-policy — see each Feature Verification Record's "North Star
unchanged" reasoning). This table restates MVP 1.0's map only where
MVP 2.0 added or strengthened defending tests; see
[`mvp-1.0.md`](mvp-1.0.md)'s own table for invariants 2, 8, 9, which are
unchanged.

| # | Invariant | Defending tests (MVP 2.0 additions) |
|---|---|---|
| 1 | Authorization before consumption; default deny | Unchanged mechanism (`PolicySet::evaluate` untouched by every MVP 2.0 ADR); every new gate (session, approval, delegation, step-up, revocation) sits *before* this check, never replacing it — `authz_session.rs`, `authz_approval.rs`, `authz_delegation.rs`, `authz_step_up.rs` all include a byte-identical-to-pre-gate regression (e.g. `authz_step_up.rs::default_config_without_step_up_is_byte_identical_to_pre_horo_794`). |
| 3 | Monitoring != Security | `crates/eltanin-audit/tests/retention.rs` extends this for bounded/rotated storage: a discarded record is reported as `SelectionResult::RetentionDiscarded`, distinct from "never happened" — the same "audit is evidence, not authority" principle MVP 1.0 established, now proven under rotation. Shadow mode (`authz_shadow.rs`) is the sharpest instance of this invariant in MVP 2.0: `ShadowVerdict` is explicitly "not a security control" (ADR 0014) — observing a decision is never mistaken for enforcing it, mechanically distinguished by `AgentResponse::ShadowObserved` never causing a real `backend.enforce()` call (`authz_shadow.rs::successful_admission_produces_would_grant_with_zero_backend_enforce_calls`). |
| 4 | Contextual signals are not authority | `crates/eltanin-core/tests/delegation_admission.rs` (self-asserted uid/session-key/executable-path evidence is `Indeterminate`, never trusted), `authz_step_up.rs`'s `RiskSignal` classification (a signal never confers admission, only names why a refusal already happened — `StepUpVerdict` has no admit variant, ADR 0012). |
| 5 | Remember authorization intent, never possession of privilege | **Strengthened from documentation-level to machine-asserted.** MVP 1.0 marked this invariant documentation-level only, defended by `lease_expiry.rs`/`authz_renewal.rs`. F-M2-002 (Remembered Authorization Intent) productizes it directly: `authz_approval.rs::once_is_consumed_after_a_single_successful_use` (a `Once` approval cannot be reused), `::a_changed_executable_digest_is_reevaluated_and_denied` (a changed binding is re-evaluated fresh, never trusted from the stored bytes), `::forget_removes_a_durable_approval`, `::deny_overrides_a_remember_for_the_same_launcher`, and `authz_session.rs::s12_a_durable_approval_survives_restart_while_the_session_and_its_lease_do_not` (the restart asymmetry that proves *intent* survives while *possession* — the session, the lease — does not). `ApprovalSet::from_document`'s Deserialize-safe row is re-validated fresh via `recall()` on every use; the bytes are evidence to re-check, never bare authority (ADR 0010). |
| 6 | A lease is scoped and expiring | `authz_concurrency.rs` (capacity/duplicate-id/race coverage under real concurrency), `authz_lifecycle.rs::an_expired_leases_slot_is_reclaimed_by_prune_before_the_capacity_check`, `::bug_b_an_expired_lease_releases_backend_enforcement_via_the_sweep` (a real fail-open bug fixed under this invariant, F-M2-005). |
| 7 | Locally observable identity is not overridable by caller claims | `crates/eltanin-core/tests/identity_adversarial.rs::pid_reused_by_unrelated_process_is_reported_different_not_same` (pre-existing, still the defending test for PID reuse — see the adversarial matrix section below), extended by MVP 2.0's session/delegation ancestry checks (`authz_session.rs::ac2_a_foreign_session_process_cannot_join_by_pid_alone`, `delegation_admission.rs::holder_pid_reused_by_unrelated_process_is_not_admitted`). |

## 12-scenario adversarial matrix (HORO-797)

HORO-797's Jira description names 12 required adversarial scenarios,
numbered here S1–S12 in the order the ticket states them. This table
indexes each to its defending test(s) — 7 were added by the dedicated
adversarial-matrix PR (#63, `mvp-2.0/HORO-797/adversarial_matrix_tests`,
merge commit `f459066`); the remaining 5 were already covered by
pre-existing MVP 1.0/MVP 2.0 tests before that PR, and 1 (S11) is
genuinely blocked on hardware.

| # | Scenario (HORO-797 wording) | Coverage | Defending test(s) |
|---|---|---|---|
| S1 | Process restart and PID reuse | Pre-existing (MVP 1.0) | `crates/eltanin-core/tests/identity_adversarial.rs::pid_reused_by_unrelated_process_is_reported_different_not_same`, `::same_pid_different_binary_disguised_as_restart_is_not_reported_same` |
| S2 | Binary replacement / identity change | Pre-existing (MVP 1.0 execve substitution) + MVP 2.0 digest binding | `crates/eltanin-agent/tests/authz_release.rs::an_execve_substitution_is_refused_even_with_the_same_pid_and_start_token` (MVP 1.0); `authz_approval.rs::a_changed_executable_digest_is_reevaluated_and_denied` (F-M2-002) |
| S3 | Same-user unrelated process attempting compute | New (PR #63) | `authz_session.rs::s3_a_same_session_unrelated_process_is_admitted_with_no_further_defense` — `PINS_LIMITATION`: pins ADR 0009's `postinstall` trade-off and ADR 0010 disclosure 2 as real, not hypothetical |
| S4 | Descendant privilege laundering | New (PR #63) | `crates/eltanin-core/tests/delegation_admission.rs::uid_transition_inside_ancestry_span_is_invisible_to_admission` — `PINS_LIMITATION`: `ProcessAncestor` has no uid field, so a uid transition strictly inside the requester→holder ancestry span is invisible to admission (ADR 0011 disclosure 3) |
| S5 | Python/Node/shell interpreter misuse | New (PR #63) | `authz_approval.rs::s5_approving_an_interpreter_admits_a_later_invocation_with_a_different_script` — `PINS_LIMITATION`: ADR 0010's AC4-partial, the argv-invisibility gap |
| S6 | Malicious/unexpected child from a trusted agent/tool | New (PR #63) | `authz_delegation.rs::s6_a_depth_one_descendant_with_an_unexpected_executable_is_still_admitted` — `PINS_LIMITATION`: ADR 0011 disclosure 5 (trust-transition detection is path-only, and a depth-1 descendant's transition-marker scan span is empty) |
| S7 | Downloaded/temp executable | New (PR #63) | `authz_step_up.rs::s7_agent_level_untrusted_execution_path_composes_through_the_real_gate_chain` — `PROVES_DEFENSE`: `RiskSignal::UntrustedExecutionPath` composes through the real gate chain as a step-up-shaped refusal (ADR 0012) |
| S8 | Detached persistent daemon | New (PR #63) | `authz_step_up.rs::s8a_a_real_detached_process_fires_detached_execution_through_the_real_gate_chain` — `PROVES_DEFENSE` (a real `setsid()`-detached process fires `RiskSignal::DetachedExecution`); `::s8b_pins_that_under_the_default_config_a_detached_process_is_admitted_anyway` — `PINS_LIMITATION` (the approval gate short-circuits before risk classification runs under default config, so the same detached process is admitted with zero friction unless step-up is explicitly configured) |
| S9 | Policy/session revoke during long-running work | Pre-existing (MVP 2.0) | `authz_session.rs::ac3_terminating_a_session_prevents_new_lease_issuance_under_required`, `::ac3_terminating_a_session_revokes_leases_issued_under_it` (F-M2-001) |
| S10 | Lease expiry/renewal races | Pre-existing (MVP 2.0) | `authz_concurrency.rs` (capacity-overshoot, shared-resource release/request race, compensating-revoke leak, duplicate-lease-id checks under real concurrency via `std::thread::scope`), `authz_lifecycle.rs::an_expired_lease_is_pruned_and_no_longer_releasable` (F-M2-005) |
| S11 | Inherited/already-open device handle behavior | **BLOCKED_ON_E3** | No test exists or can exist without real device/GPU handle access — this scenario is intrinsically a hardware-enforcement question (does a device handle opened before a lease existed, or surviving after a lease's revocation, still work), not something a `FakeBackend` can answer honestly. Blocked on the same Linux/NVIDIA bare-metal access as F-M1-002/F-M1-007 (see "Hardware requirement" below). Not fabricated or simulated. |
| S12 | Agent restart/reboot/offline-policy cases | New (PR #63) | `authz_session.rs::s12_a_durable_approval_survives_restart_while_the_session_and_its_lease_do_not` — `PROVES_DEFENSE` (design-honesty): proves the restart asymmetry directly (a durable `Remember` approval survives an agent restart; the Trusted Compute Session and its lease do not) |

## Hardware requirement (F-M1-002, F-M1-007, HORO-790, and now S11)

Unchanged from [`mvp-1.0.md`](mvp-1.0.md)'s "Hardware requirement"
section — **zero hardware evidence exists today**, no representative
bare-metal Linux/NVIDIA host has been identified. MVP 2.0 adds no new
hardware dependency of its own; it adds one new named consequence of the
existing gap (S11 above) and two declared-but-unbuilt cgroup seams
(`SessionAssurance::CgroupScope`, ADR 0009; `DelegationBounds`'s actual
cgroup/device-layer containment, ADR 0011) that remain admission-side
labels, not enforcement, until F-M1-007/E3 lands. Every MVP 2.0 Feature
is additionally labeled `UNVERIFIED_ON_BARE_METAL` in its own ADR and
Feature Verification Record: a Trusted Compute Session, a remembered
approval, a bounded delegation, a risk-based step-up, and lease-lifecycle
hardening all gate lease *issuance* — none of them proves anything about
real device-level access, which remains F-M1-007's unchanged scope. See
`docs/development/hardware-validation-runbook.md` for the full runbook;
this test plan does not repeat it.

This repository does not fabricate, simulate, or project hardware
results under any circumstance.

## Machine-readable evidence emission

Unchanged from MVP 1.0: deferred, no consumer yet. MVP 2.0 has not
changed this — no release gate has emitted machine-readable evidence,
and none is imminent as of this plan's writing (HORO-797 itself, the
MVP 2.0 release-readiness gate, is the ticket this plan is written
under).

## Open gaps summary

| Gap | Closeable now? |
|---|---|
| No versioned test plan for MVP 2.0 | Closed by this document. |
| No Feature Verification Records for F-M2-001..006 | Closed by `docs/qa/feature-verification/F-M2-00{1..6}.md` (this same PR). |
| `next/mvp-2.0` is missing `origin/main`'s CodeQL + CI token-hardening commits (#58/#59, HORO-1270) | Closeable via a forward-merge from `main` — not new work, but not done as of this plan. |
| Upgrade/rollback: rollback direction (downgrading `DOMAIN_SCHEMA_VERSION` after a bump) | Deferred — no ticket owns it; every bump is one-directional (invalidates durable approvals, no reverse path). |
| Performance/latency instrumentation for the "hours without prompting"/step-up-overhead claim | Deferred — no instrumentation exists; HORO-797's Developer Dogfood Scenario is the intended closing mechanism, not yet run. |
| S11 (inherited/already-open device handle behavior) | Blocked on Linux/NVIDIA bare-metal hardware access, same as F-M1-002/F-M1-007. |
| Structured fuzzing / property-based testing | Deferred, unchanged from MVP 1.0 — no incident currently justifies the new dependency. |
| Hardware matrix + privileged Linux/cgroup/eBPF suites | Deferred — blocked on hardware access, unchanged from MVP 1.0. |
| Machine-readable CI evidence (JUnit/JSON/SARIF/coverage) | Deferred — no consumer until a release gate is imminent, unchanged from MVP 1.0. |
| F-M2-001/002/005 are not yet operator-configurable via `eltanin-agentd` | No `.with_session_requirement()`/`.with_approval_store()`/`.with_delegation()`/`.with_revocation_requirement()` call exists in `crates/eltanin-agent/src/bin/eltanin-agentd.rs` as of this plan's writing (verified by reading the file) — these gates are library-reachable (usable by any binary that constructs `AuthorizationConfig` directly, and exercised by every integration test cited above) but not yet exposed as `eltanin-agentd` environment-variable configuration, unlike F-M2-006's shadow mode (`ELTANIN_AGENT_MODE`). No PR closing this gap has merged into `next/mvp-2.0` as of this writing. |
