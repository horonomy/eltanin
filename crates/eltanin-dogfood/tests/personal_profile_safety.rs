//! ADR-0012 §2.2 / North Star safety: personal profile never denies,
//! blocks, or kills a managed test workload.
//!
//! # Why this is phrased structurally, not "no denial ever appears"
//!
//! A naive test asserting "no projected event ever has
//! `actual_action=deny`" would be **false to the evidence, not a real
//! property** — an `Enforce`-mode `PolicyDenied` record genuinely denied
//! something, and reporting anything other than `actual_action=deny` for
//! it would be exactly the kind of overclaim `08b4d48` on this branch had
//! to walk back (that commit fixed a *different* overclaim, but the
//! shape of the mistake — reporting a happier outcome than what actually
//! happened — is the same one this test structure exists to avoid
//! repeating). The defensible, testable version of "personal profile
//! does not deny/kill managed test workloads" is: **every record
//! projected from a `Shadow` (observe) source has `actual_action=no_op`,
//! never `deny`** — nothing was actually enforced under observe, by
//! construction (`RecordedOutcome::WouldGrant`'s own doc comment: "never
//! a claim of real authority") — and the adapter never emits the
//! ADR-0012 §3-malformed combination `decision_mode=observe` +
//! `actual_action=deny`.

mod support;

use eltanin_audit::record::{RecordedEnforcementMode, RecordedOutcome};
use eltanin_dogfood::adapter::project_record;
use eltanin_dogfood::event::{ActualAction, DecisionMode, Profile};

fn zero_time() -> eltanin_audit::record::WallClockTime {
    eltanin_audit::record::WallClockTime {
        unix_secs: 1_790_244_903,
        nanos: 0,
    }
}

/// Every `Shadow`-mode outcome this codebase can produce, exhaustively —
/// if a future `RecordedOutcome` variant is added and this adapter's
/// mapping is ever changed carelessly to return `Deny` for `Observe`,
/// this test (not just the two targeted cases in `mode_mapping.rs`)
/// catches it.
#[test]
fn no_shadow_sourced_record_ever_projects_actual_action_deny() {
    let outcomes: Vec<RecordedOutcome> = vec![
        support::would_grant("i", 1),
        RecordedOutcome::PolicyDenied {
            decision: fake_policy_decision(),
        },
        RecordedOutcome::PeerNotAuthorizable,
        RecordedOutcome::StatusReported,
        RecordedOutcome::SessionNotFound,
        RecordedOutcome::ApprovalRequired,
        RecordedOutcome::ApprovalDenied,
    ];
    for (n, outcome) in outcomes.into_iter().enumerate() {
        let record = support::base_record(
            "i",
            n as u64,
            RecordedEnforcementMode::Shadow,
            outcome,
            None,
        );
        let event = project_record(&record, Profile::Personal, "0.1.0", zero_time()).unwrap();
        assert_eq!(
            event.actual_action,
            ActualAction::NoOp,
            "a Shadow-sourced record must never carry a real actual_action, got {:?} for record {n}",
            event.actual_action
        );
        assert_ne!(
            event.actual_action,
            ActualAction::Deny,
            "personal/observe profile must never report a real deny for record {n}"
        );
    }
}

/// ADR-0012 §3: "a record with `decision_mode=observe` and
/// `actual_action=deny` is malformed by construction" — this adapter
/// must never emit that combination, for any `RecordedOutcome`.
#[test]
fn observe_and_actual_action_deny_never_co_occur() {
    let record = support::base_record(
        "i",
        0,
        RecordedEnforcementMode::Shadow,
        RecordedOutcome::PolicyDenied {
            decision: fake_policy_decision(),
        },
        None,
    );
    let event = project_record(&record, Profile::Personal, "0.1.0", zero_time()).unwrap();
    assert!(
        !(event.decision_mode == DecisionMode::Observe
            && event.actual_action == ActualAction::Deny)
    );
}

fn fake_policy_decision() -> eltanin_audit::record::RecordedPolicyDecision {
    eltanin_audit::record::RecordedPolicyDecision {
        effect: eltanin_core::policy::Effect::Deny,
        reason: eltanin_audit::record::RecordedDecisionReason::NoMatchingRule,
        policy: eltanin_audit::record::RecordedPolicyProvenance {
            policy_id: eltanin_core::policy::PolicyId::new("policy-1"),
            policy_revision: 1,
            schema_version: eltanin_core::envelope::DOMAIN_SCHEMA_VERSION,
        },
    }
}
