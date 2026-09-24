//! DFC-MODE-01, DFC-SCHEMA-12, DFC-ELIG-02/05: shadow/enforce mode
//! mapping and the malformed-record refusal.

mod support;

use eltanin_audit::record::RecordedEnforcementMode;
use eltanin_dogfood::adapter::project_record;
use eltanin_dogfood::event::{ActualAction, DecisionMode, Eligibility, Profile};

/// DFC-MODE-01: a `Shadow`-mode `WouldGrant` record projects to
/// `decision_mode=observe`, `actual_action=no_op`, `would_action=allow`
/// — never a claim of real authority.
#[test]
fn shadow_would_grant_projects_to_observe_no_op_would_allow() {
    let record = support::base_record(
        "instance-a",
        1,
        RecordedEnforcementMode::Shadow,
        support::would_grant("instance-a", 1),
        None,
    );
    let event = project_record(&record, Profile::Personal, "0.1.0", zero_time()).unwrap();
    assert_eq!(event.decision_mode, DecisionMode::Observe);
    assert_eq!(event.actual_action, ActualAction::NoOp);
    assert_eq!(event.would_action, Some(ActualAction::Allow));
    // DFC-ELIG-02: Eltanin's authz family is never eligible for transfer.
    assert_eq!(event.eligibility, Eligibility::NonReplayableOperation);
}

/// The mirror case: `Shadow`-mode `PolicyDenied` → `would_action=deny`,
/// `actual_action` still `no_op` (nothing was actually denied — nothing
/// was actually enforced at all under observe).
#[test]
fn shadow_policy_denied_projects_to_observe_no_op_would_deny() {
    let record = support::base_record(
        "instance-a",
        2,
        RecordedEnforcementMode::Shadow,
        eltanin_audit::record::RecordedOutcome::PolicyDenied {
            decision: fake_policy_decision(),
        },
        None,
    );
    let event = project_record(&record, Profile::Personal, "0.1.0", zero_time()).unwrap();
    assert_eq!(event.actual_action, ActualAction::NoOp);
    assert_eq!(event.would_action, Some(ActualAction::Deny));
}

/// DFC-SCHEMA-12: `scope_id` is required under `enforce`. A record with
/// `session: None` under `Enforce` must be refused, never fabricated.
#[test]
fn enforce_with_no_session_is_refused_not_fabricated() {
    let record = support::base_record(
        "instance-a",
        3,
        RecordedEnforcementMode::Enforce,
        support::granted("instance-a", 3),
        None,
    );
    let result = project_record(&record, Profile::Personal, "0.1.0", zero_time());
    assert!(
        result.is_err(),
        "expected refusal for enforce+session=None, got {result:?}"
    );
}

/// The positive case: `Enforce` + a real session projects a real
/// `scope_id`, `actual_action=allow`, `would_action=None`.
#[test]
fn enforce_with_session_projects_a_real_scope_id() {
    let record = support::base_record(
        "instance-a",
        4,
        RecordedEnforcementMode::Enforce,
        support::granted("instance-a", 4),
        Some(support::session_id("instance-a", 9)),
    );
    let event = project_record(&record, Profile::Personal, "0.1.0", zero_time()).unwrap();
    assert_eq!(event.decision_mode, DecisionMode::Enforce);
    assert_eq!(event.scope_id.as_deref(), Some("instance-a#9"));
    assert_eq!(event.actual_action, ActualAction::Allow);
    assert_eq!(event.would_action, None);
}

fn zero_time() -> eltanin_audit::record::WallClockTime {
    eltanin_audit::record::WallClockTime {
        unix_secs: 1_790_244_903,
        nanos: 0,
    }
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
