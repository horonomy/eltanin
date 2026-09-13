//! Golden JSON coverage for `RiskSignal`/`StepUpVerdict`'s wire shape
//! (F-M2-004, HORO-794). `RiskSignal` is `Serialize + Deserialize` (it
//! is embedded in `eltanin-audit`'s `RecordedOutcome`, which must be
//! readable back off disk). `StepUpVerdict` is `Serialize`-only, like
//! `DelegationVerdict`/`RecallVerdict`/`MembershipVerdict` — so only an
//! explicit golden string, not a round-trip, can pin its shape.

use std::collections::BTreeSet;

use eltanin_core::risk::{RiskSignal, StepUpVerdict};

#[test]
fn risk_signal_round_trips_through_json() {
    for signal in RiskSignal::ALL {
        let json = serde_json::to_string(signal).unwrap();
        let restored: RiskSignal = serde_json::from_str(&json).unwrap();
        assert_eq!(*signal, restored);
    }
}

#[test]
fn risk_signal_snake_case_json() {
    assert_eq!(
        serde_json::to_string(&RiskSignal::UnknownLauncher).unwrap(),
        "\"unknown_launcher\""
    );
    assert_eq!(
        serde_json::to_string(&RiskSignal::UntrustedExecutionPath).unwrap(),
        "\"untrusted_execution_path\""
    );
    assert_eq!(
        serde_json::to_string(&RiskSignal::LauncherIdentityChanged).unwrap(),
        "\"launcher_identity_changed\""
    );
    assert_eq!(
        serde_json::to_string(&RiskSignal::PrivilegeTransition).unwrap(),
        "\"privilege_transition\""
    );
    assert_eq!(
        serde_json::to_string(&RiskSignal::PrivilegeEscalationToRoot).unwrap(),
        "\"privilege_escalation_to_root\""
    );
    assert_eq!(
        serde_json::to_string(&RiskSignal::DetachedExecution).unwrap(),
        "\"detached_execution\""
    );
    assert_eq!(
        serde_json::to_string(&RiskSignal::DelegationScopeExpanded).unwrap(),
        "\"delegation_scope_expanded\""
    );
    assert_eq!(
        serde_json::to_string(&RiskSignal::SecurityPostureChanged).unwrap(),
        "\"security_posture_changed\""
    );
    assert_eq!(
        serde_json::to_string(&RiskSignal::ContextBoundaryChanged).unwrap(),
        "\"context_boundary_changed\""
    );
    assert_eq!(
        serde_json::to_string(&RiskSignal::TrustTransition).unwrap(),
        "\"trust_transition\""
    );
    assert_eq!(
        serde_json::to_string(&RiskSignal::EvidenceIndeterminate).unwrap(),
        "\"evidence_indeterminate\""
    );
}

#[test]
fn no_step_up_golden_json() {
    let verdict = StepUpVerdict::NoStepUp {
        signals: BTreeSet::from([RiskSignal::UnknownLauncher]),
    };
    let json = serde_json::to_string_pretty(&verdict).unwrap();
    let expected = r#"{
  "verdict": "no_step_up",
  "signals": [
    "unknown_launcher"
  ]
}"#;
    assert_eq!(json, expected);
}

#[test]
fn step_up_required_golden_json() {
    let verdict = StepUpVerdict::StepUpRequired {
        signals: BTreeSet::from([RiskSignal::LauncherIdentityChanged]),
    };
    let json = serde_json::to_string_pretty(&verdict).unwrap();
    let expected = r#"{
  "verdict": "step_up_required",
  "signals": [
    "launcher_identity_changed"
  ]
}"#;
    assert_eq!(json, expected);
}

#[test]
fn risk_denied_golden_json() {
    let verdict = StepUpVerdict::RiskDenied {
        signals: BTreeSet::from([RiskSignal::PrivilegeEscalationToRoot]),
    };
    let json = serde_json::to_string_pretty(&verdict).unwrap();
    let expected = r#"{
  "verdict": "risk_denied",
  "signals": [
    "privilege_escalation_to_root"
  ]
}"#;
    assert_eq!(json, expected);
}

#[test]
fn multiple_signals_serialize_in_declaration_order() {
    let verdict = StepUpVerdict::StepUpRequired {
        signals: BTreeSet::from([
            RiskSignal::EvidenceIndeterminate,
            RiskSignal::UnknownLauncher,
            RiskSignal::TrustTransition,
        ]),
    };
    let json = serde_json::to_string_pretty(&verdict).unwrap();
    let expected = r#"{
  "verdict": "step_up_required",
  "signals": [
    "unknown_launcher",
    "trust_transition",
    "evidence_indeterminate"
  ]
}"#;
    assert_eq!(json, expected);
}
