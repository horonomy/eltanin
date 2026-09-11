//! Failure-message exhaustiveness coverage (F-M1-008, HORO-845): every
//! `LaunchFailure` and every `DenialReason` produces a non-empty message
//! and a non-empty, concrete next action.

use eltanin_cli::failure::{classify_response, LaunchFailure};
use eltanin_protocol::response::{AgentResponse, DenialReason, ErrorCode, LeaseView};
use eltanin_protocol::response::{AgentStatusView, ReleaseOutcome};

fn all_failures() -> Vec<LaunchFailure> {
    vec![
        LaunchFailure::Usage("missing --".to_string()),
        LaunchFailure::ProfileUnresolved("no such profile".to_string()),
        LaunchFailure::AgentUnavailable("connection refused".to_string()),
        LaunchFailure::AgentError(ErrorCode::Internal),
        LaunchFailure::AgentError(ErrorCode::MalformedRequest),
        LaunchFailure::AgentError(ErrorCode::Oversized),
        LaunchFailure::AgentError(ErrorCode::UnknownOperation),
        LaunchFailure::AgentError(ErrorCode::UnsupportedVersion {
            found: 2,
            expected: 1,
        }),
        LaunchFailure::Denied(DenialReason::NoMatchingRule),
        LaunchFailure::Denied(DenialReason::ExplicitDeny),
        LaunchFailure::Denied(DenialReason::IndeterminateEvidence),
        LaunchFailure::GovernedContextFailed("permission denied".to_string()),
        LaunchFailure::AuthorizationLapsed,
    ]
}

#[test]
fn every_launch_failure_has_a_non_empty_message_and_next_action() {
    for failure in all_failures() {
        assert!(
            !failure.message().is_empty(),
            "{failure:?} must have a non-empty message"
        );
        assert!(
            !failure.next_action().is_empty(),
            "{failure:?} must have a non-empty next action"
        );
    }
}

#[test]
fn a_denials_next_action_names_eltanin_explain_by_pid_never_request_id() {
    let failure = LaunchFailure::Denied(DenialReason::ExplicitDeny);
    let next_action = failure.next_action();
    assert!(
        next_action.contains("eltanin-explain"),
        "expected the denial next action to name eltanin-explain, got {next_action:?}"
    );
    assert!(
        next_action.contains("--pid"),
        "expected the denial next action to correlate by pid, got {next_action:?}"
    );
    assert!(
        !next_action.to_lowercase().contains("requestid")
            && !next_action.to_lowercase().contains("request_id"),
        "must never point at RequestId for audit correlation (F-M1-009 forward obligation), \
         got {next_action:?}"
    );
}

#[test]
fn agent_internal_error_message_does_not_overclaim_a_specific_cause() {
    let message = LaunchFailure::AgentError(ErrorCode::Internal).message();
    // Internal deliberately collapses backend failure / enforcement
    // refusal / capacity exhaustion into one wire variant — the message
    // must say so, not invent a specific one of those three.
    assert!(
        message.to_lowercase().contains("does not distinguish")
            || message.to_lowercase().contains("wire protocol"),
        "expected the Internal error message to be honest about not knowing the specific \
         cause, got {message:?}"
    );
}

#[test]
fn a_lease_granted_response_classifies_to_no_failure() {
    let response = AgentResponse::LeaseGranted {
        lease: LeaseView {
            lease_id: eltanin_core::lease::LeaseId {
                issuer: eltanin_core::lease::IssuerInstanceId::new("i"),
                sequence: 0,
            },
            remaining: std::time::Duration::from_secs(1),
        },
    };
    assert_eq!(classify_response(&response), None);
}

#[test]
fn a_denied_response_classifies_to_a_denied_failure() {
    let response = AgentResponse::LeaseDenied {
        reason: DenialReason::NoMatchingRule,
    };
    assert_eq!(
        classify_response(&response),
        Some(LaunchFailure::Denied(DenialReason::NoMatchingRule))
    );
}

#[test]
fn an_error_response_classifies_to_an_agent_error_failure() {
    let response = AgentResponse::Error {
        code: ErrorCode::Internal,
    };
    assert_eq!(
        classify_response(&response),
        Some(LaunchFailure::AgentError(ErrorCode::Internal))
    );
}

#[test]
fn responses_eltanin_run_never_sends_a_request_for_classify_to_an_agent_error_not_a_panic() {
    // eltanin run's initial request is always RequestLease, so
    // LeaseReleased/Status are wire-legal responses this crate's call
    // sites never actually see as the *first* response — classify_response
    // must still handle them without panicking.
    let released = AgentResponse::LeaseReleased {
        outcome: ReleaseOutcome::Released,
    };
    assert!(classify_response(&released).is_some());

    let status = AgentResponse::Status {
        status: AgentStatusView {
            protocol_version: 1,
        },
    };
    assert!(classify_response(&status).is_some());
}
