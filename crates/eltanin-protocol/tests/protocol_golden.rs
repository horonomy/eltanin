//! Golden/compatibility fixtures for every wire message shape (F-M1-006,
//! HORO-838). Each committed fixture under `tests/fixtures/` pins one
//! message's wire shape byte-for-byte (modulo whitespace, compared
//! structurally via `serde_json::Value`); a drift in field names, tag
//! values, or nesting fails CI rather than silently changing the wire
//! contract this ticket's AC calls "compatibility fixtures."

use std::time::Duration;

use eltanin_core::envelope::Versioned;
use eltanin_core::lease::{IssuerInstanceId, LeaseId};
use eltanin_core::resource::{Action, ResourceIdentity, ResourceKind, ResourceVendor};
use eltanin_core::session::SessionId;
use eltanin_protocol::request::{
    ClientRequest, CreateSessionRequest, LeaseRequest, ReleaseRequest, Request, RequestBody,
    RequestId,
};
use eltanin_protocol::response::{
    AgentResponse, AgentStatusView, DenialReason, ErrorCode, LeaseView, ReleaseOutcome, Response,
    ResponseBody, SessionView, TerminationOutcome,
};

fn resource() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-0".into(),
    }
}

fn lease_id() -> LeaseId {
    LeaseId {
        issuer: IssuerInstanceId::new("issuer-a"),
        sequence: 7,
    }
}

/// Asserts `value` matches the fixture at `path` structurally (parsed
/// `serde_json::Value` equality, so committed fixtures can be
/// pretty-printed for readability without the test being whitespace
/// sensitive) and that the fixture round-trips back into an identical
/// value.
fn assert_golden<T>(value: &T, fixture: &str)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let actual: serde_json::Value = serde_json::to_value(value).unwrap();
    let expected: serde_json::Value = serde_json::from_str(fixture).unwrap();
    assert_eq!(
        actual, expected,
        "wire shape drifted from the committed fixture"
    );

    let round_tripped: T = serde_json::from_str(fixture).unwrap();
    assert_eq!(
        &round_tripped, value,
        "fixture must deserialize back to the same value it was produced from"
    );
}

#[test]
fn request_lease_matches_fixture() {
    let value: Request = Versioned::current(RequestBody {
        request_id: RequestId(1),
        body: ClientRequest::RequestLease(LeaseRequest {
            resource: resource(),
            action: Action::Compute,
        }),
    });
    assert_golden(&value, include_str!("fixtures/request_lease.json"));
}

#[test]
fn release_lease_matches_fixture() {
    let value: Request = Versioned::current(RequestBody {
        request_id: RequestId(2),
        body: ClientRequest::ReleaseLease(ReleaseRequest {
            lease_id: lease_id(),
        }),
    });
    assert_golden(&value, include_str!("fixtures/release_lease.json"));
}

#[test]
fn agent_status_request_matches_fixture() {
    let value: Request = Versioned::current(RequestBody {
        request_id: RequestId(3),
        body: ClientRequest::AgentStatus {},
    });
    assert_golden(&value, include_str!("fixtures/agent_status_request.json"));
}

#[test]
fn response_lease_granted_matches_fixture() {
    let value: Response = Versioned::current(ResponseBody {
        request_id: Some(RequestId(1)),
        body: AgentResponse::LeaseGranted {
            lease: LeaseView {
                lease_id: lease_id(),
                remaining: Duration::from_secs(30),
            },
        },
    });
    assert_golden(&value, include_str!("fixtures/response_lease_granted.json"));
}

#[test]
fn response_lease_denied_matches_fixture() {
    let value: Response = Versioned::current(ResponseBody {
        request_id: Some(RequestId(1)),
        body: AgentResponse::LeaseDenied {
            reason: DenialReason::NoMatchingRule,
        },
    });
    assert_golden(&value, include_str!("fixtures/response_lease_denied.json"));
}

#[test]
fn response_released_matches_fixture() {
    let value: Response = Versioned::current(ResponseBody {
        request_id: Some(RequestId(2)),
        body: AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Released,
        },
    });
    assert_golden(&value, include_str!("fixtures/response_released.json"));
}

#[test]
fn response_status_matches_fixture() {
    let value: Response = Versioned::current(ResponseBody {
        request_id: Some(RequestId(3)),
        body: AgentResponse::Status {
            status: AgentStatusView {
                protocol_version: eltanin_core::envelope::DOMAIN_SCHEMA_VERSION,
            },
        },
    });
    assert_golden(&value, include_str!("fixtures/response_status.json"));
}

#[test]
fn response_error_unsupported_version_matches_fixture() {
    let value: Response = Versioned::current(ResponseBody {
        request_id: None,
        body: AgentResponse::Error {
            code: ErrorCode::UnsupportedVersion {
                found: 99,
                expected: eltanin_core::envelope::DOMAIN_SCHEMA_VERSION,
            },
        },
    });
    assert_golden(
        &value,
        include_str!("fixtures/response_error_unsupported_version.json"),
    );
}

fn session_id() -> SessionId {
    SessionId {
        issuer: IssuerInstanceId::new("issuer-a"),
        sequence: 0,
    }
}

#[test]
fn create_session_matches_fixture() {
    let value: Request = Versioned::current(RequestBody {
        request_id: RequestId(4),
        body: ClientRequest::CreateSession(CreateSessionRequest {
            resources: vec![resource()],
            ttl: Duration::from_mins(30),
        }),
    });
    assert_golden(&value, include_str!("fixtures/create_session.json"));
}

#[test]
fn list_sessions_matches_fixture() {
    let value: Request = Versioned::current(RequestBody {
        request_id: RequestId(5),
        body: ClientRequest::ListSessions {},
    });
    assert_golden(&value, include_str!("fixtures/list_sessions.json"));
}

#[test]
fn terminate_session_matches_fixture() {
    let value: Request = Versioned::current(RequestBody {
        request_id: RequestId(6),
        body: ClientRequest::TerminateSession {},
    });
    assert_golden(&value, include_str!("fixtures/terminate_session.json"));
}

#[test]
fn response_session_established_matches_fixture() {
    let value: Response = Versioned::current(ResponseBody {
        request_id: Some(RequestId(4)),
        body: AgentResponse::SessionEstablished {
            session: SessionView {
                session_id: session_id(),
                remaining: Duration::from_mins(30),
                resources: vec![resource()],
            },
        },
    });
    assert_golden(
        &value,
        include_str!("fixtures/response_session_established.json"),
    );
}

#[test]
fn response_session_list_matches_fixture() {
    let value: Response = Versioned::current(ResponseBody {
        request_id: Some(RequestId(5)),
        body: AgentResponse::SessionList {
            sessions: vec![SessionView {
                session_id: session_id(),
                remaining: Duration::from_mins(20),
                resources: vec![resource()],
            }],
        },
    });
    assert_golden(&value, include_str!("fixtures/response_session_list.json"));
}

#[test]
fn response_session_terminated_matches_fixture() {
    let value: Response = Versioned::current(ResponseBody {
        request_id: Some(RequestId(6)),
        body: AgentResponse::SessionTerminated {
            outcome: TerminationOutcome::Terminated,
        },
    });
    assert_golden(
        &value,
        include_str!("fixtures/response_session_terminated.json"),
    );
}

#[test]
fn response_lease_denied_no_trusted_session_matches_fixture() {
    let value: Response = Versioned::current(ResponseBody {
        request_id: Some(RequestId(1)),
        body: AgentResponse::LeaseDenied {
            reason: DenialReason::NoTrustedSession,
        },
    });
    assert_golden(
        &value,
        include_str!("fixtures/response_lease_denied_no_trusted_session.json"),
    );
}
