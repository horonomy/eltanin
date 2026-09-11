//! `ReleaseLease` coverage: happy path, double-release, cross-client
//! refusal, and execve-substitution refusal (F-M1-006, HORO-840) — the
//! `docs/product/SECURITY_MODEL.md` named obligation on HORO-840.

mod support;

use std::sync::Arc;
use std::time::Duration;

use eltanin_agent::authz::event::NullSink;
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler};
use eltanin_agent::handler::RequestHandler;
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::resource::{Action, Capability};
use eltanin_protocol::request::{ClientRequest, LeaseRequest, ReleaseRequest};
use eltanin_protocol::response::{AgentResponse, ReleaseOutcome};
use support::authz::{
    allow_policy_for_uid, backend_with_resource, resource_identity, FixedClock, TestPeer,
};

fn handler() -> AuthorizationHandler {
    AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::Enforce, Capability::Revoke]),
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    )
}

fn lease_request() -> ClientRequest {
    ClientRequest::RequestLease(LeaseRequest {
        resource: resource_identity(),
        action: Action::Compute,
    })
}

fn granted_lease_id(response: &AgentResponse) -> eltanin_core::lease::LeaseId {
    match response {
        AgentResponse::LeaseGranted { lease } => lease.lease_id.clone(),
        other => panic!("expected LeaseGranted, got {other:?}"),
    }
}

#[test]
fn the_same_client_can_release_its_own_lease() {
    let handler = handler();
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let granted = handler.handle(&lease_request(), &peer.context());
    let lease_id = granted_lease_id(&granted);

    let response = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest { lease_id }),
        &peer.context(),
    );

    assert_eq!(
        response,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Released
        }
    );
}

#[test]
fn releasing_an_already_released_lease_is_refused_not_double_released() {
    let handler = handler();
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let granted = handler.handle(&lease_request(), &peer.context());
    let lease_id = granted_lease_id(&granted);

    let first = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest {
            lease_id: lease_id.clone(),
        }),
        &peer.context(),
    );
    let second = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest { lease_id }),
        &peer.context(),
    );

    assert_eq!(
        first,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Released
        }
    );
    assert_eq!(
        second,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Refused
        }
    );
}

#[test]
fn a_different_client_cannot_release_another_clients_lease() {
    let handler = handler();
    let owner = TestPeer::fresh(1000, "sha256:trusted");
    let attacker = TestPeer::fresh(1000, "sha256:trusted"); // same uid, distinct pid/start
    let granted = handler.handle(&lease_request(), &owner.context());
    let lease_id = granted_lease_id(&granted);

    let response = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest {
            lease_id: lease_id.clone(),
        }),
        &attacker.context(),
    );

    assert_eq!(
        response,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Refused
        }
    );

    // The real owner can still release it — the attacker's attempt did
    // not consume or invalidate the lease.
    let owner_release = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest { lease_id }),
        &owner.context(),
    );
    assert_eq!(
        owner_release,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Released
        }
    );
}

#[test]
fn an_execve_substitution_is_refused_even_with_the_same_pid_and_start_token() {
    let handler = handler();
    let original = TestPeer::fresh(1000, "sha256:trusted-binary");
    let granted = handler.handle(&lease_request(), &original.context());
    let lease_id = granted_lease_id(&granted);

    // Same pid/start token (compare_process => Same) but a different
    // executable hash (compare_executable => Different) — an in-place
    // execve() swap after the lease was issued.
    let mut swapped = original.clone();
    swapped.executable_hash = "sha256:swapped-binary";

    let response = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest { lease_id }),
        &swapped.context(),
    );

    assert_eq!(
        response,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Refused
        }
    );
}

#[test]
fn releasing_an_unknown_lease_id_is_refused() {
    let handler = handler();
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let response = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest {
            lease_id: eltanin_core::lease::LeaseId {
                issuer: IssuerInstanceId::new("test-instance"),
                sequence: 999,
            },
        }),
        &peer.context(),
    );

    assert_eq!(
        response,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Refused
        }
    );
}
