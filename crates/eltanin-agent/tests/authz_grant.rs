//! `RequestLease` grant-path coverage against a real `FakeBackend`
//! (F-M1-006, HORO-840). AC #1 ("End-to-end local request works with
//! Fake Backend") and AC #2 ("Unauthorized request cannot mint a valid
//! lease").

mod support;

use std::sync::Arc;
use std::time::Duration;

use eltanin_agent::authz::event::NullSink;
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler};
use eltanin_agent::handler::RequestHandler;
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::resource::Capability;
use eltanin_protocol::request::{ClientRequest, LeaseRequest};
use eltanin_protocol::response::{AgentResponse, DenialReason, ErrorCode};
use support::authz::{
    allow_policy_for_uid, backend_with_resource, deny_all_policy, resource_identity, FixedClock,
    TestPeer,
};

fn handler_with(
    policy: eltanin_core::policy::PolicySet,
    backend: Arc<eltanin_backend::fake::FakeBackend>,
) -> AuthorizationHandler {
    AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        policy,
        backend,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    )
}

fn lease_request() -> ClientRequest {
    ClientRequest::RequestLease(LeaseRequest {
        resource: resource_identity(),
        action: eltanin_core::resource::Action::Compute,
    })
}

#[test]
fn an_authorized_request_is_granted_end_to_end_with_the_fake_backend() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let handler = handler_with(
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
    );

    let response = handler.handle(&lease_request(), &peer.context());

    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "expected LeaseGranted, got {response:?}"
    );
}

#[test]
fn a_request_denied_by_policy_cannot_mint_a_lease() {
    let peer = TestPeer::fresh(2000, "sha256:untrusted");
    // Policy only allows uid 1000; this peer is uid 2000.
    let handler = handler_with(
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
    );

    let response = handler.handle(&lease_request(), &peer.context());

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::NoMatchingRule
        }
    );
}

#[test]
fn an_empty_policy_denies_every_request() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let handler = handler_with(
        deny_all_policy(),
        backend_with_resource(&[Capability::DeviceEnforce]),
    );

    let response = handler.handle(&lease_request(), &peer.context());

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::NoMatchingRule
        }
    );
}

#[test]
fn a_non_authorizable_peer_is_denied_never_evaluated_against_policy() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    // Would be allowed if `authorizable()` were bypassed.
    let handler = handler_with(
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
    );

    let response = handler.handle(&lease_request(), &peer.inconsistent_context());

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::IndeterminateEvidence
        }
    );
}

#[test]
fn a_backend_lacking_enforce_capability_never_grants_a_lease() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    // Policy allows it, but the backend cannot enforce — must not be
    // treated as if enforcement silently succeeded.
    let handler = handler_with(allow_policy_for_uid(1000), backend_with_resource(&[]));

    let response = handler.handle(&lease_request(), &peer.context());

    assert_eq!(
        response,
        AgentResponse::Error {
            code: ErrorCode::Internal
        }
    );
}

#[test]
fn a_capability_downgrade_leaves_no_lease_available_to_release_later() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let handler = handler_with(allow_policy_for_uid(1000), backend_with_resource(&[]));
    let _ = handler.handle(&lease_request(), &peer.context());

    // Even if a client somehow guessed a lease id, nothing was ever
    // inserted into the store for a request that never actually
    // enforced.
    let release = ClientRequest::ReleaseLease(eltanin_protocol::request::ReleaseRequest {
        lease_id: eltanin_core::lease::LeaseId {
            issuer: IssuerInstanceId::new("test-instance"),
            sequence: 0,
        },
    });
    let response = handler.handle(&release, &peer.context());
    assert_eq!(
        response,
        AgentResponse::LeaseReleased {
            outcome: eltanin_protocol::response::ReleaseOutcome::Refused
        }
    );
}
