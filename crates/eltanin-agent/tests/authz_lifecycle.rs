//! Restart, disconnect, expiry, and capacity lifecycle coverage
//! (F-M1-006, HORO-840). AC #4 ("Restart/disconnect behavior has
//! integration tests").

mod support;

use std::sync::Arc;
use std::time::Duration;

use eltanin_agent::authz::event::NullSink;
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler};
use eltanin_agent::handler::RequestHandler;
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::resource::{Action, Capability};
use eltanin_protocol::request::{ClientRequest, LeaseRequest, ReleaseRequest};
use eltanin_protocol::response::{AgentResponse, ErrorCode, ReleaseOutcome};
use support::authz::{allow_policy_for_uid, backend_with_resource, resource_identity, FixedClock, TestPeer};

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

fn make_handler(instance: &str, ttl: Duration) -> AuthorizationHandler {
    AuthorizationHandler::new(
        IssuerInstanceId::new(instance),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::Enforce, Capability::Revoke]),
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(ttl).unwrap(),
    )
}

#[test]
fn a_lease_survives_multiple_independent_calls_without_being_released() {
    // Each `handle()` call here stands in for one transport connection
    // (HORO-839's serve_connection is one-request-per-connection) — a
    // lease's lifetime is bound to its TTL, never to any one
    // connection, so an AgentStatus call on an unrelated "connection" in
    // between must not disturb it.
    let handler = make_handler("instance-a", Duration::from_secs(60));
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let granted = handler.handle(&lease_request(), &peer.context());
    let lease_id = granted_lease_id(&granted);

    let _ = handler.handle(&ClientRequest::AgentStatus {}, &peer.context());
    let _ = handler.handle(&ClientRequest::AgentStatus {}, &peer.context());

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
fn a_lease_from_a_prior_agent_instance_does_not_survive_a_restart() {
    // "Restart" = a fresh AuthorizationHandler (fresh LeaseIssuer
    // instance, empty in-memory store) — exactly what HORO-840's design
    // states an agent process restart produces. A lease id naming the
    // old instance must never resolve against the new one.
    let before_restart = make_handler("instance-before", Duration::from_secs(60));
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let granted = before_restart.handle(&lease_request(), &peer.context());
    let lease_id = granted_lease_id(&granted);
    assert_eq!(lease_id.issuer, IssuerInstanceId::new("instance-before"));

    let after_restart = make_handler("instance-after", Duration::from_secs(60));
    let response = after_restart.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest { lease_id }),
        &peer.context(),
    );

    assert_eq!(
        response,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Refused
        }
    );
}

#[test]
fn an_expired_lease_is_pruned_and_no_longer_releasable() {
    let clock = FixedClock::new();
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("instance-a"),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::Enforce]),
        Arc::clone(&clock) as Arc<dyn eltanin_agent::authz::Clock>,
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(5)).unwrap(),
    );
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let granted = handler.handle(&lease_request(), &peer.context());
    let lease_id = granted_lease_id(&granted);

    clock.advance(Duration::from_secs(6));

    let response = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest { lease_id }),
        &peer.context(),
    );
    assert_eq!(
        response,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Refused
        }
    );
}

#[test]
fn a_request_beyond_max_outstanding_leases_fails_safely_without_granting() {
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("instance-a"),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::Enforce]),
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_max_outstanding_leases(1),
    );
    let first_peer = TestPeer::fresh(1000, "sha256:trusted");
    let second_peer = TestPeer::fresh(1000, "sha256:trusted");

    let first = handler.handle(&lease_request(), &first_peer.context());
    assert!(matches!(first, AgentResponse::LeaseGranted { .. }));

    let second = handler.handle(&lease_request(), &second_peer.context());
    assert_eq!(second, AgentResponse::Error { code: ErrorCode::Internal });
}

#[test]
fn an_expired_leases_slot_is_reclaimed_by_prune_before_the_capacity_check() {
    let clock = FixedClock::new();
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("instance-a"),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::Enforce]),
        Arc::clone(&clock) as Arc<dyn eltanin_agent::authz::Clock>,
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(5))
            .unwrap()
            .with_max_outstanding_leases(1),
    );
    let first_peer = TestPeer::fresh(1000, "sha256:trusted");
    let second_peer = TestPeer::fresh(1000, "sha256:trusted");

    let first = handler.handle(&lease_request(), &first_peer.context());
    assert!(matches!(first, AgentResponse::LeaseGranted { .. }));

    clock.advance(Duration::from_secs(6));

    // The first lease has expired; prune() at the top of RequestLease
    // must reclaim its slot before the capacity check runs.
    let second = handler.handle(&lease_request(), &second_peer.context());
    assert!(
        matches!(second, AgentResponse::LeaseGranted { .. }),
        "expected LeaseGranted after the prior lease expired, got {second:?}"
    );
}
