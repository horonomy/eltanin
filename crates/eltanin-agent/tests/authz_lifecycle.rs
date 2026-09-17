//! Restart, disconnect, expiry, and capacity lifecycle coverage
//! (F-M1-006, HORO-840). AC #4 ("Restart/disconnect behavior has
//! integration tests").

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use eltanin_agent::authz::event::{AuthorizationEvent, EventSink, NullSink};
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler};
use eltanin_agent::handler::RequestHandler;
use eltanin_audit::record::RecordedAgentEvent;
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::resource::{Action, Capability, EnforcementResult};
use eltanin_protocol::request::{ClientRequest, LeaseRequest, ReleaseRequest};
use eltanin_protocol::response::{AgentResponse, ErrorCode, ReleaseOutcome};
use support::authz::{
    allow_policy_for_uid, backend_with_resource, resource_identity, FixedClock, TestPeer,
};

/// Captures every [`RecordedAgentEvent`] this handler emits, in order —
/// HORO-796 subtask 2's `LeaseExpired` wiring has no wire-visible effect,
/// so tests for it must observe this seam rather than the wire response.
/// Discards ordinary per-request [`AuthorizationEvent`]s; no test in this
/// file needs them.
#[derive(Default)]
struct CapturingAgentEventSink {
    events: Mutex<Vec<RecordedAgentEvent>>,
}

impl EventSink for CapturingAgentEventSink {
    fn record(&self, _event: &AuthorizationEvent<'_>) {}

    fn record_agent_event(&self, event: RecordedAgentEvent) {
        self.events.lock().unwrap().push(event);
    }
}

impl CapturingAgentEventSink {
    fn events(&self) -> Vec<RecordedAgentEvent> {
        self.events.lock().unwrap().clone()
    }
}

/// A bogus `ReleaseLease` request against a lease id that was never
/// issued — used purely to trigger `sweep_expired_leases` (which runs at
/// the top of both `RequestLease` and `ReleaseLease` handling) without
/// coupling the trigger itself to backend/resource availability the way
/// a real `RequestLease` trigger would.
fn sweep_trigger_release(instance: &str, sequence: u64) -> ClientRequest {
    ClientRequest::ReleaseLease(ReleaseRequest {
        lease_id: eltanin_core::lease::LeaseId {
            issuer: IssuerInstanceId::new(instance),
            sequence,
        },
    })
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

fn make_handler(instance: &str, ttl: Duration) -> AuthorizationHandler {
    AuthorizationHandler::new(
        IssuerInstanceId::new(instance),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
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
        backend_with_resource(&[Capability::DeviceEnforce]),
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
        backend_with_resource(&[Capability::DeviceEnforce]),
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
    assert_eq!(
        second,
        AgentResponse::Error {
            code: ErrorCode::Internal
        }
    );
}

#[test]
fn concurrent_requests_never_overshoot_max_outstanding_leases() {
    // Regression coverage for a race an adversarial review found: the
    // capacity check and the eventual store insert happen under
    // separate lock acquisitions (enforce() runs unlocked in between),
    // so without a reservation held for the whole window, N concurrent
    // RequestLease calls could all observe capacity as free before any
    // of them inserts, overshooting max_outstanding_leases. Each
    // connection is served on its own thread in the real server, so
    // this is a genuine cross-thread scenario.
    let handler = Arc::new(AuthorizationHandler::new(
        IssuerInstanceId::new("instance-a"),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_max_outstanding_leases(5),
    ));

    let threads: Vec<_> = (0..20)
        .map(|_| {
            let handler = Arc::clone(&handler);
            let peer = TestPeer::fresh(1000, "sha256:trusted");
            std::thread::spawn(move || handler.handle(&lease_request(), &peer.context()))
        })
        .collect();

    let granted = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .filter(|r| matches!(r, AgentResponse::LeaseGranted { .. }))
        .count();

    assert!(
        granted <= 5,
        "expected at most 5 leases granted under the configured cap, got {granted}"
    );
}

/// Bug regression (F-M2-005, HORO-795): before this fix,
/// `LeaseState::prune` (called by `issue_reserving_capacity` and
/// `handle_release_lease`) removed an expired lease's *lease-state*
/// record but never called `backend.revoke()` — a workload whose
/// controlling `eltanin run` process was killed (so `ReleaseLease` is
/// never called) kept live backend-side enforcement indefinitely after
/// its lease silently expired.
#[test]
fn bug_b_an_expired_lease_releases_backend_enforcement_via_the_sweep() {
    let clock = FixedClock::new();
    let backend = backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]);
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("instance-a"),
        allow_policy_for_uid(1000),
        Arc::clone(&backend) as Arc<dyn eltanin_backend::contract::ComputeBackend>,
        Arc::clone(&clock) as Arc<dyn eltanin_agent::authz::Clock>,
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(5)).unwrap(),
    );
    let first_peer = TestPeer::fresh(1000, "sha256:trusted");
    let granted = handler.handle(&lease_request(), &first_peer.context());
    assert!(matches!(granted, AgentResponse::LeaseGranted { .. }));
    assert_eq!(backend.revoke_call_count(&resource_identity()), 0);

    // Simulate the controlling `eltanin run` process being killed:
    // nothing ever calls ReleaseLease, and the lease simply expires.
    clock.advance(Duration::from_secs(6));

    // A subsequent request (from any peer) triggers the lazy
    // expired-lease sweep at the top of RequestLease handling.
    let second_peer = TestPeer::fresh(1000, "sha256:trusted");
    let _ = handler.handle(&lease_request(), &second_peer.context());

    assert_eq!(
        backend.revoke_call_count(&resource_identity()),
        1,
        "an expired lease must trigger exactly one backend.revoke() call for its resource"
    );
}

#[test]
fn an_expired_leases_slot_is_reclaimed_by_prune_before_the_capacity_check() {
    let clock = FixedClock::new();
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("instance-a"),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
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

#[test]
fn two_leases_expiring_on_the_same_resource_each_emit_their_own_lease_expired_event() {
    let clock = FixedClock::new();
    let backend = backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]);
    let sink = Arc::new(CapturingAgentEventSink::default());
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("instance-a"),
        allow_policy_for_uid(1000),
        Arc::clone(&backend) as Arc<dyn eltanin_backend::contract::ComputeBackend>,
        Arc::clone(&clock) as Arc<dyn eltanin_agent::authz::Clock>,
        Arc::clone(&sink) as Arc<dyn eltanin_agent::authz::event::EventSink>,
        &AuthorizationConfig::new(Duration::from_secs(5)).unwrap(),
    );

    let peer_a = TestPeer::fresh(1000, "sha256:trusted");
    let peer_b = TestPeer::fresh(1000, "sha256:trusted");
    let granted_a = handler.handle(&lease_request(), &peer_a.context());
    let granted_b = handler.handle(&lease_request(), &peer_b.context());
    let id_a = granted_lease_id(&granted_a);
    let id_b = granted_lease_id(&granted_b);
    assert_ne!(id_a, id_b);

    clock.advance(Duration::from_secs(6));

    // Trigger the sweep without issuing a third RequestLease against the
    // same resource, so the sweep's own effects are the only thing this
    // assertion depends on.
    let _ = handler.handle(
        &sweep_trigger_release("instance-a", 999),
        &TestPeer::fresh(1000, "sha256:trusted").context(),
    );

    assert_eq!(
        backend.revoke_call_count(&resource_identity()),
        1,
        "HORO-795's dedup rule must still hold: one revoke call per resource, \
         not per expired lease"
    );

    let events = sink.events();
    let expired: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            RecordedAgentEvent::LeaseExpired {
                lease_id, backend, ..
            } => Some((lease_id.clone(), backend.clone())),
            RecordedAgentEvent::AuditLogRotated { .. } => None,
        })
        .collect();
    assert_eq!(
        expired.len(),
        2,
        "expected one LeaseExpired event per expired lease, got {expired:?}"
    );
    let ids: std::collections::BTreeSet<_> = expired.iter().map(|(id, _)| id.clone()).collect();
    assert!(ids.contains(&id_a) && ids.contains(&id_b));
    // Both leases shared a resource that genuinely was torn down (no
    // sibling kept it live), so both events must report the real
    // backend outcome, not `None`.
    for (_, backend_result) in &expired {
        assert_eq!(backend_result, &Some(EnforcementResult::Allowed));
    }
}

/// A lease expiring while a sibling lease on the same resource is still
/// live must report `backend: None` on its `LeaseExpired` event — HORO-795's
/// teardown-skip rule (no revoke while another live lease names the
/// resource) must be visible on the audit trail, not just in the absence
/// of a `backend.revoke()` call.
#[test]
fn an_expired_lease_with_a_still_live_sibling_reports_no_backend_teardown() {
    let clock = FixedClock::new();
    let backend = backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]);
    let sink = Arc::new(CapturingAgentEventSink::default());
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("instance-a"),
        allow_policy_for_uid(1000),
        Arc::clone(&backend) as Arc<dyn eltanin_backend::contract::ComputeBackend>,
        Arc::clone(&clock) as Arc<dyn eltanin_agent::authz::Clock>,
        Arc::clone(&sink) as Arc<dyn eltanin_agent::authz::event::EventSink>,
        &AuthorizationConfig::new(Duration::from_secs(5)).unwrap(),
    );

    let peer_a = TestPeer::fresh(1000, "sha256:trusted");
    let granted_a = handler.handle(&lease_request(), &peer_a.context());
    let id_a = granted_lease_id(&granted_a);

    // b's lease is issued 3s later, so it outlives a's by 3s under the
    // same 5s handler TTL.
    clock.advance(Duration::from_secs(3));
    let peer_b = TestPeer::fresh(1000, "sha256:trusted");
    let granted_b = handler.handle(&lease_request(), &peer_b.context());
    assert!(matches!(granted_b, AgentResponse::LeaseGranted { .. }));

    // Now a has expired (issued at t=0, ttl=5s) but b (issued at t=3,
    // ttl=5s, expires at t=8) is still live.
    clock.advance(Duration::from_secs(3));

    let _ = handler.handle(
        &sweep_trigger_release("instance-a", 999),
        &TestPeer::fresh(1000, "sha256:trusted").context(),
    );

    assert_eq!(
        backend.revoke_call_count(&resource_identity()),
        0,
        "a live sibling lease must still suppress the backend teardown"
    );

    let events = sink.events();
    let expired: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            RecordedAgentEvent::LeaseExpired {
                lease_id, backend, ..
            } => Some((lease_id.clone(), backend.clone())),
            RecordedAgentEvent::AuditLogRotated { .. } => None,
        })
        .collect();
    assert_eq!(
        expired.len(),
        1,
        "only a should have expired, got {expired:?}"
    );
    assert_eq!(expired[0].0, id_a);
    assert_eq!(
        expired[0].1, None,
        "teardown was skipped because b's lease keeps the resource live, so \
         `backend` must be None, not a fabricated result"
    );
}
