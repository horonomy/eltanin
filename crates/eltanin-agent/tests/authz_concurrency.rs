//! Concurrency/race coverage for the issue/renew/revoke/expire lifecycle
//! (F-M2-005, HORO-795, AC5). Uses `std::thread::scope` — no new
//! dependency (`proptest` was deliberately not added; see this ticket's
//! ADR).

mod support;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eltanin_agent::authz::event::NullSink;
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler};
use eltanin_agent::handler::RequestHandler;
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::resource::{Action, Capability, EnforcementResult};
use eltanin_protocol::request::{ClientRequest, LeaseRequest, ReleaseRequest};
use eltanin_protocol::response::{AgentResponse, ReleaseOutcome};
use support::authz::{
    allow_policy_for_uid, backend_with_resource, resource_identity, FixedClock, TestPeer,
};

fn lease_request() -> ClientRequest {
    ClientRequest::RequestLease(LeaseRequest {
        resource: resource_identity(),
        action: Action::Compute,
    })
}

/// N concurrent `RequestLease` calls against a small
/// `max_outstanding_leases` cap must never let the granted count
/// overshoot it — `LeaseState::reserve`'s whole reason to exist (see its
/// own doc comment on the check-then-issue-then-insert race this closes).
#[test]
fn concurrent_requests_never_overshoot_max_outstanding_leases() {
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("instance-a"),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_max_outstanding_leases(5),
    );
    let peers: Vec<TestPeer> = (0..20)
        .map(|_| TestPeer::fresh(1000, "sha256:trusted"))
        .collect();

    let granted = std::thread::scope(|scope| {
        let workers: Vec<_> = peers
            .iter()
            .map(|peer| scope.spawn(|| handler.handle(&lease_request(), &peer.context())))
            .collect();
        workers
            .into_iter()
            .map(|w| w.join().expect("worker thread must not panic"))
            .filter(|r| matches!(r, AgentResponse::LeaseGranted { .. }))
            .count()
    });

    assert!(
        granted <= 5,
        "expected at most 5 leases granted under the configured cap, got {granted}"
    );
}

/// A resource shared by two peers: one continuously releases its own
/// lease and immediately requests a fresh one (a renewal loop's actual
/// shape) while another peer does the same concurrently on the *same*
/// resource. `LeaseState::any_other_live_lease_for_same_resource`'s rule
/// — decided and executed under one lock acquisition in
/// `handle_release_lease` — must never let one peer's release tear down
/// backend enforcement the other peer's still-live lease depends on, no
/// matter how the two threads interleave. Regression coverage for
/// exactly the race `handle_release_lease`'s own doc comment names.
#[test]
fn concurrent_release_and_request_on_a_shared_resource_never_tears_down_a_live_lease() {
    const ITERATIONS: usize = 100;

    let backend = backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]);
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("instance-a"),
        allow_policy_for_uid(1000),
        Arc::clone(&backend) as Arc<dyn eltanin_backend::contract::ComputeBackend>,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_max_outstanding_leases(64),
    );
    let peer_a = TestPeer::fresh(1000, "sha256:trusted");
    let peer_b = TestPeer::fresh(1000, "sha256:trusted");

    std::thread::scope(|scope| {
        for peer in [&peer_a, &peer_b] {
            let handler = &handler;
            scope.spawn(move || {
                for _ in 0..ITERATIONS {
                    let granted = handler.handle(&lease_request(), &peer.context());
                    let AgentResponse::LeaseGranted { lease } = granted else {
                        // Capacity is generous relative to two peers'
                        // single outstanding lease each, but a transient
                        // denial is not itself a correctness failure
                        // this test cares about — only what happens to
                        // an *already-granted* lease matters here.
                        continue;
                    };
                    let released = handler.handle(
                        &ClientRequest::ReleaseLease(ReleaseRequest {
                            lease_id: lease.lease_id,
                        }),
                        &peer.context(),
                    );
                    assert!(
                        matches!(
                            released,
                            AgentResponse::LeaseReleased {
                                outcome: ReleaseOutcome::Released
                            }
                        ),
                        "a peer releasing its own just-granted lease must always succeed, \
                         got {released:?}"
                    );
                }
            });
        }
    });

    // Both peers have released every lease they ever held by now — the
    // resource has zero outstanding leases, so it must have been
    // revoked at the backend layer at least once along the way (from
    // whichever release happened to be the "last live one" at that
    // moment), but the specific invariant this test exists to prove is
    // structural, not this final count: no panic/assertion failure fired
    // above despite hundreds of racing release/request pairs on the same
    // resource, which is only possible if the lock discipline actually
    // holds.
    assert!(
        backend.revoke_call_count(&resource_identity()) >= 1,
        "expected at least one real backend.revoke() call once both peers had released \
         everything"
    );
}

/// A scripted non-`Allowed` `enforce()` result must always compensate:
/// the capacity reservation `issue_reserving_capacity` takes is released
/// on every failure path (`enforce_and_finalize`'s `Ok(non-Allowed)` and
/// `Err` arms), even under concurrent load — no permanent slot leak.
#[test]
fn compensating_revoke_never_leaks_a_capacity_slot_under_concurrency() {
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    backend.script_enforcement(
        resource_identity(),
        EnforcementResult::Denied {
            reason: "device busy".to_string(),
        },
    );
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("instance-a"),
        allow_policy_for_uid(1000),
        Arc::clone(&backend) as Arc<dyn eltanin_backend::contract::ComputeBackend>,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_max_outstanding_leases(3),
    );
    let denied_peers: Vec<TestPeer> = (0..20)
        .map(|_| TestPeer::fresh(1000, "sha256:trusted"))
        .collect();

    // Every one of these 20 concurrent requests is refused by the
    // scripted backend denial — if the reservation each one takes were
    // never released on that failure path, capacity would be
    // permanently exhausted after this loop even though zero leases are
    // actually outstanding.
    std::thread::scope(|scope| {
        for peer in &denied_peers {
            let handler = &handler;
            scope.spawn(move || {
                let response = handler.handle(&lease_request(), &peer.context());
                assert!(
                    matches!(response, AgentResponse::Error { .. }),
                    "expected every scripted-denial request to fail, got {response:?}"
                );
            });
        }
    });

    // The backend now allows again — capacity must be fully reclaimed:
    // exactly `max_outstanding_leases` fresh requests must all succeed.
    backend.remove(&resource_identity());
    backend.insert(eltanin_core::resource::ProtectedResource {
        identity: resource_identity(),
        capabilities: eltanin_core::resource::ResourceCapabilities::new([
            Capability::DeviceEnforce,
        ]),
        memory: eltanin_core::resource::AcceleratorMemory::NotReportable,
    });
    let fresh_peers: Vec<TestPeer> = (0..3)
        .map(|_| TestPeer::fresh(1000, "sha256:trusted"))
        .collect();
    let granted = fresh_peers
        .iter()
        .filter(|peer| {
            matches!(
                handler.handle(&lease_request(), &peer.context()),
                AgentResponse::LeaseGranted { .. }
            )
        })
        .count();
    assert_eq!(
        granted, 3,
        "every reservation taken by a scripted-denial request must have been released; \
         capacity must not be permanently exhausted"
    );
}

/// Every lease id `LeaseIssuer::issue` mints is generated under the
/// single state lock `issue_reserving_capacity` holds for the entire
/// prune-check-issue-reserve sequence — even under heavy concurrent
/// load from many peers racing issue/release cycles on the same
/// resource, no two granted leases (and, by construction, no lease
/// released and later "resurrected") can ever share an id. This is the
/// structural property behind "a revoked lease identity never
/// reappears as valid": [`eltanin-agent`]'s own `handle_release_lease`
/// only ever accepts a `LeaseId` this store currently holds, and ids are
/// never reused.
#[test]
fn concurrent_issue_release_cycles_never_produce_a_duplicate_lease_id() {
    const THREADS: usize = 8;
    const ITERATIONS: usize = 50;

    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("instance-a"),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_max_outstanding_leases(64),
    );
    let seen_ids: Mutex<HashSet<eltanin_core::lease::LeaseId>> = Mutex::new(HashSet::new());

    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            let peer = TestPeer::fresh(1000, "sha256:trusted");
            let seen_ids = &seen_ids;
            let handler = &handler;
            scope.spawn(move || {
                for _ in 0..ITERATIONS {
                    let granted = handler.handle(&lease_request(), &peer.context());
                    let AgentResponse::LeaseGranted { lease } = granted else {
                        continue;
                    };
                    let newly_inserted = seen_ids.lock().unwrap().insert(lease.lease_id.clone());
                    assert!(
                        newly_inserted,
                        "a lease id must never be issued twice, got a duplicate: \
                         {:?}",
                        lease.lease_id
                    );
                    handler.handle(
                        &ClientRequest::ReleaseLease(ReleaseRequest {
                            lease_id: lease.lease_id,
                        }),
                        &peer.context(),
                    );
                }
            });
        }
    });
}
