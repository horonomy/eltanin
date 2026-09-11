//! Server-side renewal semantics coverage (F-M1-008, HORO-846). Not new
//! agent behavior — pins already-merged `eltanin-core`/`eltanin-agent`
//! (HORO-836/840) behavior that HORO-846's `eltanin run` lease-renewal
//! loop depends on: a same-peer second `RequestLease` mints an
//! independent lease, the old lease is still releasable after the new
//! grant, and releasing it never tears down the new grant's enforcement.

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

fn lease_request() -> ClientRequest {
    ClientRequest::RequestLease(LeaseRequest {
        resource: resource_identity(),
        action: Action::Compute,
    })
}

#[test]
fn a_same_peer_second_request_lease_mints_an_independent_lease_and_the_old_one_stays_releasable() {
    let backend = backend_with_resource(&[Capability::Enforce, Capability::Revoke]);
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        Arc::clone(&backend) as Arc<dyn eltanin_backend::contract::ComputeBackend>,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
    // One peer, two requests — the renewal loop's actual shape: the same
    // eltanin run process asks for a fresh lease before its old one
    // expires.
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let first = handler.handle(&lease_request(), &peer.context());
    let first_id = match first {
        AgentResponse::LeaseGranted { lease } => lease.lease_id,
        other => panic!("expected LeaseGranted, got {other:?}"),
    };

    let second = handler.handle(&lease_request(), &peer.context());
    let second_id = match second {
        AgentResponse::LeaseGranted { lease } => lease.lease_id,
        other => panic!("expected LeaseGranted, got {other:?}"),
    };
    assert_ne!(
        first_id, second_id,
        "a renewal must mint a genuinely independent lease, not reuse the old id"
    );

    // The old lease must still be releasable now that a second lease on
    // the same resource is live — if it weren't, the renewal loop's
    // acquire-then-release ordering would silently leak one lease per
    // renewal until TTL, with no visible failure anywhere.
    let release_old = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest { lease_id: first_id }),
        &peer.context(),
    );
    assert!(
        matches!(
            release_old,
            AgentResponse::LeaseReleased {
                outcome: ReleaseOutcome::Released
            }
        ),
        "expected the old lease to still be releasable after the new grant, got {release_old:?}"
    );

    // Releasing the old lease must not tear down the new grant's
    // enforcement — the direct proof behind CLI_CONTRACT's "the old
    // release cannot tear down the new grant's enforcement" claim.
    assert_eq!(
        backend.revoke_call_count(&resource_identity()),
        0,
        "releasing the superseded lease must not call backend.revoke while the new lease is live"
    );

    // Clean up: the new lease is still live and releasable too.
    let release_new = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest {
            lease_id: second_id,
        }),
        &peer.context(),
    );
    assert!(matches!(
        release_new,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Released
        }
    ));
}
