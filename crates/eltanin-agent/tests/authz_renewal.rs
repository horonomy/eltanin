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
use eltanin_core::resource::{AcceleratorMemory, Action, Capability, ResourceCapabilities};
use eltanin_protocol::request::{
    ApproveRequest, ClientRequest, ForgetApprovalRequest, LeaseRequest, ReleaseRequest,
};
use eltanin_protocol::response::{AgentResponse, DenialReason, ErrorCode, ReleaseOutcome};
use support::authz::{
    allow_policy_for_uid, backend_with_resource, resource_identity, FixedClock, TestPeer,
};
use support::temp_approval_store_path;

fn lease_request() -> ClientRequest {
    ClientRequest::RequestLease(LeaseRequest {
        resource: resource_identity(),
        action: Action::Compute,
    })
}

#[test]
fn a_same_peer_second_request_lease_mints_an_independent_lease_and_the_old_one_stays_releasable() {
    let backend = backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]);
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

// Session-expiry renewal re-gating is covered in `authz_session.rs`'s
// `bug_a_a_session_reaped_by_expiry_cascade_revokes_its_leases` (which
// also proves the renewal attempt itself is refused, not just the
// cascade-revoke side effect) — establishing a real Trusted Compute
// Session requires kernel-observed session-key evidence for a real
// pid, which this file's synthetic `TestPeer` fixture cannot provide
// (see `authz_session.rs`'s own module docs on why it uses real pids).

/// AC2 (F-M2-005, HORO-795): a renewal is refused once a remembered
/// approval it depended on has been forgotten, even though the same
/// peer's earlier `RequestLease` succeeded.
#[test]
fn renewal_is_refused_after_the_approval_is_forgotten() {
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_approval_store(temp_approval_store_path("renewal-approval-forgotten")),
    );
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let recorded = handler.handle(
        &ClientRequest::Approve(ApproveRequest {
            resource: resource_identity(),
            action: Action::Compute,
            disposition: eltanin_core::approval::ApprovalDisposition::Remember,
        }),
        &peer.context(),
    );
    let AgentResponse::ApprovalRecorded { approval } = recorded else {
        panic!("expected ApprovalRecorded, got {recorded:?}");
    };

    let first = handler.handle(&lease_request(), &peer.context());
    assert!(
        matches!(first, AgentResponse::LeaseGranted { .. }),
        "expected the first grant while the approval is still remembered, got {first:?}"
    );

    let forgotten = handler.handle(
        &ClientRequest::ForgetApproval(ForgetApprovalRequest { id: approval.id }),
        &peer.context(),
    );
    assert_eq!(
        forgotten,
        AgentResponse::ApprovalForgotten {
            outcome: eltanin_protocol::response::ForgetOutcome::Forgotten
        }
    );

    let renewal = handler.handle(&lease_request(), &peer.context());
    assert_eq!(
        renewal,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired
        },
        "a renewal must be refused once the approval it depended on has been forgotten"
    );
}

/// AC2 (F-M2-005, HORO-795): every gate re-runs on every renewal, not
/// just the ones that changed since the last grant — a resource
/// capability downgrade between the first grant and the renewal attempt
/// must refuse the renewal via the same enforcement path a fresh
/// request would take.
#[test]
fn renewal_is_refused_after_the_resource_capability_changes() {
    let backend = backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]);
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        Arc::clone(&backend) as Arc<dyn eltanin_backend::contract::ComputeBackend>,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let first = handler.handle(&lease_request(), &peer.context());
    let first_id = match first {
        AgentResponse::LeaseGranted { lease } => lease.lease_id,
        other => panic!("expected LeaseGranted, got {other:?}"),
    };
    handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest { lease_id: first_id }),
        &peer.context(),
    );

    // The resource downgrades to no longer support DeviceEnforce at all
    // — e.g. a driver reset the backend now honestly reports.
    backend.insert(eltanin_core::resource::ProtectedResource {
        identity: resource_identity(),
        capabilities: ResourceCapabilities::new([Capability::DeviceRevoke]),
        memory: AcceleratorMemory::NotReportable,
    });

    let renewal = handler.handle(&lease_request(), &peer.context());
    assert_eq!(
        renewal,
        AgentResponse::Error {
            code: ErrorCode::Internal
        },
        "a renewal must be refused once the resource no longer supports DeviceEnforce, \
         got {renewal:?}"
    );
}

/// Baseline (AC1, HORO-795): while the configured condition (a
/// remembered approval) continues to hold unchanged, ordinary renewal
/// keeps succeeding with no further friction — confirming the Bug A/B
/// fixes above did not regress the already-correct happy path.
/// `authz_session.rs`'s `ac1_one_session_admits_multiple_ordinary_lease_requests`
/// covers the same property for the session gate.
#[test]
fn renewal_succeeds_repeatedly_while_every_required_condition_still_holds() {
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_approval_store(temp_approval_store_path("renewal-happy-path")),
    );
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    handler.handle(
        &ClientRequest::Approve(ApproveRequest {
            resource: resource_identity(),
            action: Action::Compute,
            disposition: eltanin_core::approval::ApprovalDisposition::Remember,
        }),
        &peer.context(),
    );

    for _ in 0..3 {
        let response = handler.handle(&lease_request(), &peer.context());
        let AgentResponse::LeaseGranted { lease } = response else {
            panic!(
                "expected every renewal to be granted with no further friction, got {response:?}"
            );
        };
        handler.handle(
            &ClientRequest::ReleaseLease(ReleaseRequest {
                lease_id: lease.lease_id,
            }),
            &peer.context(),
        );
    }
}
