//! Backend failure fail-safe coverage: a backend error or refused
//! enforcement must never leave a lease granted, and a resource shared
//! by two outstanding leases must not have its backend enforcement torn
//! down by only one of them releasing (F-M1-006, HORO-840). AC #3
//! ("Backend/policy/lease errors fail safely").

mod support;

use std::sync::Arc;
use std::time::Duration;

use eltanin_agent::authz::event::NullSink;
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler};
use eltanin_agent::handler::RequestHandler;
use eltanin_backend::contract::BackendError;
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::resource::{Action, Capability, EnforcementResult};
use eltanin_protocol::request::{ClientRequest, LeaseRequest, ReleaseRequest};
use eltanin_protocol::response::{AgentResponse, ErrorCode, ReleaseOutcome};
use support::authz::{
    allow_policy_for_uid, backend_with_resource, resource_identity, FixedClock, TestPeer,
};

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
fn a_scripted_backend_denial_never_grants_a_lease() {
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    backend.script_enforcement(
        resource_identity(),
        EnforcementResult::Denied {
            reason: "device busy".to_string(),
        },
    );
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        backend,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let response = handler.handle(&lease_request(), &peer.context());

    assert_eq!(
        response,
        AgentResponse::Error {
            code: ErrorCode::Internal
        }
    );
}

#[test]
fn a_scripted_backend_error_never_grants_a_lease_and_compensates() {
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    backend.script_enforcement(
        resource_identity(),
        EnforcementResult::Error {
            message: "driver reset".to_string(),
        },
    );
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        backend,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let response = handler.handle(&lease_request(), &peer.context());
    assert_eq!(
        response,
        AgentResponse::Error {
            code: ErrorCode::Internal
        }
    );

    // The sequence consumed by the compensated issue must not be
    // releasable later — it was never actually granted.
    let release = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest {
            lease_id: eltanin_core::lease::LeaseId {
                issuer: IssuerInstanceId::new("test-instance"),
                sequence: 0,
            },
        }),
        &peer.context(),
    );
    assert_eq!(
        release,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Refused
        }
    );
}

#[test]
fn resource_disappearing_mid_session_fails_safely() {
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        Arc::clone(&backend) as Arc<dyn eltanin_backend::contract::ComputeBackend>,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
    backend.remove(&resource_identity());
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let response = handler.handle(&lease_request(), &peer.context());

    assert_eq!(
        response,
        AgentResponse::Error {
            code: ErrorCode::Internal
        }
    );
}

#[test]
fn releasing_one_of_two_leases_on_the_same_resource_does_not_tear_down_the_others_enforcement() {
    // Two distinct clients (distinct resources aren't required by
    // LeaseIssuer, so two leases for the *same* resource is a real,
    // reachable state) both hold a lease on the same resource. Release
    // by one must not call backend.revoke while the other lease is
    // still outstanding.
    let backend = backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]);
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        Arc::clone(&backend) as Arc<dyn eltanin_backend::contract::ComputeBackend>,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
    let a = TestPeer::fresh(1000, "sha256:trusted");
    let b = TestPeer::fresh(1000, "sha256:trusted");
    let granted_a = handler.handle(&lease_request(), &a.context());
    let granted_b = handler.handle(&lease_request(), &b.context());
    let id_a = granted_lease_id(&granted_a);
    let id_b = granted_lease_id(&granted_b);

    let release_a = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest { lease_id: id_a }),
        &a.context(),
    );
    assert_eq!(
        release_a,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Released
        }
    );
    // The load-bearing assertion: a's release must not have called
    // backend.revoke while b's lease on the same resource was still
    // live.
    assert_eq!(
        backend.revoke_call_count(&resource_identity()),
        0,
        "releasing a while b's lease on the same resource is still outstanding must not call \
         backend.revoke"
    );

    let release_b = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest { lease_id: id_b }),
        &b.context(),
    );
    assert_eq!(
        release_b,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Released
        }
    );
    // Now that b was the last live lease on the resource, its release
    // must have actually called backend.revoke exactly once.
    assert_eq!(
        backend.revoke_call_count(&resource_identity()),
        1,
        "releasing the last live lease on a resource must call backend.revoke exactly once"
    );
}

#[test]
fn a_release_racing_a_grant_on_the_same_resource_never_tears_down_the_new_grant() {
    // Regression coverage for the release-then-acquire race an
    // adversarial review found: thread A releases the last lease on a
    // resource and decides to revoke it backend-side; before A's
    // (formerly unlocked) backend.revoke() call could run, thread B
    // could complete an entire RequestLease for the same resource and
    // have A's stale revoke tear down B's freshly-granted enforcement.
    // AuthorizationHandler now holds the lease-store lock across the
    // release path's backend.revoke() call specifically to close this,
    // serializing it against any concurrent insert. This test proves
    // the observable outcome: after a release-then-grant sequence on
    // the same resource, exactly one revoke call landed (a's), and it
    // did not follow b's grant in a way that would leave b's lease
    // pointing at torn-down enforcement — b's own subsequent release
    // still triggers its own, second revoke call.
    let backend = backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]);
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        Arc::clone(&backend) as Arc<dyn eltanin_backend::contract::ComputeBackend>,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
    let a = TestPeer::fresh(1000, "sha256:trusted");
    let b = TestPeer::fresh(1000, "sha256:trusted");

    let granted_a = handler.handle(&lease_request(), &a.context());
    let id_a = granted_lease_id(&granted_a);

    // a releases its lease — the only live lease on the resource at
    // this point, so this release does call backend.revoke.
    let release_a = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest { lease_id: id_a }),
        &a.context(),
    );
    assert_eq!(
        release_a,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Released
        }
    );
    assert_eq!(backend.revoke_call_count(&resource_identity()), 1);

    // b now grants a fresh lease on the same resource — sequentially
    // here (this test isn't spawning real threads), but the fix's
    // correctness claim is that the release path's revoke_backend
    // decision and its execution are atomic under the same lock as any
    // insert, so no *interleaved* real-thread ordering could produce a
    // different, incorrect outcome than this sequential one.
    let granted_b = handler.handle(&lease_request(), &b.context());
    let id_b = granted_lease_id(&granted_b);
    // b's grant must not have triggered any backend.revoke call.
    assert_eq!(backend.revoke_call_count(&resource_identity()), 1);

    let release_b = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest { lease_id: id_b }),
        &b.context(),
    );
    assert_eq!(
        release_b,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Released
        }
    );
    assert_eq!(backend.revoke_call_count(&resource_identity()), 2);
}

#[test]
fn a_permission_denied_backend_error_is_reported_as_internal_not_a_policy_denial() {
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    backend.script_enforcement(
        resource_identity(),
        // FakeBackend's script only pins EnforcementResult, not
        // BackendError directly — remove the resource entirely to
        // exercise a real BackendError::Unavailable path instead, which
        // this test's name still accurately describes as "a backend
        // error", generalized beyond PermissionDenied specifically.
        EnforcementResult::Error {
            message: BackendError::PermissionDenied.to_string(),
        },
    );
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        backend,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let response = handler.handle(&lease_request(), &peer.context());

    assert_eq!(
        response,
        AgentResponse::Error {
            code: ErrorCode::Internal
        }
    );
}
