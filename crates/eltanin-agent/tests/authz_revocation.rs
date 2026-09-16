//! Revocation-capability gate and honest release-outcome coverage
//! (F-M2-005, HORO-795).

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use eltanin_agent::authz::event::{AuthorizationEvent, AuthorizationOutcome, EventSink, NullSink};
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler, RevocationRequirement};
use eltanin_agent::handler::RequestHandler;
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::resource::{Action, Capability, EnforcementResult};
use eltanin_protocol::request::{ClientRequest, LeaseRequest, ReleaseRequest};
use eltanin_protocol::response::{AgentResponse, ErrorCode, ReleaseOutcome};
use support::authz::{
    allow_policy_for_uid, backend_with_resource, resource_identity, FixedClock, TestPeer,
};

/// Records every [`AuthorizationOutcome`] this handler produces, in
/// order — tests assert against these rather than the wire response
/// when they need internal fidelity. Mirrors `authz_delegation.rs`'s
/// identical fixture.
#[derive(Default)]
struct CapturingSink {
    outcomes: Mutex<Vec<AuthorizationOutcome>>,
}

impl EventSink for CapturingSink {
    fn record(&self, event: &AuthorizationEvent<'_>) {
        self.outcomes.lock().unwrap().push(event.outcome.clone());
    }
}

impl CapturingSink {
    fn last(&self) -> AuthorizationOutcome {
        self.outcomes
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("at least one outcome must have been recorded")
    }
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
fn revocation_required_refuses_a_grant_when_the_resource_lacks_device_revoke() {
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        backend,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_revocation_requirement(RevocationRequirement::Required),
    );
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let response = handler.handle(&lease_request(), &peer.context());

    assert_eq!(
        response,
        AgentResponse::Error {
            code: ErrorCode::Internal
        },
        "a resource lacking Capability::DeviceRevoke must never be leasable when \
         RevocationRequirement::Required is configured"
    );
}

#[test]
fn revocation_required_grants_normally_when_the_resource_supports_device_revoke() {
    let backend = backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]);
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        backend,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_revocation_requirement(RevocationRequirement::Required),
    );
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let response = handler.handle(&lease_request(), &peer.context());

    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "expected LeaseGranted when the resource does support Capability::DeviceRevoke, \
         got {response:?}"
    );
}

/// Blast-radius guard: `RevocationRequirement::NotRequired` is the
/// default, and a deployment/test harness that never heard of this gate
/// (every construction that does not call `with_revocation_requirement`)
/// must keep granting a lease for a resource that lacks
/// `Capability::DeviceRevoke`, exactly as before HORO-795.
#[test]
fn revocation_not_required_is_the_default_and_ignores_missing_device_revoke() {
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        backend,
        FixedClock::new(),
        Arc::new(NullSink),
        // No `with_revocation_requirement` call at all.
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let response = handler.handle(&lease_request(), &peer.context());

    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "the default configuration must remain byte-identical to pre-HORO-795 behavior, \
         got {response:?}"
    );
}

#[test]
fn a_backend_revoke_error_during_release_is_recorded_not_silently_discarded() {
    let backend = backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]);
    let sink = Arc::new(CapturingSink::default());
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        Arc::clone(&backend) as Arc<dyn eltanin_backend::contract::ComputeBackend>,
        FixedClock::new(),
        Arc::clone(&sink) as Arc<dyn EventSink>,
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let granted = handler.handle(&lease_request(), &peer.context());
    let lease_id = granted_lease_id(&granted);

    // Simulate the backend becoming unavailable between grant and
    // release — `revoke()` will fail with `BackendError::Unavailable`.
    backend.remove(&resource_identity());

    let response = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest { lease_id }),
        &peer.context(),
    );
    // The lease-state layer's own revocation is unconditional and
    // structural — it always succeeds regardless of what the backend
    // reports. Only the *backend*-layer outcome (checked below via the
    // internal-fidelity event) is allowed to be an honest `Error`.
    assert_eq!(
        response,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Released
        }
    );

    match sink.last() {
        AuthorizationOutcome::Released { backend, .. } => {
            assert!(
                matches!(backend, Some(EnforcementResult::Error { .. })),
                "a real backend.revoke() error must be recorded honestly instead of \
                 silently becoming None, got {backend:?}"
            );
        }
        other => panic!("expected Released outcome, got {other:?}"),
    }
}

/// Regression guard for the *other* existing `None`-shaped case: a
/// resource that structurally lacks `Capability::DeviceRevoke` still
/// correctly reports `Some(Unsupported)` (already correct before this
/// ticket) — only the real-`Err` arm needed fixing.
#[test]
fn a_backend_without_device_revoke_still_reports_unsupported_not_none() {
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        backend,
        FixedClock::new(),
        Arc::clone(&sink) as Arc<dyn EventSink>,
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
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

    match sink.last() {
        AuthorizationOutcome::Released { backend, .. } => {
            assert!(
                matches!(
                    backend,
                    Some(EnforcementResult::Unsupported {
                        capability: Capability::DeviceRevoke
                    })
                ),
                "expected Some(Unsupported) preserved unchanged, got {backend:?}"
            );
        }
        other => panic!("expected Released outcome, got {other:?}"),
    }
}
