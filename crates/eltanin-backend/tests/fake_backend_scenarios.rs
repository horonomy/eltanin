//! Deterministic conformance scenarios for `FakeBackend` (HORO-827).
//! Each test name is one scenario named in HORO-827's scope.

use eltanin_backend::contract::{BackendError, ComputeBackend};
use eltanin_backend::fake::FakeBackend;
use eltanin_core::resource::{
    Action, Capability, ComputeRequest, EnforcementResult, ProtectedResource, ResourceCapabilities,
    ResourceIdentity, ResourceKind, ResourceVendor,
};

fn identity(id: &str) -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: id.into(),
    }
}

fn resource_with(id: &str, caps: impl IntoIterator<Item = Capability>) -> ProtectedResource {
    ProtectedResource {
        identity: identity(id),
        capabilities: ResourceCapabilities::new(caps),
    }
}

#[test]
fn resource_present_is_discoverable_and_observable() {
    let backend = FakeBackend::new();
    backend.insert(resource_with(
        "gpu-0",
        [Capability::DiscoverResource, Capability::ObserveResource],
    ));

    let discovered = backend.discover().unwrap();
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].identity, identity("gpu-0"));

    let observed = backend.observe(&identity("gpu-0")).unwrap();
    assert!(observed.capabilities.supports(Capability::ObserveResource));
}

#[test]
fn resource_absent_is_unavailable_not_a_silent_empty_success() {
    let backend = FakeBackend::new();
    let err = backend.observe(&identity("nonexistent")).unwrap_err();
    assert_eq!(
        err,
        BackendError::Unavailable {
            resource: identity("nonexistent")
        }
    );
}

#[test]
fn backend_lacking_enforce_capability_reports_unsupported_not_allowed() {
    let backend = FakeBackend::new();
    backend.insert(resource_with(
        "gpu-0",
        [Capability::DiscoverResource, Capability::ObserveResource],
    ));
    let request = ComputeRequest {
        resource: identity("gpu-0"),
        action: Action::Compute,
    };

    let result = backend.enforce(&request).unwrap();
    assert_eq!(
        result,
        EnforcementResult::Unsupported {
            capability: Capability::DeviceEnforce
        }
    );
}

#[test]
fn enforcement_succeeds_when_capability_present_and_no_override() {
    let backend = FakeBackend::new();
    backend.insert(resource_with(
        "gpu-0",
        [Capability::DiscoverResource, Capability::DeviceEnforce],
    ));
    let request = ComputeRequest {
        resource: identity("gpu-0"),
        action: Action::Compute,
    };

    let result = backend.enforce(&request).unwrap();
    assert_eq!(result, EnforcementResult::Allowed);
}

#[test]
fn unauthorized_request_reports_scripted_denial() {
    // Simulates a policy decision (F-M1-004, not yet implemented) that
    // already decided DENY before the backend was ever asked to enforce
    // — i.e. an unauthorized request reaching an otherwise-capable backend.
    let backend = FakeBackend::new();
    backend.insert(resource_with(
        "gpu-0",
        [Capability::DiscoverResource, Capability::DeviceEnforce],
    ));
    backend.script_enforcement(
        identity("gpu-0"),
        EnforcementResult::Denied {
            reason: "no valid authorization".into(),
        },
    );
    let request = ComputeRequest {
        resource: identity("gpu-0"),
        action: Action::Compute,
    };

    let result = backend.enforce(&request).unwrap();
    assert_eq!(
        result,
        EnforcementResult::Denied {
            reason: "no valid authorization".into()
        }
    );
}

#[test]
fn resource_disappears_mid_session() {
    let backend = FakeBackend::new();
    backend.insert(resource_with(
        "gpu-0",
        [Capability::DiscoverResource, Capability::DeviceEnforce],
    ));
    assert!(backend.observe(&identity("gpu-0")).is_ok());

    backend.remove(&identity("gpu-0"));

    let err = backend.observe(&identity("gpu-0")).unwrap_err();
    assert_eq!(
        err,
        BackendError::Unavailable {
            resource: identity("gpu-0")
        }
    );

    let request = ComputeRequest {
        resource: identity("gpu-0"),
        action: Action::Compute,
    };
    let err = backend.enforce(&request).unwrap_err();
    assert_eq!(
        err,
        BackendError::Unavailable {
            resource: identity("gpu-0")
        }
    );
}

#[test]
fn lease_expiry_scenario_via_scripted_denial() {
    // F-M1-005 (Compute Lease) doesn't exist yet; this scripts the
    // outcome a real lease-expiry check would produce, so downstream
    // Feature tests have a fixture to build on now. Uses a distinct
    // resource from unauthorized_request_reports_scripted_denial so a
    // future EnforcementResult::Denied refinement (e.g. a structured
    // reason code instead of a free-text string) can tell them apart.
    let backend = FakeBackend::new();
    backend.insert(resource_with(
        "gpu-1",
        [Capability::DiscoverResource, Capability::DeviceEnforce],
    ));
    backend.script_enforcement(
        identity("gpu-1"),
        EnforcementResult::Denied {
            reason: "lease expired".into(),
        },
    );

    let request = ComputeRequest {
        resource: identity("gpu-1"),
        action: Action::Compute,
    };
    let result = backend.enforce(&request).unwrap();
    assert_eq!(
        result,
        EnforcementResult::Denied {
            reason: "lease expired".into()
        }
    );
}

#[test]
fn scripted_allowed_cannot_mask_a_capability_downgrade() {
    // A script must never be able to make enforce() report Allowed for a
    // resource that structurally lacks Capability::DeviceEnforce — capability
    // is checked before any scripted override is consulted.
    let backend = FakeBackend::new();
    backend.insert(resource_with("gpu-0", [Capability::DiscoverResource]));
    backend.script_enforcement(identity("gpu-0"), EnforcementResult::Allowed);

    let request = ComputeRequest {
        resource: identity("gpu-0"),
        action: Action::Compute,
    };
    let result = backend.enforce(&request).unwrap();
    assert_eq!(
        result,
        EnforcementResult::Unsupported {
            capability: Capability::DeviceEnforce
        }
    );
}

#[test]
fn revoke_without_capability_is_explicit_unsupported() {
    let backend = FakeBackend::new();
    backend.insert(resource_with(
        "gpu-0",
        [Capability::DiscoverResource, Capability::DeviceEnforce],
    ));

    let result = backend.revoke(&identity("gpu-0")).unwrap();
    assert_eq!(
        result,
        EnforcementResult::Unsupported {
            capability: Capability::DeviceRevoke
        }
    );
}

#[test]
fn revoke_with_capability_succeeds() {
    let backend = FakeBackend::new();
    backend.insert(resource_with(
        "gpu-0",
        [
            Capability::DiscoverResource,
            Capability::DeviceEnforce,
            Capability::DeviceRevoke,
        ],
    ));

    let result = backend.revoke(&identity("gpu-0")).unwrap();
    assert_eq!(result, EnforcementResult::Allowed);
}

#[test]
fn scenarios_are_deterministic_across_repeated_runs() {
    // Same script, called twice, must produce the same result — no
    // hidden randomness or ordering dependency.
    for _ in 0..3 {
        let backend = FakeBackend::new();
        backend.insert(resource_with(
            "gpu-0",
            [Capability::DiscoverResource, Capability::DeviceEnforce],
        ));
        let request = ComputeRequest {
            resource: identity("gpu-0"),
            action: Action::Compute,
        };
        assert_eq!(
            backend.enforce(&request).unwrap(),
            EnforcementResult::Allowed
        );
    }
}
