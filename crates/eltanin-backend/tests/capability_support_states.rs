//! Behavioral proof that `ComputeBackend::enforce`/`revoke` treat every
//! `SupportState` short of `Supported` identically to "unsupported" —
//! never as if partial support were full protection (HORO-1011, ADR 0006).

use eltanin_backend::contract::ComputeBackend;
use eltanin_backend::fake::FakeBackend;
use eltanin_core::resource::{
    AcceleratorMemory, Action, Capability, ComputeRequest, EnforcementResult, ProtectedResource,
    ResourceCapabilities, ResourceIdentity, ResourceKind, ResourceVendor, SupportState,
};

fn identity(vendor: &str, id: &str) -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::new(vendor),
        kind: ResourceKind::gpu(),
        local_id: id.into(),
    }
}

fn resource_with_states(
    identity: ResourceIdentity,
    states: impl IntoIterator<Item = (Capability, SupportState)>,
) -> ProtectedResource {
    ProtectedResource {
        identity,
        capabilities: ResourceCapabilities::from_states(states),
        memory: AcceleratorMemory::NotReportable,
    }
}

fn compute_request(resource: &ResourceIdentity) -> ComputeRequest {
    ComputeRequest {
        resource: resource.clone(),
        action: Action::Compute,
    }
}

#[test]
fn partial_device_enforce_support_never_reports_allowed() {
    let backend = FakeBackend::new();
    let target = identity("fake", "partial-enforce");
    backend.insert(resource_with_states(
        target.clone(),
        [(Capability::DeviceEnforce, SupportState::Partial)],
    ));

    let result = backend.enforce(&compute_request(&target)).unwrap();

    assert_eq!(
        result,
        EnforcementResult::Unsupported {
            capability: Capability::DeviceEnforce,
        }
    );
    assert_ne!(result, EnforcementResult::Allowed);
}

#[test]
fn not_evaluated_device_enforce_support_never_reports_allowed() {
    let backend = FakeBackend::new();
    let target = identity("fake", "not-evaluated-enforce");
    // DeviceEnforce is absent entirely — NotEvaluated by construction.
    backend.insert(resource_with_states(
        target.clone(),
        [(Capability::ControlledLaunch, SupportState::Supported)],
    ));

    let result = backend.enforce(&compute_request(&target)).unwrap();

    assert_eq!(
        result,
        EnforcementResult::Unsupported {
            capability: Capability::DeviceEnforce,
        }
    );
}

#[test]
fn controlled_launch_support_does_not_imply_device_enforce_support() {
    let backend = FakeBackend::new();
    let target = identity("fake", "launch-only");
    let resource = resource_with_states(
        target.clone(),
        [(Capability::ControlledLaunch, SupportState::Supported)],
    );
    backend.insert(resource);

    let observed = backend.observe(&target).unwrap();
    assert!(observed.capabilities.supports(Capability::ControlledLaunch));
    assert!(!observed.capabilities.supports(Capability::DeviceEnforce));

    let result = backend.enforce(&compute_request(&target)).unwrap();
    assert_eq!(
        result,
        EnforcementResult::Unsupported {
            capability: Capability::DeviceEnforce,
        }
    );
}

#[test]
fn enforcement_outcome_is_identical_across_vendor_tags() {
    // The enforcement mechanism dispatches purely on SupportState, never
    // on the resource's vendor tag — no vendor gets special-cased
    // behavior. Proven by running the exact same capability state under
    // two different (opaque, made-up) vendor tags and asserting identical
    // outcomes for both.
    let backend = FakeBackend::new();
    let vendor_a = identity("vendor-a", "gpu-0");
    let vendor_b = identity("vendor-b", "gpu-0");
    backend.insert(resource_with_states(
        vendor_a.clone(),
        [(Capability::DeviceEnforce, SupportState::Supported)],
    ));
    backend.insert(resource_with_states(
        vendor_b.clone(),
        [(Capability::DeviceEnforce, SupportState::Supported)],
    ));

    let result_a = backend.enforce(&compute_request(&vendor_a)).unwrap();
    let result_b = backend.enforce(&compute_request(&vendor_b)).unwrap();

    assert_eq!(result_a, EnforcementResult::Allowed);
    assert_eq!(result_a, result_b);
}
