//! `AppleBackend::enforce`/`revoke` must report `Unsupported` on every
//! target, unconditionally — not `cfg`-gated to non-macOS, and never
//! influenced by whether a real Metal device happens to be present. No
//! compilation path may ever produce `EnforcementResult::Allowed` from
//! this backend (F-M1-010, HORO-1012; ADR 0006's E2 definition).

use eltanin_apple::AppleBackend;
use eltanin_backend::contract::ComputeBackend;
use eltanin_core::resource::{
    Action, Capability, ComputeRequest, EnforcementResult, ResourceIdentity, ResourceKind,
    ResourceVendor,
};

fn apple_resource() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::new("apple"),
        kind: ResourceKind::gpu(),
        local_id: "0".to_string(),
    }
}

#[test]
fn enforce_always_reports_unsupported_device_enforce() {
    let backend = AppleBackend::new();
    let request = ComputeRequest {
        resource: apple_resource(),
        action: Action::Compute,
    };
    assert_eq!(
        backend.enforce(&request),
        Ok(EnforcementResult::Unsupported {
            capability: Capability::DeviceEnforce,
        })
    );
}

#[test]
fn revoke_always_reports_unsupported_device_revoke() {
    let backend = AppleBackend::new();
    assert_eq!(
        backend.revoke(&apple_resource()),
        Ok(EnforcementResult::Unsupported {
            capability: Capability::DeviceRevoke,
        })
    );
}
