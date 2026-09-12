//! Behavioral tests for the `ComputeBackend` contract and `BackendError`.

use eltanin_backend::contract::{BackendError, ComputeBackend};
use eltanin_core::resource::{
    Action, Capability, ComputeRequest, EnforcementResult, ProtectedResource, ResourceCapabilities,
    ResourceIdentity, ResourceKind, ResourceVendor,
};

/// A minimal backend that lacks `Capability::DeviceEnforce`, used to verify a
/// capability downgrade surfaces as `Unsupported`, never as `Allowed`.
struct NoEnforceBackend;

impl ComputeBackend for NoEnforceBackend {
    fn discover(&self) -> Result<Vec<ProtectedResource>, BackendError> {
        Ok(vec![])
    }

    fn observe(&self, resource: &ResourceIdentity) -> Result<ProtectedResource, BackendError> {
        Ok(ProtectedResource {
            identity: resource.clone(),
            capabilities: ResourceCapabilities::new([Capability::DiscoverResource, Capability::ObserveResource]),
        })
    }

    fn enforce(&self, _request: &ComputeRequest) -> Result<EnforcementResult, BackendError> {
        Ok(EnforcementResult::Unsupported {
            capability: Capability::DeviceEnforce,
        })
    }

    fn revoke(&self, _resource: &ResourceIdentity) -> Result<EnforcementResult, BackendError> {
        Err(BackendError::Unsupported {
            capability: Capability::DeviceRevoke,
        })
    }
}

fn sample_identity() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "0".into(),
    }
}

#[test]
fn capability_downgrade_reports_unsupported_not_allowed() {
    let backend = NoEnforceBackend;
    let request = ComputeRequest {
        resource: sample_identity(),
        action: Action::Compute,
    };
    let result = backend
        .enforce(&request)
        .expect("enforce call itself succeeds");
    assert_eq!(
        result,
        EnforcementResult::Unsupported {
            capability: Capability::DeviceEnforce
        }
    );
    assert_ne!(result, EnforcementResult::Allowed);
}

#[test]
fn revoke_without_capability_is_a_typed_unsupported_error() {
    let backend = NoEnforceBackend;
    let err = backend.revoke(&sample_identity()).unwrap_err();
    assert_eq!(
        err,
        BackendError::Unsupported {
            capability: Capability::DeviceRevoke
        }
    );
}

#[test]
fn backend_error_variants_serialize_with_distinct_tags() {
    let cases: &[(BackendError, &str)] = &[
        (
            BackendError::Unsupported {
                capability: Capability::DeviceEnforce,
            },
            r#"{"kind":"unsupported","capability":"enforce"}"#,
        ),
        (
            BackendError::PermissionDenied,
            r#"{"kind":"permission_denied"}"#,
        ),
        (
            BackendError::Transient {
                message: "retry me".into(),
            },
            r#"{"kind":"transient","message":"retry me"}"#,
        ),
        (
            BackendError::Invariant {
                message: "impossible state".into(),
            },
            r#"{"kind":"invariant","message":"impossible state"}"#,
        ),
    ];
    for (error, expected_json) in cases {
        let json = serde_json::to_string(error).unwrap();
        assert_eq!(&json, expected_json);
    }
}

#[test]
fn unavailable_error_carries_the_specific_resource() {
    let identity = sample_identity();
    let err = BackendError::Unavailable {
        resource: identity.clone(),
    };
    if let BackendError::Unavailable { resource } = err {
        assert_eq!(resource, identity);
    } else {
        panic!("expected Unavailable variant");
    }
}
