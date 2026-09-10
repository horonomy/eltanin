//! Golden serialization fixtures for the resource domain.
//!
//! These fixtures are deterministic byte-for-byte JSON. A test failure
//! here means the wire shape changed — bump [`DOMAIN_SCHEMA_VERSION`] and
//! update the fixture deliberately, don't just fix the test to match.

use eltanin_core::envelope::{Versioned, DOMAIN_SCHEMA_VERSION};
use eltanin_core::resource::{
    Action, Capability, ComputeRequest, EnforcementResult, ProtectedResource, ResourceCapabilities,
    ResourceIdentity, ResourceKind, ResourceVendor,
};

fn sample_resource() -> ProtectedResource {
    ProtectedResource {
        identity: ResourceIdentity {
            vendor: ResourceVendor::Fake,
            kind: ResourceKind::Gpu,
            local_id: "fake-gpu-0".to_string(),
        },
        capabilities: ResourceCapabilities::new([
            Capability::Discover,
            Capability::Observe,
            Capability::Authorize,
            Capability::Enforce,
        ]),
    }
}

#[test]
fn protected_resource_golden_json() {
    let versioned = Versioned::current(sample_resource());
    let json = serde_json::to_string_pretty(&versioned).unwrap();
    let expected = r#"{
  "version": 1,
  "payload": {
    "identity": {
      "vendor": "fake",
      "kind": "gpu",
      "local_id": "fake-gpu-0"
    },
    "capabilities": {
      "supported": [
        "discover",
        "observe",
        "authorize",
        "enforce"
      ]
    }
  }
}"#;
    assert_eq!(json, expected);
}

#[test]
fn protected_resource_roundtrips_through_versioned_envelope() {
    let original = sample_resource();
    let versioned = Versioned::current(original.clone());
    let json = serde_json::to_string(&versioned).unwrap();
    let decoded: Versioned<ProtectedResource> = serde_json::from_str(&json).unwrap();
    let payload = decoded.into_current().expect("current version must decode");
    assert_eq!(payload, original);
}

#[test]
fn unsupported_schema_version_fails_explicitly() {
    let envelope = Versioned {
        version: DOMAIN_SCHEMA_VERSION + 1,
        payload: sample_resource(),
    };
    let err = envelope.into_current().unwrap_err();
    assert_eq!(err.found, DOMAIN_SCHEMA_VERSION + 1);
    assert_eq!(err.expected, DOMAIN_SCHEMA_VERSION);
}

#[test]
fn unknown_vendor_deserializes_explicitly_rather_than_failing_closed() {
    let json = r#"{"vendor":"amd","kind":"gpu","local_id":"x"}"#;
    let identity: ResourceIdentity = serde_json::from_str(json).unwrap();
    assert_eq!(identity.vendor, ResourceVendor::Unknown);
}

#[test]
fn capability_check_reflects_actual_support_not_assumption() {
    let caps = ResourceCapabilities::new([Capability::Discover, Capability::Observe]);
    assert!(caps.supports(Capability::Discover));
    assert!(!caps.supports(Capability::Enforce));
}

#[test]
fn enforcement_result_unsupported_is_distinct_from_allowed() {
    let downgraded = EnforcementResult::Unsupported {
        capability: Capability::Enforce,
    };
    let json = serde_json::to_string(&downgraded).unwrap();
    assert_eq!(json, r#"{"outcome":"unsupported","capability":"enforce"}"#);
    assert_ne!(downgraded, EnforcementResult::Allowed);
}

#[test]
fn unknown_action_deserializes_explicitly() {
    let request: ComputeRequest = serde_json::from_str(
        r#"{"resource":{"vendor":"fake","kind":"gpu","local_id":"x"},"action":"reboot"}"#,
    )
    .unwrap();
    assert_eq!(request.action, Action::Unknown);
}
