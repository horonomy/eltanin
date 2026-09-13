//! Golden serialization fixtures for the resource domain.
//!
//! These fixtures are deterministic byte-for-byte JSON. A test failure
//! here means the wire shape changed — update the fixture deliberately,
//! don't just fix the test to match. This does NOT automatically mean
//! bumping [`DOMAIN_SCHEMA_VERSION`]: see
//! `docs/adr/0006-cross-accelerator-capability-and-memory-model.md` for
//! why the HORO-1011 resource-shape change deliberately did not bump it
//! (that constant is shared with the IPC framing and user-published
//! policy-document formats, neither of which this change touches).

use eltanin_core::envelope::{Versioned, DOMAIN_SCHEMA_VERSION};
use eltanin_core::resource::{
    AcceleratorMemory, Action, Capability, ComputeRequest, EnforcementResult, ProtectedResource,
    ResourceCapabilities, ResourceIdentity, ResourceKind, ResourceVendor,
};

fn sample_resource() -> ProtectedResource {
    ProtectedResource {
        identity: ResourceIdentity {
            vendor: ResourceVendor::fake(),
            kind: ResourceKind::gpu(),
            local_id: "fake-gpu-0".to_string(),
        },
        capabilities: ResourceCapabilities::new([
            Capability::DiscoverResource,
            Capability::ObserveResource,
            Capability::Authorize,
            Capability::DeviceEnforce,
        ]),
        memory: AcceleratorMemory::NotReportable,
    }
}

#[test]
fn protected_resource_golden_json() {
    let versioned = Versioned::current(sample_resource());
    let json = serde_json::to_string_pretty(&versioned).unwrap();
    let expected = r#"{
  "version": 3,
  "payload": {
    "identity": {
      "vendor": "fake",
      "kind": "gpu",
      "local_id": "fake-gpu-0"
    },
    "capabilities": {
      "support": {
        "discover_resource": "supported",
        "observe_resource": "supported",
        "authorize": "supported",
        "device_enforce": "supported"
      }
    },
    "memory": {
      "model": "not_reportable"
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
fn arbitrary_vendor_tag_round_trips_without_data_loss() {
    // eltanin-core has no closed vendor enum, so a vendor it has never
    // heard of (this crate must never name a real vendor — see the
    // module docs) decodes as-is rather than collapsing into a lossy
    // "unknown" placeholder. This is what makes audit evidence (F-M1-009)
    // able to actually preserve what was observed.
    let json = r#"{"vendor":"some-future-vendor","kind":"tpu","local_id":"x"}"#;
    let identity: ResourceIdentity = serde_json::from_str(json).unwrap();
    assert_eq!(identity.vendor.as_str(), "some-future-vendor");
    assert_eq!(identity.kind.as_str(), "tpu");
    // Round-trip must reproduce the exact tag, not a placeholder.
    let reencoded = serde_json::to_string(&identity).unwrap();
    let redecoded: ResourceIdentity = serde_json::from_str(&reencoded).unwrap();
    assert_eq!(redecoded, identity);
}

#[test]
fn capability_check_reflects_actual_support_not_assumption() {
    let caps =
        ResourceCapabilities::new([Capability::DiscoverResource, Capability::ObserveResource]);
    assert!(caps.supports(Capability::DiscoverResource));
    assert!(!caps.supports(Capability::DeviceEnforce));
}

#[test]
fn an_unrecognized_support_state_string_fails_decode_explicitly() {
    // No #[serde(other)] on SupportState: an unrecognized value must be a
    // hard decode error, never silently collapsed into NotEvaluated or any
    // other state — a typo or a future variant this build doesn't know
    // about must not be misread as a known, weaker guarantee.
    let json = r#"{"identity":{"vendor":"fake","kind":"gpu","local_id":"x"},
        "capabilities":{"support":{"device_enforce":"probably"}}}"#;
    let result: Result<ProtectedResource, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn enforcement_result_unsupported_is_distinct_from_allowed() {
    let downgraded = EnforcementResult::Unsupported {
        capability: Capability::DeviceEnforce,
    };
    let json = serde_json::to_string(&downgraded).unwrap();
    assert_eq!(
        json,
        r#"{"outcome":"unsupported","capability":"device_enforce"}"#
    );
    assert_ne!(downgraded, EnforcementResult::Allowed);
}

#[test]
fn unified_memory_resource_round_trips_with_no_fabricated_byte_count() {
    let mut resource = sample_resource();
    resource.memory = AcceleratorMemory::Unified;
    let json = serde_json::to_string(&resource).unwrap();
    // A shared-memory backend must never be forced to invent a dedicated
    // byte count — the wire shape carries only the tag, nothing else.
    assert_eq!(json.matches("total_bytes").count(), 0);
    let decoded: ProtectedResource = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, resource);
}

#[test]
fn dedicated_memory_resource_round_trips_with_its_reported_byte_count() {
    let mut resource = sample_resource();
    resource.memory = AcceleratorMemory::Dedicated {
        total_bytes: 24 * 1024 * 1024 * 1024,
    };
    let json = serde_json::to_string(&resource).unwrap();
    assert!(json.contains("\"total_bytes\":25769803776"));
    let decoded: ProtectedResource = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, resource);
}

#[test]
fn an_omitted_memory_field_decodes_as_not_reportable() {
    // Pre-HORO-1011 shape: no "memory" key at all. #[serde(default)] must
    // make this additive, decoding to NotReportable, never a hard error.
    let json = r#"{"identity":{"vendor":"fake","kind":"gpu","local_id":"x"},
        "capabilities":{"support":{}}}"#;
    let decoded: ProtectedResource = serde_json::from_str(json).unwrap();
    assert_eq!(decoded.memory, AcceleratorMemory::NotReportable);
}

#[test]
fn unknown_action_deserializes_explicitly() {
    let request: ComputeRequest = serde_json::from_str(
        r#"{"resource":{"vendor":"fake","kind":"gpu","local_id":"x"},"action":"reboot"}"#,
    )
    .unwrap();
    assert_eq!(request.action, Action::Unknown);
}
