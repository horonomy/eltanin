//! Capability/memory mapping coverage (F-M1-010, HORO-1012, ADR 0007) —
//! `eltanin_apple::backend::snapshot_to_resource` as a pure function over
//! synthetic `DeviceSnapshot` values. No real Metal device or macOS
//! build is required: `DeviceSnapshot` and `snapshot_to_resource` are
//! deliberately unconditional, so this runs on this repo's hardware-free
//! `ubuntu-latest` CI.

use eltanin_apple::backend::snapshot_to_resource;
use eltanin_apple::device::DeviceSnapshot;
use eltanin_core::resource::{
    AcceleratorMemory, Capability, ResourceKind, ResourceVendor, SupportState,
};

fn unified_snapshot() -> DeviceSnapshot {
    DeviceSnapshot {
        registry_id: 4_294_967_296,
        name: "Apple M3 Max".to_string(),
        has_unified_memory: true,
    }
}

#[test]
fn identity_uses_the_registry_id_as_local_id_not_the_name() {
    let resource = snapshot_to_resource(&unified_snapshot());
    assert_eq!(resource.identity.vendor, ResourceVendor::new("apple"));
    assert_eq!(resource.identity.kind, ResourceKind::gpu());
    assert_eq!(resource.identity.local_id, "4294967296");
}

#[test]
fn unified_memory_flag_maps_to_accelerator_memory_unified() {
    let resource = snapshot_to_resource(&unified_snapshot());
    assert_eq!(resource.memory, AcceleratorMemory::Unified);
}

#[test]
fn absent_unified_memory_flag_maps_to_not_reportable_never_dedicated() {
    let snapshot = DeviceSnapshot {
        has_unified_memory: false,
        ..unified_snapshot()
    };
    let resource = snapshot_to_resource(&snapshot);
    assert_eq!(resource.memory, AcceleratorMemory::NotReportable);
}

#[test]
fn discover_resource_is_the_only_fully_supported_capability() {
    let resource = snapshot_to_resource(&unified_snapshot());
    assert_eq!(
        resource.capabilities.state_of(Capability::DiscoverResource),
        SupportState::Supported
    );
    // No other capability may be reported as fully `Supported` — this
    // backend never claims more than genuine discovery.
    for capability in [
        Capability::ObserveResource,
        Capability::ObserveWorkload,
        Capability::AttributeWorkload,
        Capability::Authorize,
        Capability::ControlledLaunch,
        Capability::DeviceEnforce,
        Capability::DeviceRevoke,
        Capability::Attest,
    ] {
        assert_ne!(
            resource.capabilities.state_of(capability),
            SupportState::Supported,
            "{capability:?} must not be reported as Supported"
        );
    }
}

#[test]
fn observe_resource_is_reported_as_partial_not_supported_or_unsupported() {
    let resource = snapshot_to_resource(&unified_snapshot());
    assert_eq!(
        resource.capabilities.state_of(Capability::ObserveResource),
        SupportState::Partial
    );
}

#[test]
fn controlled_launch_is_not_evaluated_not_unsupported() {
    // HORO-1013's scope, not this ticket's — `NotEvaluated`, not a
    // negative claim this backend has no basis to make yet.
    let resource = snapshot_to_resource(&unified_snapshot());
    assert_eq!(
        resource.capabilities.state_of(Capability::ControlledLaunch),
        SupportState::NotEvaluated
    );
}
