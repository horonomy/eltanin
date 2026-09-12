//! Discovery/observation fallback coverage (F-M1-010, HORO-1012). Real
//! Metal device discovery only meaningfully validates on macOS; on any
//! other `target_os` (this repo's hardware-free `ubuntu-latest` CI), the
//! documented `BackendError::Unsupported` fallback is what's validated
//! instead — this test still compiles and passes on a macOS dev machine,
//! same pattern as `eltanin-linux/tests/peer_credential.rs`.

use eltanin_apple::AppleBackend;
#[cfg(not(target_os = "macos"))]
use eltanin_backend::contract::BackendError;
use eltanin_backend::contract::ComputeBackend;
#[cfg(not(target_os = "macos"))]
use eltanin_core::resource::{Capability, ResourceIdentity, ResourceKind, ResourceVendor};

#[cfg(not(target_os = "macos"))]
#[test]
fn discover_reports_unsupported_on_a_non_macos_target() {
    let backend = AppleBackend::new();
    assert_eq!(
        backend.discover(),
        Err(BackendError::Unsupported {
            capability: Capability::DiscoverResource,
        })
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn observe_reports_unsupported_on_a_non_macos_target() {
    let backend = AppleBackend::new();
    let resource = ResourceIdentity {
        vendor: ResourceVendor::new("apple"),
        kind: ResourceKind::gpu(),
        local_id: "0".to_string(),
    };
    assert_eq!(
        backend.observe(&resource),
        Err(BackendError::Unsupported {
            capability: Capability::ObserveResource,
        })
    );
}

#[cfg(target_os = "macos")]
#[test]
fn discover_succeeds_on_a_real_macos_host() {
    // On this repo's real target platform, discovery must not fail
    // structurally — a physical Apple Silicon host has at least one
    // Metal device (this repo's own hardware-validation runbook
    // convention: verify the real path, don't just assert the fallback).
    let backend = AppleBackend::new();
    let resources = backend
        .discover()
        .expect("discover must succeed on a real macOS host");
    assert!(
        !resources.is_empty(),
        "expected at least one Metal device on a real macOS host"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn observe_finds_a_resource_discover_just_reported() {
    let backend = AppleBackend::new();
    let discovered = backend.discover().expect("discover must succeed");
    let first = discovered
        .first()
        .expect("expected at least one discovered Metal device");
    let observed = backend
        .observe(&first.identity)
        .expect("observe must find a resource discover just reported");
    assert_eq!(observed.identity, first.identity);
}
