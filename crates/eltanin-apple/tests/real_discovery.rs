//! Real-hardware Apple Silicon accelerator discovery and capability-state
//! inspection (F-M1-010, HORO-1015).
//!
//! `tests/non_macos_fallback.rs` proves the `Unsupported` fallback on
//! every non-macOS target; `tests/capability_mapping.rs` proves the
//! capability/memory mapping as a pure function over synthetic
//! `DeviceSnapshot` values, on every target. Neither exercises
//! `AppleBackend::discover()` for real against a genuine Metal device —
//! that gap is this file's whole purpose: HORO-1015's Track B journey
//! (steps 3-4, "discover Apple accelerator" / "inspect capability
//! state") needs real evidence that `discover()` returns a real,
//! honestly-mapped `ProtectedResource` on physical Apple Silicon, not
//! just a passing type-level contract.
//!
//! Unlike `metal_compute_probe.rs`, this file dispatches no Metal
//! *compute* kernel at all — `MTLCopyAllDevices` and its accessors are
//! cheap enumeration calls, not workload execution — so it is not
//! `#[ignore]`d. It is still `#![cfg(target_os = "macos")]` (nothing to
//! discover on a non-macOS build) and, like every other test in this
//! crate, never runs on this repository's CI: `.github/workflows/ci.yml`'s
//! `test-macos` job `--exclude`s `eltanin-apple` entirely (see that
//! file's comment) so that no real-hardware-only test in this crate can
//! ever be silently mis-run against a virtualized macOS CI runner. Run
//! for real by hand: `cargo test -p eltanin-apple --test real_discovery`.
#![cfg(target_os = "macos")]

use eltanin_apple::backend::AppleBackend;
use eltanin_backend::contract::ComputeBackend;
use eltanin_core::resource::{AcceleratorMemory, Capability, ResourceVendor, SupportState};

#[test]
fn discover_finds_at_least_one_real_apple_gpu() {
    let backend = AppleBackend::new();
    let resources = backend
        .discover()
        .expect("AppleBackend::discover() must succeed on real Apple Silicon hardware");
    assert!(
        !resources.is_empty(),
        "expected at least one real Metal device to be discovered on physical Apple Silicon \
         hardware, found none"
    );
    // Printed (not asserted on) so a `--nocapture` run doubles as a
    // human-readable capability-report evidence artifact
    // (HORO-1015's Jira "capability report" evidence ask) — the actual
    // AC is verified by the typed assertions below and in
    // `discovered_resource_capability_state_matches_the_honesty_table`,
    // not by this text.
    for resource in &resources {
        println!("capability report: {resource:#?}");
    }
    for resource in &resources {
        assert_eq!(
            resource.identity.vendor,
            ResourceVendor::new("apple"),
            "a real discovered resource must be vendor-tagged \"apple\""
        );
        assert!(
            !resource.identity.local_id.is_empty(),
            "a real discovered resource must have a non-empty local_id (registryID)"
        );
    }
}

/// The capability-state inspection HORO-1015's Track B journey names
/// explicitly: every real discovered resource's capability map must
/// match the honesty table `snapshot_to_resource` (already unit-tested
/// against synthetic data in `capability_mapping.rs`) declares — proven
/// here against the real value `discover()` actually returns, not a
/// constructed stand-in.
#[test]
fn discovered_resource_capability_state_matches_the_honesty_table() {
    let backend = AppleBackend::new();
    let resources = backend
        .discover()
        .expect("AppleBackend::discover() must succeed on real Apple Silicon hardware");
    assert!(
        !resources.is_empty(),
        "precondition for this test: at least one real Metal device must be discovered"
    );

    for resource in &resources {
        assert_eq!(
            resource.capabilities.state_of(Capability::DiscoverResource),
            SupportState::Supported,
            "a really-discovered Apple resource must report DiscoverResource as Supported"
        );
        // HORO-1015 AC: capability state must explicitly report device
        // enforcement/revoke as unsupported/not proven — checked here
        // against the real discovered resource, not a synthetic one.
        assert_eq!(
            resource.capabilities.state_of(Capability::DeviceEnforce),
            SupportState::Unsupported,
            "a real Apple Silicon resource must never report DeviceEnforce as anything but \
             Unsupported — device-level enforcement is not proven on this platform"
        );
        assert_eq!(
            resource.capabilities.state_of(Capability::DeviceRevoke),
            SupportState::Unsupported,
            "a real Apple Silicon resource must never report DeviceRevoke as anything but \
             Unsupported — device-level revoke is not proven on this platform"
        );
        assert!(
            matches!(
                resource.memory,
                AcceleratorMemory::Unified | AcceleratorMemory::NotReportable
            ),
            "a real Apple Silicon GPU must never be reported as AcceleratorMemory::Dedicated — \
             it is unified or not-reportable, never a fabricated dedicated-VRAM figure, got: \
             {:?}",
            resource.memory,
        );
    }
}
