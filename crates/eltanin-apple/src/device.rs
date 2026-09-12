//! Safe Metal device snapshotting.
//!
//! [`DeviceSnapshot`] is an owned, plain-Rust value: every function here
//! acquires whatever Metal/`objc2` objects it needs locally, reads their
//! publicly reported attributes, and returns only [`DeviceSnapshot`]
//! values — never a Metal/`objc2` object itself. This is what lets
//! `crate::backend::AppleBackend` hold no Metal state at all and be
//! trivially `Send + Sync` without needing to reason about whether the
//! underlying Objective-C types are.
//!
//! [`snapshot_all`] uses no `unsafe` code: every `objc2-metal` call it
//! makes (`MTLCopyAllDevices`, `MTLDevice::name`/`registryID`/
//! `hasUnifiedMemory`) is a safe function on the pinned `objc2-metal`
//! version — see this crate's `Cargo.toml` and HORO-1012's design
//! verification against current docs.rs.

/// An owned, plain-Rust snapshot of one Metal device's publicly reported
/// static attributes, taken at one point in time.
///
/// Deliberately unconditional (not `cfg`-gated) and with public fields:
/// the hardware-free capability/memory-mapping tests
/// (`tests/capability_mapping.rs`) construct synthetic values of this
/// type directly, with no real Metal device or macOS build required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSnapshot {
    /// The device's `registryID` — a stable-enough local identifier for
    /// this device on this host across process runs, unlike its
    /// human-readable `name`, which is not guaranteed unique on a
    /// multi-GPU host.
    pub registry_id: u64,
    /// The device's human-readable name (e.g. "Apple M3 Max"), for
    /// display/observability only — never used as an identity key.
    pub name: String,
    /// Whether this device reports a unified (shared-with-host) memory
    /// architecture.
    pub has_unified_memory: bool,
}

/// Enumerate every Metal device currently present on this host, as owned
/// snapshots. An empty result means "no Metal devices found," which is a
/// legitimate outcome, not a failure — `MTLCopyAllDevices` never reports
/// an error, only an array that may be empty.
///
/// On any `target_os` other than `macos`, this returns an empty `Vec`
/// without making any Metal call at all (there is no `objc2-metal`
/// dependency to call on such a build — see this crate's `Cargo.toml`).
/// Callers needing an explicit "this platform has no Metal support"
/// signal (as opposed to "this platform's Metal has zero devices") should
/// use `crate::backend::AppleBackend`, which reports that distinction via
/// `BackendError::Unsupported` on non-macOS rather than through this
/// function's return value.
#[must_use]
pub fn snapshot_all() -> Vec<DeviceSnapshot> {
    imp::snapshot_all()
}

#[cfg(target_os = "macos")]
mod imp {
    use super::DeviceSnapshot;
    use objc2_metal::{MTLCopyAllDevices, MTLDevice};

    pub(super) fn snapshot_all() -> Vec<DeviceSnapshot> {
        // No `unsafe` code here: MTLCopyAllDevices and every MTLDevice
        // accessor used below are safe functions on the objc2-metal
        // version pinned in this crate's Cargo.toml.
        let devices = MTLCopyAllDevices();
        devices
            .iter()
            .map(|device| DeviceSnapshot {
                registry_id: device.registryID(),
                name: device.name().to_string(),
                has_unified_memory: device.hasUnifiedMemory(),
            })
            .collect()
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::DeviceSnapshot;

    pub(super) fn snapshot_all() -> Vec<DeviceSnapshot> {
        Vec::new()
    }
}
