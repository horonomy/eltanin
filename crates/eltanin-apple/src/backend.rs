//! `ComputeBackend` implementation for the Apple Silicon adapter.

use eltanin_backend::contract::{BackendError, ComputeBackend};
use eltanin_core::resource::{
    AcceleratorMemory, Capability, ComputeRequest, EnforcementResult, ProtectedResource,
    ResourceCapabilities, ResourceIdentity, ResourceKind, ResourceVendor, SupportState,
};

#[cfg(target_os = "macos")]
use crate::device;
use crate::device::DeviceSnapshot;

/// The vendor tag this adapter reports itself under. Constructed here
/// (in this vendor-specific adapter crate), never as a helper added to
/// `eltanin-core` — see `docs/product/PRODUCT_CONSTITUTION.md`'s
/// vendor-neutral-core rule.
#[must_use]
fn vendor() -> ResourceVendor {
    ResourceVendor::new("apple")
}

/// Map one [`DeviceSnapshot`] onto a vendor-neutral [`ProtectedResource`],
/// per the capability honesty table in this crate's `lib.rs` docs.
///
/// Deliberately `pub` and unconditional (not `cfg`-gated to `macos`):
/// this is what lets `tests/capability_mapping.rs` exercise the
/// capability/memory mapping as a pure function over synthetic
/// [`DeviceSnapshot`] values on every target, including this repo's
/// hardware-free Linux CI, with no real Metal device required. On a
/// non-macOS build this function is simply never called from
/// [`AppleBackend`] (see its `discover`/`observe`, which are `cfg`-gated
/// to `macos`) — being `pub` keeps it live rather than triggering
/// `dead_code` under `-D warnings`.
#[must_use]
pub fn snapshot_to_resource(snapshot: &DeviceSnapshot) -> ProtectedResource {
    let identity = ResourceIdentity {
        vendor: vendor(),
        kind: ResourceKind::gpu(),
        // The device's stable registry ID, not its human-readable name —
        // `name` is not guaranteed stable/unique on a multi-GPU host.
        local_id: snapshot.registry_id.to_string(),
    };

    let capabilities = ResourceCapabilities::from_states([
        (Capability::DiscoverResource, SupportState::Supported),
        (Capability::ObserveResource, SupportState::Partial),
        (Capability::ObserveWorkload, SupportState::Unsupported),
        (Capability::AttributeWorkload, SupportState::Unsupported),
        (Capability::Authorize, SupportState::Unsupported),
        (Capability::ControlledLaunch, SupportState::NotEvaluated),
        (Capability::DeviceEnforce, SupportState::Unsupported),
        (Capability::DeviceRevoke, SupportState::Unsupported),
        (Capability::Attest, SupportState::Unsupported),
    ]);

    // Reported truthfully, never fabricated: `hasUnifiedMemory() == true`
    // maps to `Unified` (no byte count required); `false` maps to
    // `NotReportable` — never synthesized as `Dedicated { total_bytes }`
    // from a working-set-recommendation API, which is not a real
    // dedicated-VRAM figure. See ADR 0006 and this crate's `lib.rs` docs.
    let memory = if snapshot.has_unified_memory {
        AcceleratorMemory::Unified
    } else {
        AcceleratorMemory::NotReportable
    };

    ProtectedResource {
        identity,
        capabilities,
        memory,
    }
}

/// The Apple Silicon `ComputeBackend` adapter (F-M1-010, HORO-1012).
///
/// Holds no Metal/`objc2` state — every method acquires what it needs
/// locally via `crate::device` and returns owned, plain-Rust values, so
/// this type is trivially `Send + Sync`. See this crate's `lib.rs` docs
/// for the full capability honesty table.
#[derive(Debug, Default, Clone, Copy)]
pub struct AppleBackend;

impl AppleBackend {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl ComputeBackend for AppleBackend {
    /// # Errors
    ///
    /// Returns [`BackendError::Unsupported`] on any non-macOS target — no
    /// Metal call is ever attempted there. Never returns an error on
    /// macOS: an empty `Ok(vec![])` means "no Metal devices found."
    fn discover(&self) -> Result<Vec<ProtectedResource>, BackendError> {
        #[cfg(target_os = "macos")]
        {
            Ok(device::snapshot_all()
                .iter()
                .map(snapshot_to_resource)
                .collect())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(BackendError::Unsupported {
                capability: Capability::DiscoverResource,
            })
        }
    }

    /// # Errors
    ///
    /// Returns [`BackendError::Unsupported`] on any non-macOS target.
    /// Returns [`BackendError::Unavailable`] on macOS if no currently
    /// discoverable device matches `resource`.
    fn observe(&self, resource: &ResourceIdentity) -> Result<ProtectedResource, BackendError> {
        #[cfg(target_os = "macos")]
        {
            device::snapshot_all()
                .iter()
                .map(snapshot_to_resource)
                .find(|candidate| &candidate.identity == resource)
                .ok_or_else(|| BackendError::Unavailable {
                    resource: resource.clone(),
                })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = resource;
            Err(BackendError::Unsupported {
                capability: Capability::ObserveResource,
            })
        }
    }

    /// Never claims device-level enforcement, on any target — this
    /// backend structurally lacks [`Capability::DeviceEnforce`] (see this
    /// crate's `lib.rs` docs). Not `cfg`-gated: no compilation path can
    /// ever produce [`EnforcementResult::Allowed`] here.
    ///
    /// # Errors
    ///
    /// Never returns `Err` — always `Ok(EnforcementResult::Unsupported)`.
    fn enforce(&self, _request: &ComputeRequest) -> Result<EnforcementResult, BackendError> {
        Ok(EnforcementResult::Unsupported {
            capability: Capability::DeviceEnforce,
        })
    }

    /// Never claims device-level revocation, on any target — this
    /// backend structurally lacks [`Capability::DeviceRevoke`]. Not
    /// `cfg`-gated, for the same reason as [`Self::enforce`].
    ///
    /// # Errors
    ///
    /// Never returns `Err` — always `Ok(EnforcementResult::Unsupported)`.
    fn revoke(&self, _resource: &ResourceIdentity) -> Result<EnforcementResult, BackendError> {
        Ok(EnforcementResult::Unsupported {
            capability: Capability::DeviceRevoke,
        })
    }
}
