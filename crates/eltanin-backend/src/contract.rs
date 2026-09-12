//! Vendor-neutral backend capability contract (F-M1-001, HORO-826).
//!
//! `ComputeBackend` is the seam the Fake backend (HORO-827) and, later,
//! the real NVIDIA backend (F-M1-002) both implement — this crate never
//! names a real vendor (enforced by
//! `tests/architecture_no_vendor_leak.rs`, mirroring `eltanin-core`'s).
//!
//! This trait is a compatibility boundary, not a promise of a stable
//! dynamic Rust ABI: if the backend is ever externalized into a separate
//! process, the wire contract is `eltanin-protocol`'s versioned protocol,
//! not this trait's `dyn` vtable — see ADR 0002/0004.

use eltanin_core::resource::{
    Capability, ComputeRequest, EnforcementResult, ProtectedResource, ResourceIdentity,
};
use serde::{Deserialize, Serialize};

/// A typed backend-operation failure, distinct from [`EnforcementResult`]
/// (which describes the *outcome of an enforcement attempt*, not why the
/// attempt itself couldn't be made). Each variant is a different response
/// to a caller: retry, don't retry, this backend can never do this, or
/// something is wrong enough to stop trusting this backend's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum BackendError {
    /// The backend does not have `capability` at all — not "right now,"
    /// structurally. A caller must not retry; it must treat this as a
    /// capability downgrade and report it as such, never as enforcement
    /// having silently succeeded.
    #[error("backend does not support capability {capability:?}")]
    Unsupported { capability: Capability },

    /// The resource is not reachable right now (e.g. observed to have
    /// disappeared). May be transient at the resource level even though
    /// the backend itself is healthy — distinct from `Transient` because
    /// callers may want different retry/backoff policy for "this
    /// specific resource is gone" versus "the backend had a hiccup."
    #[error("resource {resource:?} is currently unavailable")]
    Unavailable { resource: ResourceIdentity },

    /// The calling context lacks OS/process permission to perform this
    /// backend operation. Not a policy/authorization decision — this is
    /// about the backend's own access to underlying hardware/OS state,
    /// evaluated before F-M1-004's policy is ever consulted.
    #[error("permission denied performing backend operation")]
    PermissionDenied,

    /// A retryable failure with no more specific classification.
    #[error("transient backend failure: {message}")]
    Transient { message: String },

    /// The backend observed a state it should be structurally impossible
    /// to observe (e.g. contradictory capability/resource data). Signals
    /// a bug, not a runtime condition a caller should retry around.
    #[error("backend invariant violated: {message}")]
    Invariant { message: String },
}

/// The vendor-neutral contract every compute backend implements.
///
/// Implementations: the deterministic Fake Compute Backend
/// (`crate::fake`, HORO-827) for CI/tests, and the real NVIDIA backend
/// (`crates/eltanin-nvidia`, F-M1-002) once that ticket starts. Both
/// target exactly this trait — no backend-specific method exists outside
/// it.
pub trait ComputeBackend: Send + Sync {
    /// Enumerate protected resources this backend currently knows about.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if discovery itself fails (e.g.
    /// `PermissionDenied`, `Transient`). An empty `Ok(vec![])` means "no
    /// resources found," which is different from a discovery failure.
    fn discover(&self) -> Result<Vec<ProtectedResource>, BackendError>;

    /// Look up one resource's current identity and capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Unavailable`] if `resource` is not
    /// currently observable, or another [`BackendError`] variant for
    /// other observation failures.
    fn observe(&self, resource: &ResourceIdentity) -> Result<ProtectedResource, BackendError>;

    /// Attempt to enforce (or verify enforcement of) `request`.
    ///
    /// This method does **not** decide authorization — that decision
    /// (F-M1-004) has already been made by the time this is called. It
    /// only reports whether the backend could carry out or verify the
    /// already-decided action. A backend lacking
    /// [`Capability::DeviceEnforce`] must return
    /// `Ok(EnforcementResult::Unsupported { .. })`, never
    /// `Ok(EnforcementResult::Allowed)` — see [`EnforcementResult`]'s own
    /// docs on why capability downgrade must never masquerade as
    /// enforcement.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] if the attempt itself could not be made
    /// (e.g. the backend errored trying to act, as opposed to acting and
    /// reporting a `Denied`/`Unsupported` outcome).
    fn enforce(&self, request: &ComputeRequest) -> Result<EnforcementResult, BackendError>;

    /// Revoke previously granted access to `resource`, if this backend
    /// has [`Capability::DeviceRevoke`].
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::Unsupported`] if the backend lacks
    /// [`Capability::DeviceRevoke`], or another [`BackendError`] variant for
    /// other revocation failures.
    fn revoke(&self, resource: &ResourceIdentity) -> Result<EnforcementResult, BackendError>;
}
