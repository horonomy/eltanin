//! Deterministic Fake Compute Backend (F-M1-001, HORO-827).
//!
//! Implements [`ComputeBackend`] with in-memory, scriptable state so
//! every downstream Feature's authorization flow can be exercised in
//! ordinary CI, with no GPU and no real backend implementation.
//! [`FakeBackend`] implements the same trait real backends do — no
//! special-case logic exists here that a real backend couldn't also
//! provide.

use std::collections::HashMap;
use std::sync::RwLock;

use eltanin_core::resource::{
    Capability, ComputeRequest, EnforcementResult, ProtectedResource, ResourceIdentity,
};

use crate::contract::{BackendError, ComputeBackend};

/// A deterministic, in-memory [`ComputeBackend`] for tests and CI.
///
/// Resources are added at construction (or later, via [`Self::insert`])
/// and can be removed to simulate a resource disappearing mid-session.
/// [`Self::script_enforcement`] lets a test pin exactly what `enforce`
/// returns for a resource that has [`Capability::DeviceEnforce`] — this is how
/// a test simulates "policy already decided ALLOW/DENY" and "a lease has
/// expired" without depending on F-M1-004/005, which don't exist yet. A
/// script can never override a real capability downgrade.
#[derive(Default)]
pub struct FakeBackend {
    resources: RwLock<HashMap<ResourceIdentity, ProtectedResource>>,
    scripted_enforcement: RwLock<HashMap<ResourceIdentity, EnforcementResult>>,
    revoke_calls: RwLock<HashMap<ResourceIdentity, u32>>,
}

impl FakeBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a resource this backend reports as present.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (a prior panic while
    /// holding it) — this is a test/CI fixture, so failing loudly is
    /// preferable to silently continuing on corrupted state.
    pub fn insert(&self, resource: ProtectedResource) {
        self.resources
            .write()
            .expect("lock poisoned")
            .insert(resource.identity.clone(), resource);
    }

    /// Remove a resource, simulating it disappearing mid-session.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned — see [`Self::insert`].
    pub fn remove(&self, identity: &ResourceIdentity) {
        self.resources
            .write()
            .expect("lock poisoned")
            .remove(identity);
        self.scripted_enforcement
            .write()
            .expect("lock poisoned")
            .remove(identity);
    }

    /// Pin what `enforce` returns for `identity` when it also has
    /// [`Capability::DeviceEnforce`]. Used to script an already-decided
    /// ALLOW/DENY (F-M1-004's job in the real system) or a lease-expiry
    /// outcome (F-M1-005's job) without depending on those Features.
    ///
    /// A script can never produce `Allowed` for a resource that lacks
    /// `Capability::DeviceEnforce` — `enforce` checks capability first and
    /// ignores the script entirely in that case, so this can't be used
    /// to accidentally mask a capability downgrade.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned — see [`Self::insert`].
    pub fn script_enforcement(&self, identity: ResourceIdentity, result: EnforcementResult) {
        self.scripted_enforcement
            .write()
            .expect("lock poisoned")
            .insert(identity, result);
    }

    /// How many times [`ComputeBackend::revoke`] has been called for
    /// `identity` so far — including calls that returned
    /// `Unsupported`/`Err`, since a caller deciding *whether* to call
    /// `revoke` at all is exactly the behavior this exists to make
    /// observable to a test (see `eltanin-agent`'s
    /// `authz_backend_failure.rs`, which asserts a shared resource's
    /// backend enforcement is torn down at most once even when two
    /// clients hold leases on it).
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned — see [`Self::insert`].
    #[must_use]
    pub fn revoke_call_count(&self, identity: &ResourceIdentity) -> u32 {
        self.revoke_calls
            .read()
            .expect("lock poisoned")
            .get(identity)
            .copied()
            .unwrap_or(0)
    }
}

impl ComputeBackend for FakeBackend {
    fn discover(&self) -> Result<Vec<ProtectedResource>, BackendError> {
        Ok(self
            .resources
            .read()
            .expect("lock poisoned")
            .values()
            .cloned()
            .collect())
    }

    fn observe(&self, resource: &ResourceIdentity) -> Result<ProtectedResource, BackendError> {
        self.resources
            .read()
            .expect("lock poisoned")
            .get(resource)
            .cloned()
            .ok_or_else(|| BackendError::Unavailable {
                resource: resource.clone(),
            })
    }

    fn enforce(&self, request: &ComputeRequest) -> Result<EnforcementResult, BackendError> {
        let resource = self.observe(&request.resource)?;

        // Capability is checked first, before any scripted override. A
        // script may stand in for a policy/lease decision (ALLOW/DENY),
        // but it must never be able to mask a real capability downgrade
        // by scripting `Allowed` on a resource that structurally cannot
        // be enforced on — that's exactly what EnforcementResult's own
        // docs forbid (a downgrade must never masquerade as enforcement).
        if !resource.capabilities.supports(Capability::DeviceEnforce) {
            return Ok(EnforcementResult::Unsupported {
                capability: Capability::DeviceEnforce,
            });
        }

        if let Some(scripted) = self
            .scripted_enforcement
            .read()
            .expect("lock poisoned")
            .get(&request.resource)
        {
            return Ok(scripted.clone());
        }

        Ok(EnforcementResult::Allowed)
    }

    fn revoke(&self, resource: &ResourceIdentity) -> Result<EnforcementResult, BackendError> {
        *self
            .revoke_calls
            .write()
            .expect("lock poisoned")
            .entry(resource.clone())
            .or_insert(0) += 1;
        let observed = self.observe(resource)?;
        if !observed.capabilities.supports(Capability::DeviceRevoke) {
            return Ok(EnforcementResult::Unsupported {
                capability: Capability::DeviceRevoke,
            });
        }
        Ok(EnforcementResult::Allowed)
    }
}
