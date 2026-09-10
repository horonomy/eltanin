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
/// returns for a given resource, independent of its capabilities —
/// this is how a test simulates "policy already decided ALLOW/DENY" and
/// "a lease has expired" without depending on F-M1-004/005, which don't
/// exist yet.
#[derive(Default)]
pub struct FakeBackend {
    resources: RwLock<HashMap<ResourceIdentity, ProtectedResource>>,
    scripted_enforcement: RwLock<HashMap<ResourceIdentity, EnforcementResult>>,
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
    /// [`Capability::Enforce`]. Used to script an already-decided
    /// ALLOW/DENY (F-M1-004's job in the real system) or a lease-expiry
    /// outcome (F-M1-005's job) without depending on those Features.
    ///
    /// A script can never produce `Allowed` for a resource that lacks
    /// `Capability::Enforce` — `enforce` checks capability first and
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
        if !resource.capabilities.supports(Capability::Enforce) {
            return Ok(EnforcementResult::Unsupported {
                capability: Capability::Enforce,
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
        let observed = self.observe(resource)?;
        if !observed.capabilities.supports(Capability::Revoke) {
            return Ok(EnforcementResult::Unsupported {
                capability: Capability::Revoke,
            });
        }
        Ok(EnforcementResult::Allowed)
    }
}
