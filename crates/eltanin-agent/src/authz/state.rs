//! In-memory lease storage for one [`crate::authz::AuthorizationHandler`]
//! (F-M1-006, HORO-840).
//!
//! Held behind a `Mutex` inside the handler ([`crate::handler::RequestHandler`]
//! is `&self`). Keyed by [`LeaseId`], not by raw sequence number, so a
//! [`LeaseId`] naming a prior `IssuerInstanceId` simply misses the
//! store — cross-instance sequence collision is unrepresentable, not
//! merely avoided by convention.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use eltanin_core::lease::{ComputeLease, LeaseId, LeaseIssuer, MonotonicTime};

/// Owns one [`LeaseIssuer`] instance and the leases it has issued that
/// are still outstanding.
pub(crate) struct LeaseState {
    issuer: LeaseIssuer,
    leases: HashMap<LeaseId, ComputeLease>,
    max_outstanding: usize,
}

impl LeaseState {
    pub(crate) fn new(issuer: LeaseIssuer, max_outstanding: usize) -> Self {
        Self {
            issuer,
            leases: HashMap::new(),
            max_outstanding,
        }
    }

    pub(crate) fn issuer(&self) -> &LeaseIssuer {
        &self.issuer
    }

    pub(crate) fn issuer_mut(&mut self) -> &mut LeaseIssuer {
        &mut self.issuer
    }

    /// Drop every lease whose `expires_at <= now`. Called at the top of
    /// both `RequestLease` and `ReleaseLease` handling, so a release can
    /// never report success for a lease that has already expired.
    pub(crate) fn prune(&mut self, now: MonotonicTime) {
        self.leases.retain(|_, lease| lease.expires_at() > now);
    }

    pub(crate) fn is_at_capacity(&self) -> bool {
        self.leases.len() >= self.max_outstanding
    }

    pub(crate) fn insert(&mut self, lease: ComputeLease) {
        self.leases.insert(lease.id().clone(), lease);
    }

    pub(crate) fn get(&self, id: &LeaseId) -> Option<&ComputeLease> {
        self.leases.get(id)
    }

    pub(crate) fn remove(&mut self, id: &LeaseId) -> Option<ComputeLease> {
        self.leases.remove(id)
    }

    /// Whether any *other* outstanding lease names the same resource as
    /// `id`'s lease. Used to gate a backend teardown on release: two
    /// clients holding leases for the same resource must not have one
    /// client's release tear down enforcement the other still relies on.
    pub(crate) fn any_other_live_lease_for_same_resource(&self, id: &LeaseId) -> bool {
        let Some(released) = self.leases.get(id) else {
            return false;
        };
        self.leases.iter().any(|(other_id, other)| {
            other_id != id && other.origin().request.resource == released.origin().request.resource
        })
    }
}

/// Recover a poisoned lock rather than propagate the poison. A handler
/// panic inside `catch_unwind` (see [`crate::connection::serve_connection`])
/// poisons any `Mutex` still held at that moment; using `.unwrap()` here
/// would convert one bad request into a permanent agent outage for every
/// request after it. The lease state's own invariants (a `HashMap`, a
/// `LeaseIssuer`) have no partial-update window a panic could leave
/// torn — every mutation here is a single non-panicking operation — so
/// recovering the guard is safe, not merely convenient.
pub(crate) fn lock(mutex: &Mutex<LeaseState>) -> std::sync::MutexGuard<'_, LeaseState> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
