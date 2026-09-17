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
use eltanin_core::resource::ResourceIdentity;

/// Owns one [`LeaseIssuer`] instance and the leases it has issued that
/// are still outstanding.
pub(crate) struct LeaseState {
    issuer: LeaseIssuer,
    leases: HashMap<LeaseId, ComputeLease>,
    max_outstanding: usize,
    /// Slots reserved by an `issue()` that succeeded but whose backend
    /// enforcement is still pending (`enforce()` runs unlocked, between
    /// this reservation and the eventual `insert`/`release_reservation`
    /// call). Without this, `is_at_capacity` checked only against
    /// `leases.len()` would let N concurrent `RequestLease` calls all
    /// pass the capacity gate before any of them inserts — the capacity
    /// bound would be enforced against a snapshot that's stale by the
    /// time it matters. `is_at_capacity` counts both together so the
    /// check-then-issue-then-(later)-insert sequence can't overshoot.
    reserved: usize,
}

impl LeaseState {
    pub(crate) fn new(issuer: LeaseIssuer, max_outstanding: usize) -> Self {
        Self {
            issuer,
            leases: HashMap::new(),
            max_outstanding,
            reserved: 0,
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

    /// Remove every lease whose `expires_at <= now`, returning
    /// `(LeaseId, ResourceIdentity)` for exactly the resources whose
    /// backend enforcement must actually be torn down — i.e. every
    /// distinct resource named by a just-expired lease for which no
    /// other still-live lease remains. `LeaseId` is one representative
    /// expired lease's id for that resource, carried through for audit
    /// fidelity; the actual backend call the caller makes with this
    /// result is keyed on the resource alone (mirroring
    /// `AuthorizationHandler::handle_release_lease`'s own
    /// `backend.revoke(&resource)` call).
    ///
    /// Bug fix (HORO-795): [`Self::prune`] above (called by
    /// `issue_reserving_capacity` and `AuthorizationHandler::handle_release_lease`)
    /// drops an expired lease's *lease-state* record but owns no
    /// [`eltanin_backend::contract::ComputeBackend`] reference and
    /// cannot itself call `backend.revoke()` — without this sweep, a
    /// workload whose controlling `eltanin run` process was killed (so
    /// `ReleaseLease` is never called) keeps live backend-side
    /// enforcement indefinitely after its lease has silently expired and
    /// been pruned. This method owns no backend reference either
    /// (mirrors `SessionState::reap`'s identical "returns work for the
    /// caller, owns no backend reference" shape) — `#[must_use]` because
    /// a caller that drops this return value silently reproduces exactly
    /// that bug.
    #[must_use]
    pub(crate) fn sweep_expired(&mut self, now: MonotonicTime) -> Vec<(LeaseId, ResourceIdentity)> {
        let expired_ids: Vec<LeaseId> = self
            .leases
            .iter()
            .filter(|(_, lease)| lease.expires_at() <= now)
            .map(|(id, _)| id.clone())
            .collect();
        let expired: Vec<ComputeLease> = expired_ids
            .into_iter()
            .filter_map(|id| self.leases.remove(&id))
            .collect();

        // Every expired lease is already removed from `self.leases`
        // above, so checking "any other live lease for this resource"
        // now means checking the leases that remain — the same rule
        // `any_other_live_lease_for_same_resource` applies, evaluated
        // once per distinct resource rather than once per lease so a
        // resource named by several simultaneously-expired leases is
        // not handed back (and later revoked) more than once.
        let mut seen_resources = std::collections::BTreeSet::new();
        let mut work = Vec::new();
        for lease in &expired {
            let resource = lease.origin().request.resource.clone();
            if !seen_resources.insert(resource.clone()) {
                continue;
            }
            let still_live = self
                .leases
                .values()
                .any(|other| other.origin().request.resource == resource);
            if !still_live {
                work.push((lease.id().clone(), resource));
            }
        }
        work
    }

    pub(crate) fn is_at_capacity(&self) -> bool {
        self.leases.len() + self.reserved >= self.max_outstanding
    }

    /// Reserve a capacity slot for a lease that has just been issued but
    /// not yet inserted (its backend enforcement is still pending). Must
    /// be paired with exactly one later `insert` or
    /// `release_reservation` call.
    pub(crate) fn reserve(&mut self) {
        self.reserved += 1;
    }

    /// Release a slot reserved by [`Self::reserve`] without inserting a
    /// lease — the compensating-revoke path when enforcement did not
    /// succeed.
    pub(crate) fn release_reservation(&mut self) {
        self.reserved = self.reserved.saturating_sub(1);
    }

    /// Consume one reservation and insert the lease it was reserved for.
    pub(crate) fn insert(&mut self, lease: ComputeLease) {
        self.release_reservation();
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
