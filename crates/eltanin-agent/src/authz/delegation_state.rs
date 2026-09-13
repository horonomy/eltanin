//! In-memory [`DelegationGrant`] storage for one
//! [`crate::authz::AuthorizationHandler`] (F-M2-003, HORO-793).
//!
//! Mirrors `session_state.rs`'s shape and locking discipline exactly —
//! held behind its own `Mutex`, recovered rather than propagated on
//! poison, for the same reason. Two indices: `LeaseId -> DelegationGrant`
//! (the grant store itself) and `LeaseId -> BTreeSet<LeaseId>` (which
//! child leases were minted under a given parent grant, so revoking the
//! parent can cascade to every descendant).
//!
//! # Lazy reaping, no background thread
//!
//! [`DelegationState::reap`] is called at the top of `RequestLease`
//! handling, same touch-triggered idiom `session_state.rs`'s
//! `SessionState::reap`/`state.rs`'s `LeaseState::prune` already
//! establish. **This is an optimization, not a correctness
//! requirement**: [`eltanin_core::delegation::delegated_admission`]
//! independently re-verifies holder liveness on every actual admission
//! decision — fail-closed on `IdentityComparison::Indeterminate`, never
//! silently `Admitted`. A grant this sweep has not yet noticed is stale
//! can never be used to admit a request; reaping only bounds how long a
//! dead grant's memory footprint lingers.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};

use eltanin_core::delegation::DelegationGrant;
use eltanin_core::identity::{IdentityComparison, WorkloadIdentity};
use eltanin_core::lease::{LeaseId, MonotonicTime};

/// Owns every currently outstanding [`DelegationGrant`], keyed by the
/// [`LeaseId`] it is 1:1 with, plus the parent-lease -> child-lease-ids
/// index HORO-793's design specifies.
pub(crate) struct DelegationState {
    grants: BTreeMap<LeaseId, DelegationGrant>,
    children: BTreeMap<LeaseId, BTreeSet<LeaseId>>,
}

impl DelegationState {
    pub(crate) fn new() -> Self {
        Self {
            grants: BTreeMap::new(),
            children: BTreeMap::new(),
        }
    }

    /// Insert a freshly minted grant, registering the parent -> child
    /// link when `grant.parent()` is `Some`.
    pub(crate) fn insert(&mut self, grant: DelegationGrant) {
        let lease_id = grant.lease_id().clone();
        if let Some(parent) = grant.parent() {
            self.children
                .entry(parent.clone())
                .or_default()
                .insert(lease_id.clone());
        }
        self.grants.insert(lease_id, grant);
    }

    /// Every currently stored grant — the candidate set
    /// `AuthorizationHandler`'s delegation gate scans, same shape as
    /// `authz::ApprovalState::candidates`.
    pub(crate) fn candidates(&self) -> impl Iterator<Item = &DelegationGrant> {
        self.grants.values()
    }

    /// Drop every grant whose `not_after` has passed, or whose holder
    /// process is no longer observably the same one it was minted for
    /// (`observe_holder` returning `None`, or `compare_process` reporting
    /// `Different` — never on `Indeterminate`, which is left for the
    /// next touch to re-evaluate rather than reaped speculatively).
    /// Cascades to every descendant grant. Returns every removed grant's
    /// [`LeaseId`] (root and cascaded) for the caller to revoke at the
    /// backend/lease-state layer — this module owns no
    /// `ComputeBackend`/`LeaseState` reference itself, staying a pure
    /// grant store, mirroring `SessionState::reap`'s identical contract.
    pub(crate) fn reap(
        &mut self,
        now: MonotonicTime,
        mut observe_holder: impl FnMut(u32) -> Option<WorkloadIdentity>,
    ) -> BTreeSet<LeaseId> {
        let stale: Vec<LeaseId> = self
            .grants
            .iter()
            .filter_map(|(id, grant)| {
                if grant.not_after() <= now {
                    return Some(id.clone());
                }
                match observe_holder(grant.holder().pid) {
                    None => Some(id.clone()),
                    Some(observed) => match grant.holder().compare_process(&observed) {
                        IdentityComparison::Different => Some(id.clone()),
                        IdentityComparison::Same | IdentityComparison::Indeterminate => None,
                    },
                }
            })
            .collect();
        let mut removed = BTreeSet::new();
        for id in stale {
            removed.extend(self.remove_cascade(&id));
        }
        removed
    }

    /// Remove `lease` and every descendant grant chained under it
    /// (recursively, via the parent -> child index), returning every
    /// removed [`LeaseId`] for the caller to revoke. A no-op returning an
    /// empty set if `lease` names no stored grant.
    pub(crate) fn remove_cascade(&mut self, lease: &LeaseId) -> BTreeSet<LeaseId> {
        let mut removed = BTreeSet::new();
        let mut stack = vec![lease.clone()];
        while let Some(id) = stack.pop() {
            if self.grants.remove(&id).is_some() {
                removed.insert(id.clone());
            }
            if let Some(children) = self.children.remove(&id) {
                stack.extend(children);
            }
        }
        removed
    }
}

/// Recover a poisoned lock rather than propagate the poison — identical
/// rationale to `state::lock`/`session_state::lock`.
pub(crate) fn lock(mutex: &Mutex<DelegationState>) -> std::sync::MutexGuard<'_, DelegationState> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
