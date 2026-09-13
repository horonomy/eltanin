//! In-memory Trusted Compute Session storage for one
//! [`crate::authz::AuthorizationHandler`] (F-M2-001, HORO-791).
//!
//! Mirrors `state.rs`'s `LeaseState` shape and locking discipline
//! exactly — held behind its own `Mutex`, recovered rather than
//! propagated on poison, for the same reason.
//!
//! # Lazy reaping, no background thread
//!
//! [`SessionState::reap`] is called at the top of every session-touching
//! agent operation (`RequestLease`, `CreateSession`, `ListSessions`,
//! `TerminateSession`), re-observing each live session's anchor leader
//! and dropping any session whose liveness or administrative validity
//! ([`eltanin_core::session::SessionAuthority::validate`]) no longer
//! holds — the same touch-triggered idiom `state.rs`'s `LeaseState::prune`
//! already establishes for leases. **This is safe specifically because
//! [`eltanin_core::session::membership`] re-verifies fresh evidence on
//! every actual admission decision, not because this sweep is what
//! keeps membership honest** — a session that a reaping pass has not
//! yet noticed is dead can never be *used*, because `membership` would
//! independently reject it the moment anyone tried. Reaping only bounds
//! how long a dead session's memory footprint lingers; it is never the
//! sole thing standing between a dead session and a wrongly granted
//! lease. Do not read the absence of a background sweep thread as a
//! leak — this comment is here because that is an easy thing for a
//! future reader to misread.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, PoisonError};

use eltanin_core::identity::WorkloadIdentity;
use eltanin_core::lease::{LeaseId, MonotonicTime};
use eltanin_core::session::{
    SessionAuthority, SessionId, SessionKey, SessionValidity, TrustedSession,
};

/// Owns one [`SessionAuthority`] instance and the sessions it has
/// established that are still outstanding, plus the two indices HORO-791's
/// design specifies: `SessionKey -> SessionId` (membership lookup) and
/// `SessionId -> BTreeSet<LeaseId>` (which leases were issued under a
/// given session, so terminating it can revoke them).
pub(crate) struct SessionState {
    authority: SessionAuthority,
    sessions: HashMap<SessionId, TrustedSession>,
    by_key: HashMap<SessionKey, SessionId>,
    leases_by_session: HashMap<SessionId, BTreeSet<LeaseId>>,
}

impl SessionState {
    pub(crate) fn new(authority: SessionAuthority) -> Self {
        Self {
            authority,
            sessions: HashMap::new(),
            by_key: HashMap::new(),
            leases_by_session: HashMap::new(),
        }
    }

    pub(crate) fn authority_mut(&mut self) -> &mut SessionAuthority {
        &mut self.authority
    }

    /// Insert a freshly established session. Must not be called with a
    /// [`SessionKey`] already present — [`crate::authz::AuthorizationHandler`]'s
    /// `CreateSession` handling only calls this once per successfully
    /// established session, and a stale prior session sharing the same
    /// key would already have been reaped (its anchor leader is, by
    /// construction, a different live process than the one just
    /// establishing a new session with the same kernel-recycled key).
    pub(crate) fn insert(&mut self, session: TrustedSession) {
        let id = session.id().clone();
        self.by_key.insert(session.anchor().key, id.clone());
        self.leases_by_session.insert(id.clone(), BTreeSet::new());
        self.sessions.insert(id, session);
    }

    /// Look up a session by its [`SessionKey`] — the only lookup path
    /// used to decide membership. Never by [`SessionId`] alone from a
    /// client-presented value, because no client-presented session id
    /// exists anywhere in this protocol.
    pub(crate) fn find_by_key(&self, key: SessionKey) -> Option<&TrustedSession> {
        self.by_key.get(&key).and_then(|id| self.sessions.get(id))
    }

    pub(crate) fn get(&self, id: &SessionId) -> Option<&TrustedSession> {
        self.sessions.get(id)
    }

    /// Remove `id`, returning the session and the set of lease ids that
    /// were issued under it (for the caller to revoke), if it existed.
    pub(crate) fn remove(&mut self, id: &SessionId) -> Option<(TrustedSession, BTreeSet<LeaseId>)> {
        let session = self.sessions.remove(id)?;
        self.by_key.remove(&session.anchor().key);
        let leases = self.leases_by_session.remove(id).unwrap_or_default();
        Some((session, leases))
    }

    /// Record that `lease_id` was issued while `id`'s session was the
    /// verified membership match for the granting request. A no-op if
    /// `id` is not (or is no longer) stored — a session reaped between
    /// the membership check and the grant is not resurrected by this
    /// call.
    pub(crate) fn associate_lease(&mut self, id: &SessionId, lease_id: LeaseId) {
        if let Some(set) = self.leases_by_session.get_mut(id) {
            set.insert(lease_id);
        }
    }

    /// Drop every stored session whose [`SessionAuthority::validate`]
    /// (re-observing its anchor leader via `observe_leader`) is not
    /// [`SessionValidity::Valid`]. Returns each reaped session's id and
    /// its associated lease ids, for the caller to revoke at the
    /// backend/lease-state layer — this module owns no
    /// `ComputeBackend`/`LeaseState` reference itself, staying a pure
    /// session store.
    pub(crate) fn reap(
        &mut self,
        now: MonotonicTime,
        mut observe_leader: impl FnMut(u32) -> WorkloadIdentity,
    ) -> Vec<(SessionId, BTreeSet<LeaseId>)> {
        let stale: Vec<SessionId> = self
            .sessions
            .values()
            .filter_map(|session| {
                let leader = observe_leader(session.anchor().leader.pid);
                match self.authority.validate(session, &leader, now) {
                    SessionValidity::Valid { .. } => None,
                    _ => Some(session.id().clone()),
                }
            })
            .collect();
        stale
            .into_iter()
            .filter_map(|id| {
                self.remove(&id)
                    .map(|(session, leases)| (session.id().clone(), leases))
            })
            .collect()
    }
}

/// Recover a poisoned lock rather than propagate the poison — identical
/// rationale to `state::lock`.
pub(crate) fn lock(mutex: &Mutex<SessionState>) -> std::sync::MutexGuard<'_, SessionState> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
