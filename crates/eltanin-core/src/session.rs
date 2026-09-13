//! Trusted Compute Session (F-M2-001, HORO-791).
//!
//! A [`TrustedSession`] is a new, agent-owned authorization-security
//! context layered **on top of** the existing [`crate::lease`] model —
//! it narrows *who may even ask* for a [`crate::lease::ComputeLease`],
//! it does not itself grant compute. [`crate::policy::PolicySet`] still
//! evaluates every lease request; establishing a session changes
//! nothing about that evaluation. See ADR 0009 for the full design
//! record and the rejected alternatives (cgroup-scoped membership,
//! bearer token, TPM).
//!
//! # Why the caller's POSIX session, not a token
//!
//! No syscall lets an unprivileged process *join* an existing POSIX
//! session it did not create — only leave one (`setsid`). Membership by
//! descent from a session leader is therefore kernel-unforgeable:
//! anyone can *read* another process's session id (this is not a
//! read-protected value on Linux or macOS — verified for HORO-791, see
//! ADR 0009), but nothing lets an unrelated process *become* a member
//! of a session it does not already belong to. This is exactly the
//! property AC2 depends on ("another ordinary process cannot join
//! merely by copying session metadata/ID").
//!
//! **No client-supplied session id is ever accepted anywhere in this
//! module.** [`SessionAuthority::establish`] derives everything from
//! caller-supplied *evidence* (a freshly collected [`SessionKey`] and
//! [`crate::identity::WorkloadIdentity`]), never from a value a client
//! presents as "my session is X."
//!
//! # `Serialize`-only, mirroring `lease.rs`'s discipline
//!
//! [`TrustedSession`] is `Serialize` but never `Deserialize` — the
//! serialized form is a record of an established session, never a path
//! back into one. This is load-bearing for AC5 ("no long-lived
//! plaintext bearer secret is the trust root"): even if a serialized
//! `TrustedSession` leaked in full, it cannot be decoded back into a
//! value this module treats as authoritative. Fields are private with
//! no public constructor outside [`SessionAuthority::establish`], no
//! setter, and no `Default`.
//!
//! # `membership` is the one security-critical entry point
//!
//! [`membership`] is deliberately a single combined signature —
//! evidence freshness, key equality, and leader-liveness in one call —
//! rather than a lookup step followed by a separate liveness check.
//! Splitting it would reopen exactly the bug this module exists to
//! close: a caller could look a session up once, then rely on that
//! lookup's result indefinitely without ever re-confirming the leader
//! process is still the same one, which is precisely how a bearer
//! token becomes reusable after its original binding is gone.
//!
//! # Extensible seams, not implemented here
//!
//! - [`IntentProof`] has exactly one variant today
//!   ([`IntentProof::LocalPeerPresence`]). Hardware-backed
//!   key/user-presence (TPM) is explicitly deferred by the ticket; a
//!   second variant is additive.
//! - [`SessionAssurance`] has exactly one variant today
//!   ([`SessionAssurance::LocalKernelSession`]). Cgroup-scoped
//!   membership is a declared, unbuilt seam — `BLOCKED_ON_E3` per
//!   `docs/development/campaign-state.md` — and gets a second variant
//!   only when E3 lands. Nothing in this module implements or assumes
//!   cgroup scoping today.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Serialize;

use crate::identity::{Evidence, EvidenceSource, IdentityComparison, WorkloadIdentity};
use crate::lease::{IssuerInstanceId, MonotonicTime};
use crate::resource::ResourceIdentity;

/// A correlation identifier for one established [`TrustedSession`].
/// Carries no entropy and is **not** a capability or a secret — same
/// contract as [`crate::lease::LeaseId`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, serde::Deserialize)]
pub struct SessionId {
    pub issuer: IssuerInstanceId,
    pub sequence: u64,
}

/// An opaque, platform-collected value identifying one POSIX session on
/// this host (e.g. Linux/macOS's kernel session id, as read by
/// `eltanin-linux`/`eltanin-macos`'s `collect_session_key`). Meaningful
/// only when compared within one host's one collector — the same
/// "opaque, compared only within one host's one collector" contract as
/// [`crate::identity::ProcessStartToken`]. Never itself sufficient proof
/// of membership — see [`membership`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
pub struct SessionKey(pub u64);

/// The kernel-observed anchor a [`TrustedSession`] is bound to: a
/// session key plus the [`WorkloadIdentity`] of the process that was
/// the session's leader at establishment time. [`membership`] re-checks
/// both on every use — this is what defeats a PID/session-id-reuse
/// attack after the original leader process has exited (see
/// [`WorkloadIdentity::compare_process`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct LocalSessionAnchor {
    pub key: SessionKey,
    pub leader: WorkloadIdentity,
}

/// Why [`SessionScope::new`] refused a scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("session scope must name at least one resource")]
pub struct EmptyScope;

/// The set of resources a [`TrustedSession`] narrows admission to.
/// Structurally non-empty — the only way to obtain one is
/// [`SessionScope::new`], which rejects an empty resource set. Actions
/// stay per-lease, unchanged: a session narrows *which resources* may
/// even be asked about, never *what may be done* to them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct SessionScope {
    resources: BTreeSet<ResourceIdentity>,
}

impl SessionScope {
    /// # Errors
    ///
    /// Returns [`EmptyScope`] if `resources` is empty.
    pub fn new(resources: impl IntoIterator<Item = ResourceIdentity>) -> Result<Self, EmptyScope> {
        let resources: BTreeSet<ResourceIdentity> = resources.into_iter().collect();
        if resources.is_empty() {
            return Err(EmptyScope);
        }
        Ok(Self { resources })
    }

    #[must_use]
    pub fn resources(&self) -> &BTreeSet<ResourceIdentity> {
        &self.resources
    }

    #[must_use]
    pub fn contains(&self, resource: &ResourceIdentity) -> bool {
        self.resources.contains(resource)
    }
}

/// How the session owner's intent to establish a Trusted Compute
/// Session was proven. One variant today — see the module docs'
/// "Extensible seams" section. Hardware-backed user-presence (TPM) is
/// explicitly deferred by the ticket and would be a second variant,
/// never a modification of this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentProof {
    /// The requester was the authorizable local peer of the
    /// `CreateSession` request itself — i.e. proven the same way every
    /// other request to this agent proves who is asking
    /// ([`crate::peer::PeerContext::authorizable`]), with no additional
    /// hardware-backed step. This is the whole of MVP 2.0's intent
    /// model; see ADR 0009 for why a local, software-only proof is
    /// accepted at this assurance level.
    LocalPeerPresence,
}

/// What kind of kernel-backed membership evidence a [`TrustedSession`]
/// relies on. One variant today — see the module docs' "Extensible
/// seams" section. `CgroupScope` is a declared, unbuilt seam
/// (`BLOCKED_ON_E3`): adding it requires a privileged, non-delegated
/// cgroup subtree this campaign does not yet have available outside
/// bare metal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionAssurance {
    /// Membership is derived solely from POSIX session descent — see
    /// the module docs' "Why the caller's POSIX session" section.
    LocalKernelSession,
}

/// One established Trusted Compute Session. Fields are private with no
/// public constructor outside [`SessionAuthority::establish`];
/// `Serialize` only, deliberately not `Deserialize` — see the module
/// docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustedSession {
    id: SessionId,
    owner_uid: u32,
    anchor: LocalSessionAnchor,
    scope: SessionScope,
    intent: IntentProof,
    assurance: SessionAssurance,
    established_at: MonotonicTime,
    expires_at: MonotonicTime,
}

impl TrustedSession {
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    #[must_use]
    pub fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    #[must_use]
    pub fn anchor(&self) -> &LocalSessionAnchor {
        &self.anchor
    }

    #[must_use]
    pub fn scope(&self) -> &SessionScope {
        &self.scope
    }

    #[must_use]
    pub fn intent(&self) -> IntentProof {
        self.intent
    }

    #[must_use]
    pub fn assurance(&self) -> SessionAssurance {
        self.assurance
    }

    #[must_use]
    pub fn established_at(&self) -> MonotonicTime {
        self.established_at
    }

    #[must_use]
    pub fn expires_at(&self) -> MonotonicTime {
        self.expires_at
    }
}

/// Why [`SessionAuthority::establish`] refused to establish a session.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("session ttl must be greater than zero")]
    NonPositiveTtl,
    #[error("session ttl {requested:?} exceeds authority maximum {maximum:?}")]
    TtlExceedsMaximum {
        requested: Duration,
        maximum: Duration,
    },
    #[error("session expiry would overflow the monotonic clock range")]
    ExpiryOverflow,
}

/// The result of [`SessionAuthority::terminate`]. Mirrors
/// [`crate::lease::RevocationOutcome`]'s shape exactly, for the same
/// reason: a client-facing wire projection (see `eltanin-protocol`)
/// collapses everything but `Terminated` to a single refusal so a
/// client can never use the response to enumerate whether a session id
/// exists, belongs to another owner, or was already terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionTerminationOutcome {
    Terminated,
    AlreadyTerminated,
    NotIssued,
    ForeignIssuer,
}

/// The result of [`SessionAuthority::validate`] — the *administrative*
/// validity check (issuer identity, termination, anchor liveness,
/// expiry). Distinct from [`membership`], which additionally requires
/// fresh evidence *from the requesting peer itself*; `validate` is what
/// the agent's lazy-reaping sweep uses to decide whether a session is
/// still worth keeping around at all, re-observing the anchor leader
/// itself (not a peer's claim about it) to do so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "validity")]
pub enum SessionValidity {
    Valid {
        remaining: Duration,
    },
    /// The session names an [`IssuerInstanceId`] that is not this live
    /// authority — an agent restart, or a second live authority. Never
    /// treated as valid. This is what makes restart/recovery semantics
    /// explicit (AC4): after an agent restart, every prior session is
    /// unconditionally `ForeignIssuer`, never silently `Valid`.
    ForeignIssuer {
        issued_by: IssuerInstanceId,
    },
    Terminated,
    /// The session's anchor leader process is no longer observably the
    /// same process that established the session (it exited, or its
    /// `ProcessStartToken` no longer matches — [`IdentityComparison::Different`]),
    /// or liveness could not be confirmed at all
    /// ([`IdentityComparison::Indeterminate`], fails closed identically
    /// to `Different`).
    AnchorGone,
    Expired {
        expired_at: MonotonicTime,
    },
}

/// The result of [`membership`]. A rich enum, not a `bool`, following
/// this crate's established pattern (see
/// [`crate::identity::IdentityComparison`],
/// [`crate::policy::DecisionReason`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "verdict")]
pub enum MembershipVerdict {
    Member,
    NotMember,
    /// The evidence needed to decide membership could not be confirmed
    /// (missing/unsupported/self-asserted session-key evidence, or
    /// [`IdentityComparison::Indeterminate`] leader comparison). Callers
    /// must treat this identically to [`MembershipVerdict::NotMember`]
    /// — never as `Member` — but it is kept as its own case so an audit
    /// trail can distinguish "confirmed not a member" from "could not
    /// confirm."
    Indeterminate {
        reason: String,
    },
}

/// Determine whether `observed_leader` (freshly collected for
/// `session.anchor().leader().pid`, at call time, by the caller) and
/// `peer_key` (a freshly collected [`SessionKey`] for the requesting
/// peer) together prove that peer is a current member of `session`.
///
/// This is deliberately the **one** combined signature: evidence
/// freshness, key equality, and leader-liveness are checked together,
/// not as a lookup step followed by a separate liveness check — see the
/// module docs for why splitting it would reintroduce the bug this
/// function exists to prevent.
///
/// `peer_key` must be [`Evidence::Present`] and not
/// [`EvidenceSource::SelfAsserted`]; its value must equal
/// `session.anchor().key`; and
/// [`WorkloadIdentity::compare_process`] of `session.anchor().leader()`
/// against `observed_leader` must report [`IdentityComparison::Same`].
/// Anything else is [`MembershipVerdict::Indeterminate`] or
/// [`MembershipVerdict::NotMember`] — never [`MembershipVerdict::Member`].
#[must_use]
pub fn membership(
    session: &TrustedSession,
    peer_key: &Evidence<SessionKey>,
    observed_leader: &WorkloadIdentity,
) -> MembershipVerdict {
    let key = match peer_key {
        Evidence::Present {
            value,
            source: EvidenceSource::SelfAsserted,
        } => {
            let _ = value;
            return MembershipVerdict::Indeterminate {
                reason: "peer session-key evidence was self-asserted".to_string(),
            };
        }
        Evidence::Present { value, .. } => value,
        Evidence::Missing { reason } => {
            return MembershipVerdict::Indeterminate {
                reason: reason.clone(),
            }
        }
        Evidence::Unsupported => {
            return MembershipVerdict::Indeterminate {
                reason: "session-key collection is unsupported on this platform".to_string(),
            }
        }
    };

    if *key != session.anchor.key {
        return MembershipVerdict::NotMember;
    }

    match session.anchor.leader.compare_process(observed_leader) {
        IdentityComparison::Same => MembershipVerdict::Member,
        IdentityComparison::Different => MembershipVerdict::NotMember,
        IdentityComparison::Indeterminate => MembershipVerdict::Indeterminate {
            reason: "session anchor leader liveness could not be confirmed".to_string(),
        },
    }
}

/// Issues and terminates [`TrustedSession`] values for one live process
/// instance. Mirrors [`crate::lease::LeaseIssuer`]'s shape and API style
/// exactly: `max_ttl` is required at construction, time is always
/// injected, and there is no `renew`/`extend` — establishing a new
/// session is always a fresh act of intent.
pub struct SessionAuthority {
    instance: IssuerInstanceId,
    max_ttl: Duration,
    next_sequence: u64,
    terminated: BTreeSet<u64>,
}

impl SessionAuthority {
    #[must_use]
    pub fn new(instance: IssuerInstanceId, max_ttl: Duration) -> Self {
        Self {
            instance,
            max_ttl,
            next_sequence: 0,
            terminated: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn instance(&self) -> &IssuerInstanceId {
        &self.instance
    }

    /// Establish a new [`TrustedSession`] bound to `anchor`, scoped to
    /// `scope`, for `owner_uid`.
    ///
    /// This never consults [`crate::policy::PolicySet`] — a session
    /// gates lease *issuance*, it is not itself policy-evaluated.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::NonPositiveTtl`] if `ttl` is zero,
    /// [`SessionError::TtlExceedsMaximum`] if `ttl` exceeds this
    /// authority's `max_ttl`, or [`SessionError::ExpiryOverflow`] if
    /// `now + ttl` would overflow the monotonic clock range.
    // Eight parameters, one per field a `TrustedSession` actually needs
    // — every one is a distinct, independently-sourced piece of
    // evidence (never bundle-able into a single struct without
    // reintroducing a "partially built session" intermediate value,
    // which this module's "no public constructor outside `establish`"
    // discipline deliberately avoids).
    #[allow(clippy::too_many_arguments)]
    pub fn establish(
        &mut self,
        owner_uid: u32,
        anchor: LocalSessionAnchor,
        scope: SessionScope,
        intent: IntentProof,
        assurance: SessionAssurance,
        now: MonotonicTime,
        ttl: Duration,
    ) -> Result<TrustedSession, SessionError> {
        if ttl.is_zero() {
            return Err(SessionError::NonPositiveTtl);
        }
        if ttl > self.max_ttl {
            return Err(SessionError::TtlExceedsMaximum {
                requested: ttl,
                maximum: self.max_ttl,
            });
        }
        let expires_at = now.checked_add(ttl).ok_or(SessionError::ExpiryOverflow)?;

        let id = SessionId {
            issuer: self.instance.clone(),
            sequence: self.next_sequence,
        };
        self.next_sequence += 1;

        Ok(TrustedSession {
            id,
            owner_uid,
            anchor,
            scope,
            intent,
            assurance,
            established_at: now,
            expires_at,
        })
    }

    /// Terminate the session identified by `id`, if it was established
    /// by this authority instance.
    pub fn terminate(&mut self, id: &SessionId) -> SessionTerminationOutcome {
        if id.issuer != self.instance {
            return SessionTerminationOutcome::ForeignIssuer;
        }
        if id.sequence >= self.next_sequence {
            return SessionTerminationOutcome::NotIssued;
        }
        if !self.terminated.insert(id.sequence) {
            return SessionTerminationOutcome::AlreadyTerminated;
        }
        SessionTerminationOutcome::Terminated
    }

    /// Administrative validity of `session`: issuer identity,
    /// termination, anchor-leader liveness (re-observed as
    /// `observed_leader`, never taken from `session` itself), then
    /// expiry — same check-order discipline as
    /// [`crate::lease::LeaseIssuer::validate`]. This is *not* a
    /// substitute for [`membership`]: `validate` never checks the
    /// requesting peer's own session-key evidence, only whether the
    /// session itself is still administratively alive. See the module
    /// docs on why the agent's lazy-reaping sweep uses this and
    /// `membership` is reserved for actual admission decisions.
    #[must_use]
    pub fn validate(
        &self,
        session: &TrustedSession,
        observed_leader: &WorkloadIdentity,
        now: MonotonicTime,
    ) -> SessionValidity {
        if session.id.issuer != self.instance {
            return SessionValidity::ForeignIssuer {
                issued_by: session.id.issuer.clone(),
            };
        }
        if self.terminated.contains(&session.id.sequence) {
            return SessionValidity::Terminated;
        }
        match session.anchor.leader.compare_process(observed_leader) {
            IdentityComparison::Same => {}
            IdentityComparison::Different | IdentityComparison::Indeterminate => {
                return SessionValidity::AnchorGone;
            }
        }
        if now >= session.expires_at {
            return SessionValidity::Expired {
                expired_at: session.expires_at,
            };
        }
        SessionValidity::Valid {
            remaining: session.expires_at.saturating_duration_since(now),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ProcessStartToken;

    fn present_start(token: u64) -> Evidence<ProcessStartToken> {
        Evidence::Present {
            value: ProcessStartToken(token),
            source: EvidenceSource::KernelObserved,
        }
    }

    fn leader(pid: u32, start: u64) -> WorkloadIdentity {
        WorkloadIdentity {
            pid,
            process_start: present_start(start),
            uid: Evidence::Present {
                value: 1000,
                source: EvidenceSource::KernelObserved,
            },
            gid: Evidence::Unsupported,
            executable_path: Evidence::Unsupported,
            executable_hash: Evidence::Unsupported,
            ancestry: Vec::new(),
        }
    }

    fn scope() -> SessionScope {
        SessionScope::new([ResourceIdentity {
            vendor: crate::resource::ResourceVendor::new("fake"),
            kind: crate::resource::ResourceKind::gpu(),
            local_id: "0".to_string(),
        }])
        .unwrap()
    }

    fn authority() -> SessionAuthority {
        SessionAuthority::new(IssuerInstanceId::new("agent-1"), Duration::from_secs(3600))
    }

    fn establish_default(authority: &mut SessionAuthority) -> TrustedSession {
        authority
            .establish(
                1000,
                LocalSessionAnchor {
                    key: SessionKey(42),
                    leader: leader(100, 999),
                },
                scope(),
                IntentProof::LocalPeerPresence,
                SessionAssurance::LocalKernelSession,
                MonotonicTime::from_nanos(0),
                Duration::from_secs(60),
            )
            .unwrap()
    }

    #[test]
    fn empty_scope_is_rejected() {
        assert!(SessionScope::new(std::iter::empty::<ResourceIdentity>()).is_err());
    }

    #[test]
    fn membership_requires_matching_key_and_same_leader() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let matching_key = Evidence::Present {
            value: SessionKey(42),
            source: EvidenceSource::KernelObserved,
        };
        assert_eq!(
            membership(&session, &matching_key, &leader(100, 999)),
            MembershipVerdict::Member
        );
    }

    #[test]
    fn membership_rejects_wrong_key() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let wrong_key = Evidence::Present {
            value: SessionKey(7),
            source: EvidenceSource::KernelObserved,
        };
        assert_eq!(
            membership(&session, &wrong_key, &leader(100, 999)),
            MembershipVerdict::NotMember
        );
    }

    #[test]
    fn membership_rejects_dead_leader_reuse_even_with_matching_key() {
        // Same pid, different start token: the original leader exited and
        // pid 100 was reused by an unrelated later process. Matching the
        // session key alone must not be sufficient.
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let matching_key = Evidence::Present {
            value: SessionKey(42),
            source: EvidenceSource::KernelObserved,
        };
        assert_eq!(
            membership(&session, &matching_key, &leader(100, 111)),
            MembershipVerdict::NotMember
        );
    }

    #[test]
    fn membership_rejects_self_asserted_key_evidence() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let self_asserted = Evidence::Present {
            value: SessionKey(42),
            source: EvidenceSource::SelfAsserted,
        };
        assert_eq!(
            membership(&session, &self_asserted, &leader(100, 999)),
            MembershipVerdict::Indeterminate {
                reason: "peer session-key evidence was self-asserted".to_string()
            }
        );
    }

    #[test]
    fn membership_missing_key_evidence_is_indeterminate_not_not_member() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let missing = Evidence::Missing {
            reason: "no session".to_string(),
        };
        assert!(matches!(
            membership(&session, &missing, &leader(100, 999)),
            MembershipVerdict::Indeterminate { .. }
        ));
    }

    #[test]
    fn validate_reports_valid_before_expiry() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let validity =
            authority.validate(&session, &leader(100, 999), MonotonicTime::from_nanos(1));
        assert!(matches!(validity, SessionValidity::Valid { .. }));
    }

    #[test]
    fn validate_reports_expired_after_ttl() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let validity = authority.validate(
            &session,
            &leader(100, 999),
            MonotonicTime::from_nanos(u64::try_from(Duration::from_secs(60).as_nanos()).unwrap()),
        );
        assert!(matches!(validity, SessionValidity::Expired { .. }));
    }

    #[test]
    fn validate_reports_anchor_gone_when_leader_no_longer_matches() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let validity =
            authority.validate(&session, &leader(100, 111), MonotonicTime::from_nanos(1));
        assert_eq!(validity, SessionValidity::AnchorGone);
    }

    #[test]
    fn validate_reports_terminated_after_terminate() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        assert_eq!(
            authority.terminate(session.id()),
            SessionTerminationOutcome::Terminated
        );
        let validity =
            authority.validate(&session, &leader(100, 999), MonotonicTime::from_nanos(1));
        assert_eq!(validity, SessionValidity::Terminated);
    }

    #[test]
    fn validate_reports_foreign_issuer_after_restart() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let restarted =
            SessionAuthority::new(IssuerInstanceId::new("agent-2"), Duration::from_secs(3600));
        let validity =
            restarted.validate(&session, &leader(100, 999), MonotonicTime::from_nanos(1));
        assert_eq!(
            validity,
            SessionValidity::ForeignIssuer {
                issued_by: IssuerInstanceId::new("agent-1")
            }
        );
    }

    #[test]
    fn terminate_is_idempotent_and_reports_already_terminated() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        assert_eq!(
            authority.terminate(session.id()),
            SessionTerminationOutcome::Terminated
        );
        assert_eq!(
            authority.terminate(session.id()),
            SessionTerminationOutcome::AlreadyTerminated
        );
    }

    #[test]
    fn establish_rejects_zero_ttl() {
        let mut authority = authority();
        let result = authority.establish(
            1000,
            LocalSessionAnchor {
                key: SessionKey(1),
                leader: leader(1, 1),
            },
            scope(),
            IntentProof::LocalPeerPresence,
            SessionAssurance::LocalKernelSession,
            MonotonicTime::from_nanos(0),
            Duration::ZERO,
        );
        assert_eq!(result, Err(SessionError::NonPositiveTtl));
    }

    #[test]
    fn establish_rejects_ttl_over_maximum() {
        let mut authority = authority();
        let result = authority.establish(
            1000,
            LocalSessionAnchor {
                key: SessionKey(1),
                leader: leader(1, 1),
            },
            scope(),
            IntentProof::LocalPeerPresence,
            SessionAssurance::LocalKernelSession,
            MonotonicTime::from_nanos(0),
            Duration::from_secs(999_999),
        );
        assert!(matches!(
            result,
            Err(SessionError::TtlExceedsMaximum { .. })
        ));
    }
}
