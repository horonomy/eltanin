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
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

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

/// Locally-resolved host identity (HORO-1278), e.g. `uname()`'s
/// nodename as read by `eltanin-agent::authz::session::collect_host_id`
/// — never network-resolved. A hostname is mutable by the host's own
/// owner and is not a security boundary against a local attacker; its
/// only job is cross-host session reuse rejection, which is currently
/// inert (session state is agent-in-memory, single-host) but becomes
/// meaningful the moment session state is ever shared/persisted across
/// hosts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HostId(pub String);

/// A 32-byte value read from the OS CSPRNG at session-establishment
/// time (HORO-1278). **This does no security work today** — it is
/// agent-held only (never serialized onto the wire or into an audit
/// log: `#[serde(skip)]`), never compared, never validated. It exists
/// solely as the future extension seam a hardware-backed (Secure
/// Enclave/TPM) challenge/response could bind a per-session
/// challenge to, per ADR 0009's "extensible seams, not implemented
/// here" discipline. Do not read its mere presence as proof of any
/// stronger assurance than [`SessionAssurance::LocalKernelSession`]
/// already states.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct SessionNonce(#[serde(skip)] [u8; 32]);

impl SessionNonce {
    /// Construct a [`SessionNonce`] from 32 bytes already read from the
    /// OS CSPRNG by the caller (this crate performs no I/O itself — see
    /// `eltanin-agent::authz::session::generate_session_nonce`, which
    /// mirrors [`SessionAuthority::establish`]'s existing "time is
    /// always injected" discipline for exactly the same reason: no
    /// non-deterministic external read happens inside this vendor-
    /// neutral crate).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for SessionNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionNonce(<redacted>)")
    }
}

/// Whether a [`TrustedSession`]'s anchor leader was actually observed at
/// establishment time. **This is reject-only evidence.** An absent or
/// unobservable leader — [`LeaderCorroboration::Unobserved`], or a
/// [`LeaderCorroboration::Recorded`] leader that a later re-observation
/// cannot confirm ([`IdentityComparison::Indeterminate`]) — must NEVER
/// cause [`membership`] or [`SessionAuthority::validate`] to deny. Only
/// an actual contradiction — a different, live process now observably
/// occupying the same pid/sid
/// ([`IdentityComparison::Different`]) — may deny. This deliberately
/// inverts this crate's usual fail-closed [`Evidence`] discipline (where
/// missing evidence is treated as indeterminate/denied): the entire
/// point of HORO-1278 is that a Trusted Compute Session's establishing
/// CLI process is *expected* to exit almost immediately, so treating
/// "the original leader is no longer observable" as a denial reason
/// would silently reintroduce the exact bug this ticket exists to fix.
/// A future maintainer tempted to "fix" this by failing closed on
/// absence would be reintroducing that bug, not hardening this module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum LeaderCorroboration {
    /// The anchor leader's [`WorkloadIdentity`] as observed at
    /// establishment time. Re-checked on every use via
    /// [`WorkloadIdentity::compare_process`] against a freshly observed
    /// identity for the same pid — see this enum's own doc for why only
    /// [`IdentityComparison::Different`] may ever deny.
    Recorded(WorkloadIdentity),
    /// No usable (kernel-observed, non-self-asserted) leader identity
    /// could be collected at establishment time. Never itself a reason
    /// to deny — see this enum's own doc.
    Unobserved,
}

/// The kernel-observed anchor a [`TrustedSession`] is bound to: a
/// session key plus reject-only corroborating evidence about the
/// process that was the session's leader at establishment time.
/// [`membership`] re-checks both on every use — this is what defeats a
/// PID/session-id-reuse attack after the original leader process has
/// exited (see [`WorkloadIdentity::compare_process`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct LocalSessionAnchor {
    pub key: SessionKey,
    pub leader: LeaderCorroboration,
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
    /// The host this session was established on (HORO-1278). Compared
    /// by [`membership`]/[`SessionAuthority::validate`] against a
    /// freshly observed [`HostId`] on every use — see that type's own
    /// doc for what this does and does not defend against.
    host: HostId,
    /// Write-only extension seam — see [`SessionNonce`]'s own doc. Never
    /// read back by this module; kept only so a `TrustedSession` carries
    /// the value a future hardware-backed strengthening would need.
    nonce: SessionNonce,
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
    pub fn host(&self) -> &HostId {
        &self.host
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
    /// The session's anchor sid is now observably occupied by a
    /// *different*, live process than the one recorded at establishment
    /// time ([`IdentityComparison::Different`]) — the sid was recycled.
    /// Reject-only, per [`LeaderCorroboration`]'s doc: the leader simply
    /// being unobservable (exited, or [`IdentityComparison::Indeterminate`])
    /// is never itself a reason to deny — only a confirmed contradiction
    /// is. Named `AnchorRecycled` (HORO-1278; was `AnchorGone`) to make
    /// that distinction unambiguous in the type itself.
    AnchorRecycled,
    /// A freshly observed [`HostId`] does not match the one recorded at
    /// establishment time (HORO-1278). Missing/unsupported host evidence
    /// is never itself a reason to deny — same reject-only discipline as
    /// [`LeaderCorroboration`].
    HostMismatch,
    Expired {
        expired_at: MonotonicTime,
    },
}

/// Why [`membership`] (or [`SessionAuthority::validate`]) reports
/// [`MembershipVerdict::NotMember`]. Server-internal/audit-facing only —
/// `Serialize` but not `Deserialize`, mirroring
/// [`SessionTerminationOutcome`]'s sibling wire-collapse discipline: a
/// client never sees this directly (see `eltanin-protocol`'s lossy
/// `DenialReason::NoTrustedSession` projection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotMemberReason {
    /// The peer's freshly collected [`SessionKey`] does not equal
    /// `session.anchor().key`.
    KeyMismatch,
    /// The peer's freshly collected uid does not equal
    /// [`TrustedSession::owner_uid`].
    OwnerUidMismatch,
    /// A freshly observed [`HostId`] does not equal
    /// [`TrustedSession::host`].
    HostMismatch,
    /// `now` is at or past [`TrustedSession::expires_at`]. Checked
    /// structurally inside `membership` itself (HORO-1278) — see that
    /// function's own doc for why this closes the previous dependency on
    /// `SessionState::reap` running first under the same lock.
    Expired { expired_at: MonotonicTime },
    /// The session's anchor sid is now observably occupied by a
    /// *different*, live process than the one recorded at establishment
    /// time — see [`LeaderCorroboration`]'s doc for why this is the
    /// *only* leader-related reason `membership` may ever deny.
    AnchorRecycled,
}

/// The result of [`membership`]. A rich enum, not a `bool`, following
/// this crate's established pattern (see
/// [`crate::identity::IdentityComparison`],
/// [`crate::policy::DecisionReason`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "verdict")]
pub enum MembershipVerdict {
    Member,
    NotMember {
        reason: NotMemberReason,
    },
    /// The evidence needed to decide membership could not be confirmed
    /// (missing/unsupported/self-asserted key/uid/host evidence).
    /// Callers must treat this identically to
    /// [`MembershipVerdict::NotMember`] — never as `Member` — but it is
    /// kept as its own case so an audit trail can distinguish "confirmed
    /// not a member" from "could not confirm."
    Indeterminate {
        reason: String,
    },
}

/// Unwrap one piece of [`Evidence`] for [`membership`]'s combined check,
/// or produce the [`MembershipVerdict::Indeterminate`] that evidence's
/// state demands. Not itself a security decision — every actual
/// equality/expiry/corroboration check still lives in `membership`
/// itself; this only removes the duplicated four-way `Evidence` match
/// that would otherwise appear three times (key, uid, host) and push
/// that one combined function over this crate's line-count lint.
fn require_present<'a, T>(
    evidence: &'a Evidence<T>,
    self_asserted_reason: &str,
    unsupported_reason: &str,
) -> Result<&'a T, MembershipVerdict> {
    match evidence {
        Evidence::Present {
            value,
            source: EvidenceSource::SelfAsserted,
        } => {
            let _ = value;
            Err(MembershipVerdict::Indeterminate {
                reason: self_asserted_reason.to_string(),
            })
        }
        Evidence::Present { value, .. } => Ok(value),
        Evidence::Missing { reason } => Err(MembershipVerdict::Indeterminate {
            reason: reason.clone(),
        }),
        Evidence::Unsupported => Err(MembershipVerdict::Indeterminate {
            reason: unsupported_reason.to_string(),
        }),
    }
}

/// Determine whether `peer_uid`/`peer_key`/`observed_host` (all freshly
/// collected for the requesting peer, at call time, by the caller) and
/// `observed_leader` (freshly collected for the sid recorded in
/// `session.anchor().key`) together prove that peer is a current member
/// of `session` at `now`.
///
/// This is deliberately the **one** combined signature: evidence
/// freshness, key/uid/host equality, expiry, and leader corroboration
/// are checked together, not as a lookup step followed by a separate
/// liveness check — see the module docs for why splitting it would
/// reintroduce the bug this function exists to prevent. (Its evidence
/// unwrapping is factored into a private `require_present` helper purely to satisfy
/// this crate's line-count lint — that helper makes no verdict of its
/// own beyond "could not confirm.")
///
/// Leader corroboration is **reject-only** — see [`LeaderCorroboration`]'s
/// own doc. `observed_leader`'s only power here is to *deny* via
/// [`NotMemberReason::AnchorRecycled`] when it confirms a different, live
/// process now occupies the recorded sid; it can never itself grant
/// membership, and its absence/indeterminacy never denies it.
#[must_use]
pub fn membership(
    session: &TrustedSession,
    peer_uid: &Evidence<u32>,
    peer_key: &Evidence<SessionKey>,
    observed_host: &Evidence<HostId>,
    observed_leader: &WorkloadIdentity,
    now: MonotonicTime,
) -> MembershipVerdict {
    let key = match require_present(
        peer_key,
        "peer session-key evidence was self-asserted",
        "session-key collection is unsupported on this platform",
    ) {
        Ok(key) => key,
        Err(verdict) => return verdict,
    };
    if *key != session.anchor.key {
        return MembershipVerdict::NotMember {
            reason: NotMemberReason::KeyMismatch,
        };
    }

    let uid = match require_present(
        peer_uid,
        "peer uid evidence was self-asserted",
        "uid collection is unsupported on this platform",
    ) {
        Ok(uid) => uid,
        Err(verdict) => return verdict,
    };
    if *uid != session.owner_uid {
        return MembershipVerdict::NotMember {
            reason: NotMemberReason::OwnerUidMismatch,
        };
    }

    let host = match require_present(
        observed_host,
        "peer host evidence was self-asserted",
        "host collection is unsupported on this platform",
    ) {
        Ok(host) => host,
        Err(verdict) => return verdict,
    };
    if *host != session.host {
        return MembershipVerdict::NotMember {
            reason: NotMemberReason::HostMismatch,
        };
    }

    if now >= session.expires_at {
        return MembershipVerdict::NotMember {
            reason: NotMemberReason::Expired {
                expired_at: session.expires_at,
            },
        };
    }

    // Leader corroboration is reject-only (HORO-1278) — see
    // `LeaderCorroboration`'s own doc. Absence/indeterminacy never
    // denies; only a confirmed `Different` process does.
    match &session.anchor.leader {
        LeaderCorroboration::Recorded(recorded) => {
            match recorded.compare_process(observed_leader) {
                IdentityComparison::Same | IdentityComparison::Indeterminate => {
                    MembershipVerdict::Member
                }
                IdentityComparison::Different => MembershipVerdict::NotMember {
                    reason: NotMemberReason::AnchorRecycled,
                },
            }
        }
        LeaderCorroboration::Unobserved => MembershipVerdict::Member,
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
    /// `scope`, for `owner_uid`, on `host`.
    ///
    /// `nonce` is generated by the caller (never by this crate — see
    /// [`SessionNonce::from_bytes`]'s own doc for why: this crate reads
    /// no non-deterministic external state itself, mirroring `now`
    /// already being injected rather than read from a clock here).
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
    // One parameter per field a `TrustedSession` actually needs — every
    // one is a distinct, independently-sourced piece of evidence (never
    // bundle-able into a single struct without reintroducing a
    // "partially built session" intermediate value, which this module's
    // "no public constructor outside `establish`" discipline
    // deliberately avoids).
    #[allow(clippy::too_many_arguments)]
    pub fn establish(
        &mut self,
        owner_uid: u32,
        anchor: LocalSessionAnchor,
        scope: SessionScope,
        intent: IntentProof,
        assurance: SessionAssurance,
        host: HostId,
        nonce: SessionNonce,
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
            host,
            nonce,
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
    /// termination, host, anchor-sid recycling (re-observed as
    /// `observed_leader`, never taken from `session` itself), then
    /// expiry — same check-order discipline as
    /// [`crate::lease::LeaseIssuer::validate`]. This is *not* a
    /// substitute for [`membership`]: `validate` never checks the
    /// requesting peer's own session-key/uid evidence, only whether the
    /// session itself is still administratively alive. See the module
    /// docs on why the agent's lazy-reaping sweep uses this and
    /// `membership` is reserved for actual admission decisions.
    ///
    /// Leader corroboration is reject-only here too (HORO-1278) — see
    /// [`LeaderCorroboration`]'s doc: a session whose anchor leader has
    /// simply become unobservable (the establishing CLI process
    /// exited — the expected, common case) is never itself
    /// administratively invalid; only a confirmed sid-recycling
    /// ([`IdentityComparison::Different`]) is. A consequence worth
    /// stating plainly: what now bounds a [`TrustedSession`]'s lifetime —
    /// and therefore `SessionState`'s memory — is TTL/expiry alone, not
    /// leader liveness. This is not a regression; it is exactly the
    /// founder's "explicit TTL/expiry" requirement (HORO-1278), made
    /// structural rather than incidental.
    #[must_use]
    pub fn validate(
        &self,
        session: &TrustedSession,
        observed_host: &Evidence<HostId>,
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
        if let Evidence::Present {
            value,
            source: source @ (EvidenceSource::KernelObserved | EvidenceSource::BestEffort),
        } = observed_host
        {
            let _ = source;
            if *value != session.host {
                return SessionValidity::HostMismatch;
            }
        }
        if let LeaderCorroboration::Recorded(recorded) = &session.anchor.leader {
            if recorded.compare_process(observed_leader) == IdentityComparison::Different {
                return SessionValidity::AnchorRecycled;
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

    const OWNER_UID: u32 = 1000;

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
                value: OWNER_UID,
                source: EvidenceSource::KernelObserved,
            },
            gid: Evidence::Unsupported,
            executable_path: Evidence::Unsupported,
            executable_hash: Evidence::Unsupported,
            ancestry: Vec::new(),
        }
    }

    /// A leader identity whose process cannot currently be observed at
    /// all (e.g. the establishing CLI process already exited) —
    /// `process_start` is `Missing`, so `compare_process` reports
    /// `Indeterminate` against it, never `Same`/`Different`.
    fn leader_unobservable(pid: u32) -> WorkloadIdentity {
        WorkloadIdentity {
            pid,
            process_start: Evidence::Missing {
                reason: "process exited".to_string(),
            },
            uid: Evidence::Unsupported,
            gid: Evidence::Unsupported,
            executable_path: Evidence::Unsupported,
            executable_hash: Evidence::Unsupported,
            ancestry: Vec::new(),
        }
    }

    fn matching_uid() -> Evidence<u32> {
        Evidence::Present {
            value: OWNER_UID,
            source: EvidenceSource::KernelObserved,
        }
    }

    fn host() -> HostId {
        HostId("test-host".to_string())
    }

    fn matching_host() -> Evidence<HostId> {
        Evidence::Present {
            value: host(),
            source: EvidenceSource::KernelObserved,
        }
    }

    fn nonce() -> SessionNonce {
        SessionNonce::from_bytes([7u8; 32])
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

    fn establish_with_leader(
        authority: &mut SessionAuthority,
        leader: LeaderCorroboration,
    ) -> TrustedSession {
        authority
            .establish(
                OWNER_UID,
                LocalSessionAnchor {
                    key: SessionKey(42),
                    leader,
                },
                scope(),
                IntentProof::LocalPeerPresence,
                SessionAssurance::LocalKernelSession,
                host(),
                nonce(),
                MonotonicTime::from_nanos(0),
                Duration::from_secs(60),
            )
            .unwrap()
    }

    fn establish_default(authority: &mut SessionAuthority) -> TrustedSession {
        establish_with_leader(authority, LeaderCorroboration::Recorded(leader(100, 999)))
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
            membership(
                &session,
                &matching_uid(),
                &matching_key,
                &matching_host(),
                &leader(100, 999),
                MonotonicTime::from_nanos(1),
            ),
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
            membership(
                &session,
                &matching_uid(),
                &wrong_key,
                &matching_host(),
                &leader(100, 999),
                MonotonicTime::from_nanos(1),
            ),
            MembershipVerdict::NotMember {
                reason: NotMemberReason::KeyMismatch
            }
        );
    }

    #[test]
    fn membership_rejects_dead_leader_reuse_even_with_matching_key() {
        // Same pid, different start token: the original leader exited and
        // pid 100 was reused by an *unrelated, live* later process — a
        // confirmed contradiction (`IdentityComparison::Different`), the
        // one case `LeaderCorroboration`'s reject-only contract actually
        // denies on. Matching the session key alone must not be
        // sufficient.
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let matching_key = Evidence::Present {
            value: SessionKey(42),
            source: EvidenceSource::KernelObserved,
        };
        assert_eq!(
            membership(
                &session,
                &matching_uid(),
                &matching_key,
                &matching_host(),
                &leader(100, 111),
                MonotonicTime::from_nanos(1),
            ),
            MembershipVerdict::NotMember {
                reason: NotMemberReason::AnchorRecycled
            }
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
            membership(
                &session,
                &matching_uid(),
                &self_asserted,
                &matching_host(),
                &leader(100, 999),
                MonotonicTime::from_nanos(1),
            ),
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
            membership(
                &session,
                &matching_uid(),
                &missing,
                &matching_host(),
                &leader(100, 999),
                MonotonicTime::from_nanos(1),
            ),
            MembershipVerdict::Indeterminate { .. }
        ));
    }

    /// Bug fix (HORO-1278): `owner_uid` was stored on `TrustedSession`
    /// but never compared by `membership` at all.
    #[test]
    fn membership_requires_matching_owner_uid() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let matching_key = Evidence::Present {
            value: SessionKey(42),
            source: EvidenceSource::KernelObserved,
        };
        let wrong_uid = Evidence::Present {
            value: OWNER_UID + 1,
            source: EvidenceSource::KernelObserved,
        };
        assert_eq!(
            membership(
                &session,
                &wrong_uid,
                &matching_key,
                &matching_host(),
                &leader(100, 999),
                MonotonicTime::from_nanos(1),
            ),
            MembershipVerdict::NotMember {
                reason: NotMemberReason::OwnerUidMismatch
            }
        );
    }

    #[test]
    fn membership_missing_uid_evidence_is_indeterminate() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let matching_key = Evidence::Present {
            value: SessionKey(42),
            source: EvidenceSource::KernelObserved,
        };
        assert!(matches!(
            membership(
                &session,
                &Evidence::Unsupported,
                &matching_key,
                &matching_host(),
                &leader(100, 999),
                MonotonicTime::from_nanos(1),
            ),
            MembershipVerdict::Indeterminate { .. }
        ));
    }

    #[test]
    fn membership_requires_matching_host() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let matching_key = Evidence::Present {
            value: SessionKey(42),
            source: EvidenceSource::KernelObserved,
        };
        let wrong_host = Evidence::Present {
            value: HostId("other-host".to_string()),
            source: EvidenceSource::KernelObserved,
        };
        assert_eq!(
            membership(
                &session,
                &matching_uid(),
                &matching_key,
                &wrong_host,
                &leader(100, 999),
                MonotonicTime::from_nanos(1),
            ),
            MembershipVerdict::NotMember {
                reason: NotMemberReason::HostMismatch
            }
        );
    }

    #[test]
    fn membership_missing_host_evidence_is_indeterminate() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let matching_key = Evidence::Present {
            value: SessionKey(42),
            source: EvidenceSource::KernelObserved,
        };
        assert!(matches!(
            membership(
                &session,
                &matching_uid(),
                &matching_key,
                &Evidence::Unsupported,
                &leader(100, 999),
                MonotonicTime::from_nanos(1),
            ),
            MembershipVerdict::Indeterminate { .. }
        ));
    }

    /// Pins a founder-mandated constraint verbatim (HORO-1278): "PID/
    /// process lifetime must NOT be the primary session identity." A
    /// session's establishing CLI process is *expected* to exit almost
    /// immediately — an absent/unobservable leader must never itself
    /// deny membership. If this test is ever changed to expect denial,
    /// that is a regression of the founder's explicit requirement, not a
    /// hardening.
    #[test]
    fn absent_leader_observation_does_not_deny() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let matching_key = Evidence::Present {
            value: SessionKey(42),
            source: EvidenceSource::KernelObserved,
        };
        assert_eq!(
            membership(
                &session,
                &matching_uid(),
                &matching_key,
                &matching_host(),
                &leader_unobservable(100),
                MonotonicTime::from_nanos(1),
            ),
            MembershipVerdict::Member
        );
    }

    #[test]
    fn unobserved_leader_at_establishment_does_not_deny() {
        let mut authority = authority();
        let session = establish_with_leader(&mut authority, LeaderCorroboration::Unobserved);
        let matching_key = Evidence::Present {
            value: SessionKey(42),
            source: EvidenceSource::KernelObserved,
        };
        // Even a freshly observed leader that would, if `Recorded`, have
        // been a confirmed `Different` must not deny when the session
        // never recorded a leader to compare against at all.
        assert_eq!(
            membership(
                &session,
                &matching_uid(),
                &matching_key,
                &matching_host(),
                &leader(999, 1),
                MonotonicTime::from_nanos(1),
            ),
            MembershipVerdict::Member
        );
    }

    #[test]
    fn membership_rejects_an_expired_session_on_its_own() {
        // No `SessionState::reap` call anywhere in this test — expiry is
        // structural inside `membership` itself (HORO-1278), not
        // dependent on a reap sweep having already run under the same
        // lock.
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let matching_key = Evidence::Present {
            value: SessionKey(42),
            source: EvidenceSource::KernelObserved,
        };
        let at_expiry =
            MonotonicTime::from_nanos(u64::try_from(Duration::from_secs(60).as_nanos()).unwrap());
        assert_eq!(
            membership(
                &session,
                &matching_uid(),
                &matching_key,
                &matching_host(),
                &leader(100, 999),
                at_expiry,
            ),
            MembershipVerdict::NotMember {
                reason: NotMemberReason::Expired {
                    expired_at: session.expires_at()
                }
            }
        );
    }

    #[test]
    fn validate_reports_valid_before_expiry() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let validity = authority.validate(
            &session,
            &matching_host(),
            &leader(100, 999),
            MonotonicTime::from_nanos(1),
        );
        assert!(matches!(validity, SessionValidity::Valid { .. }));
    }

    #[test]
    fn validate_reports_expired_after_ttl() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let validity = authority.validate(
            &session,
            &matching_host(),
            &leader(100, 999),
            MonotonicTime::from_nanos(u64::try_from(Duration::from_secs(60).as_nanos()).unwrap()),
        );
        assert!(matches!(validity, SessionValidity::Expired { .. }));
    }

    #[test]
    fn validate_reports_anchor_recycled_when_leader_is_confirmed_different() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let validity = authority.validate(
            &session,
            &matching_host(),
            &leader(100, 111),
            MonotonicTime::from_nanos(1),
        );
        assert_eq!(validity, SessionValidity::AnchorRecycled);
    }

    /// Bug fix (HORO-1278): a session whose anchor leader has simply
    /// become unobservable (the establishing CLI process exited — the
    /// expected, common case) must remain administratively `Valid`, not
    /// be reaped as `AnchorRecycled`/`AnchorGone`. This is the change
    /// that makes lazy reaping stop deleting exactly the sessions this
    /// ticket exists to preserve.
    #[test]
    fn validate_does_not_reject_when_leader_is_simply_unobservable() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let validity = authority.validate(
            &session,
            &matching_host(),
            &leader_unobservable(100),
            MonotonicTime::from_nanos(1),
        );
        assert!(matches!(validity, SessionValidity::Valid { .. }));
    }

    #[test]
    fn validate_reports_host_mismatch() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let wrong_host = Evidence::Present {
            value: HostId("other-host".to_string()),
            source: EvidenceSource::KernelObserved,
        };
        let validity = authority.validate(
            &session,
            &wrong_host,
            &leader(100, 999),
            MonotonicTime::from_nanos(1),
        );
        assert_eq!(validity, SessionValidity::HostMismatch);
    }

    #[test]
    fn validate_ignores_missing_host_evidence() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let validity = authority.validate(
            &session,
            &Evidence::Unsupported,
            &leader(100, 999),
            MonotonicTime::from_nanos(1),
        );
        assert!(matches!(validity, SessionValidity::Valid { .. }));
    }

    #[test]
    fn validate_reports_terminated_after_terminate() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        assert_eq!(
            authority.terminate(session.id()),
            SessionTerminationOutcome::Terminated
        );
        let validity = authority.validate(
            &session,
            &matching_host(),
            &leader(100, 999),
            MonotonicTime::from_nanos(1),
        );
        assert_eq!(validity, SessionValidity::Terminated);
    }

    #[test]
    fn validate_reports_foreign_issuer_after_restart() {
        let mut authority = authority();
        let session = establish_default(&mut authority);
        let restarted =
            SessionAuthority::new(IssuerInstanceId::new("agent-2"), Duration::from_secs(3600));
        let validity = restarted.validate(
            &session,
            &matching_host(),
            &leader(100, 999),
            MonotonicTime::from_nanos(1),
        );
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
            OWNER_UID,
            LocalSessionAnchor {
                key: SessionKey(1),
                leader: LeaderCorroboration::Recorded(leader(1, 1)),
            },
            scope(),
            IntentProof::LocalPeerPresence,
            SessionAssurance::LocalKernelSession,
            host(),
            nonce(),
            MonotonicTime::from_nanos(0),
            Duration::ZERO,
        );
        assert_eq!(result, Err(SessionError::NonPositiveTtl));
    }

    #[test]
    fn establish_rejects_ttl_over_maximum() {
        let mut authority = authority();
        let result = authority.establish(
            OWNER_UID,
            LocalSessionAnchor {
                key: SessionKey(1),
                leader: LeaderCorroboration::Recorded(leader(1, 1)),
            },
            scope(),
            IntentProof::LocalPeerPresence,
            SessionAssurance::LocalKernelSession,
            host(),
            nonce(),
            MonotonicTime::from_nanos(0),
            Duration::from_secs(999_999),
        );
        assert!(matches!(
            result,
            Err(SessionError::TtlExceedsMaximum { .. })
        ));
    }
}
