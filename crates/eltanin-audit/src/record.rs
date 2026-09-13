//! The audit record schema (F-M1-006 correlation seam consumer,
//! F-M1-009, HORO-824).
//!
//! # The load-bearing structural fact of this module
//!
//! [`AuditRecord`] derives `Deserialize` — it must be readable back off
//! disk for [`crate::explain`] to work at all. Every authority-bearing
//! type in `eltanin-core` — `ComputeLease`, `PolicyDecision`,
//! `DecisionReason`, `PolicyProvenance`, `LeaseValidity` — is
//! `Serialize`-only by construction, and `LeaseError` has no serde
//! derives at all. Embedding any of them here directly would fail to
//! compile. This is the same argument `eltanin-protocol`'s
//! `AgentResponse` module doc makes, reused here: "audit records cannot
//! be used as authorization input merely by editing/replaying them" is
//! enforced by the compiler, not by review discipline. This module
//! therefore hand-writes a plain, `Deserialize`-safe mirror for each
//! authority-bearing type it needs to record — see the `Recorded*`
//! types below. `eltanin_core::identity::ExecutionContext` and
//! `WorkloadIdentity` need no mirror: they are observation records
//! (already `Deserialize`, like `eltanin_core::provenance::ProvenanceRecord`
//! embeds them directly), not authorization artifacts.

use serde::{Deserialize, Serialize};

use eltanin_backend::contract::BackendError;
use eltanin_core::approval::{ApprovalDisposition, ApprovalId};
use eltanin_core::delegation::ExceededBound;
use eltanin_core::envelope::DOMAIN_SCHEMA_VERSION;
use eltanin_core::identity::{Evidence, ExecutionContext};
use eltanin_core::lease::{IssuerInstanceId, LeaseId, MonotonicTime, RevocationOutcome};
use eltanin_core::policy::{Effect, PolicyId, RuleId};
use eltanin_core::resource::{Action, EnforcementResult, ResourceIdentity};
use eltanin_core::session::{SessionId, SessionTerminationOutcome};
use eltanin_protocol::response::AgentResponse;
use std::collections::BTreeSet;
use std::time::Duration;

/// Identifies one audit record. Minted only by
/// [`crate::sink::AuditFileSink`] — never by a caller — so a record's id
/// cannot be forged or backdated. `instance` is the agent's own
/// [`IssuerInstanceId`] (its kernel-grounded restart epoch): records
/// from different agent lifetimes never collide, and `sequence` is only
/// ever meaningful compared within the same `instance`, mirroring
/// `MonotonicTime`'s own restart discipline.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditEventId {
    pub instance: IssuerInstanceId,
    pub sequence: u64,
}

impl std::fmt::Display for AuditEventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}", self.instance.as_str(), self.sequence)
    }
}

/// A wall-clock reading, recorded as evidence of *when* — never compared
/// against a lease's expiry, which is `MonotonicTime`'s job. Wall clocks
/// can move backward (NTP correction, suspend/resume); this type exists
/// so that fact can never silently affect an authorization decision, the
/// same reasoning `eltanin_core::lease`'s module docs give for banning
/// `SystemTime::now()` there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WallClockTime {
    pub unix_secs: i64,
    pub nanos: u32,
}

/// A source of [`WallClockTime`] readings, injected so tests can control
/// it — mirrors `eltanin_agent::authz::Clock`'s rationale exactly, one
/// level up (wall clock instead of monotonic).
pub trait AuditClock: Send + Sync {
    fn now(&self) -> WallClockTime;
}

/// Reads the real system clock.
pub struct SystemWallClock;

impl AuditClock for SystemWallClock {
    fn now(&self) -> WallClockTime {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        WallClockTime {
            unix_secs: i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
            nanos: now.subsec_nanos(),
        }
    }
}

/// Which wire operation this record reports on — mirrors
/// `eltanin_agent::authz::event::Operation`, but this crate cannot
/// depend on `eltanin-agent` (see the crate-level docs on dependency
/// direction), so it is a plain, independent copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedOperation {
    RequestLease,
    ReleaseLease,
    AgentStatus,
    CreateSession,
    ListSessions,
    TerminateSession,
    Approve,
    ListApprovals,
    ForgetApproval,
}

/// The client-asserted request parameters — a distinct trust class from
/// [`RecordedPeer`]: default-deny policy can only narrow what these
/// parameters ask for, never grant it, but they are still what was
/// *asked*, not what was *observed*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "op")]
pub enum RecordedRequest {
    RequestLease {
        resource: ResourceIdentity,
        action: Action,
    },
    ReleaseLease {
        lease_id: LeaseId,
    },
    AgentStatus,
    CreateSession {
        resources: Vec<ResourceIdentity>,
        ttl: Duration,
    },
    ListSessions,
    TerminateSession,
    Approve {
        resource: ResourceIdentity,
        action: Action,
        disposition: ApprovalDisposition,
    },
    ListApprovals,
    ForgetApproval {
        id: ApprovalId,
    },
}

/// Mirror of `eltanin_core::peer::PeerCredential` — plain data, no
/// serde derives on the original (it isn't meant to cross a wire), so
/// this crate keeps its own `Deserialize`-safe copy rather than adding
/// serde to a crate this one cannot depend on anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedPeerCredential {
    pub pid: u32,
    pub effective_uid: u32,
    pub effective_gid: u32,
}

/// Mirror of `eltanin_core::peer::PeerConsistency`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "consistency")]
pub enum RecordedPeerConsistency {
    Consistent,
    CredentialDivergence {
        peer_effective_uid: u32,
        observed_real_uid: Evidence<u32>,
        observed_effective_uid: Evidence<u32>,
    },
    PeerUnmapped,
    Indeterminate {
        reason: String,
    },
}

/// The peer as observed at connect time, regardless of outcome — an
/// audit trail needs the identity behind a *refused* request as much as
/// a granted one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedPeer {
    pub credential: RecordedPeerCredential,
    pub consistency: RecordedPeerConsistency,
    pub observed: ExecutionContext,
}

/// Mirror of `eltanin_core::policy::PolicyProvenance` — already
/// `Serialize`-only there (deliberately, so nothing reconstructs a
/// `PolicySet` binding from bytes), but every field is plain data, so a
/// `Deserialize`-safe copy here is exactly as safe as it looks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedPolicyProvenance {
    pub policy_id: PolicyId,
    pub policy_revision: u32,
    pub schema_version: u16,
}

/// Mirror of `eltanin_core::policy::DecisionReason`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum RecordedDecisionReason {
    NoMatchingRule,
    ExplicitAllow {
        matched_rules: BTreeSet<RuleId>,
    },
    ExplicitDeny {
        matched_rules: BTreeSet<RuleId>,
        overridden_allow_rules: BTreeSet<RuleId>,
    },
    IndeterminateEvidence {
        rules: BTreeSet<RuleId>,
    },
}

/// Mirror of `eltanin_core::policy::PolicyDecision` — the record
/// version, `Deserialize`-safe because it is data, never fed back into
/// `PolicySet::evaluate` or any lease call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedPolicyDecision {
    pub effect: Effect,
    pub reason: RecordedDecisionReason,
    pub policy: RecordedPolicyProvenance,
}

/// Mirror of `eltanin_core::lease::LeaseError` (which has no serde
/// derives at all).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "error")]
pub enum RecordedLeaseError {
    Denied {
        decision: RecordedPolicyDecision,
    },
    NonPositiveTtl,
    TtlExceedsMaximum {
        requested: Duration,
        maximum: Duration,
    },
    ExpiryOverflow,
}

/// Mirror of `eltanin_core::lease::LeaseValidity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "validity")]
pub enum RecordedLeaseValidity {
    Valid { remaining: Duration },
    ForeignIssuer { issued_by: IssuerInstanceId },
    Revoked,
    ResourceMismatch,
    ActionMismatch,
    WorkloadMismatch,
    WorkloadIndeterminate,
    ExecutableMismatch,
    Expired { expired_at: MonotonicTime },
}

/// Mirror of `eltanin_agent::authz::session::SessionAdmissionError`
/// (which itself wraps `eltanin_core::session::SessionError` and
/// `eltanin_core::session::EmptyScope`, neither of which has serde
/// derives) — flattened to one enum rather than nested, since both
/// sources together are only four cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "error")]
pub enum RecordedSessionAdmissionError {
    EmptyScope,
    NonPositiveTtl,
    TtlExceedsMaximum {
        requested: Duration,
        maximum: Duration,
    },
    ExpiryOverflow,
}

/// The delegation-specific provenance of one `GrantedByDelegation`
/// outcome — deliberately minimal (not the full `DelegationGrant`,
/// which is not `Deserialize`/audit-safe by design, see
/// `eltanin_core::delegation`'s module docs): just enough for
/// `crate::explain` to reconstruct the delegation chain from a sequence
/// of audit records, never enough to reconstruct a usable grant from the
/// log alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedDelegation {
    pub parent_lease: LeaseId,
    pub depth: u8,
    pub holder_pid: u32,
}

/// Full internal fidelity of what happened — the record-schema
/// counterpart of `eltanin_agent::authz::event::AuthorizationOutcome`,
/// with every non-`Deserialize`-safe field replaced by its `Recorded*`
/// mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum RecordedOutcome {
    Granted {
        lease_id: LeaseId,
        expires_at: MonotonicTime,
    },
    PolicyDenied {
        decision: RecordedPolicyDecision,
    },
    PeerNotAuthorizable,
    LeaseIssueFailed {
        error: RecordedLeaseError,
    },
    EnforcementRefused {
        result: EnforcementResult,
    },
    BackendFailed {
        error: BackendError,
    },
    CapacityExhausted {
        outstanding: usize,
    },
    Released {
        revocation: RevocationOutcome,
        backend: Option<EnforcementResult>,
    },
    ReleaseRefused {
        validity: RecordedLeaseValidity,
    },
    ReleaseUnknownLease,
    StatusReported,
    SessionRequired,
    SessionEstablished {
        session_id: SessionId,
        expires_at: MonotonicTime,
    },
    SessionEstablishFailed {
        error: RecordedSessionAdmissionError,
    },
    SessionListed {
        sessions: Vec<SessionId>,
    },
    SessionTerminated {
        // Named `termination_outcome`, not `outcome` — this enum's own
        // internal tag key is literally `"outcome"`
        // (`#[serde(tag = "outcome")]` above), and serde rejects a
        // variant field name colliding with the tag.
        termination_outcome: SessionTerminationOutcome,
    },
    SessionNotFound,
    ApprovalRequired,
    ApprovalDenied,
    ApprovalGateObserveFailed {
        error: BackendError,
    },
    ApprovalRecorded {
        id: ApprovalId,
        resource: ResourceIdentity,
        action: Action,
        disposition: ApprovalDisposition,
    },
    ApprovalListed {
        approvals: Vec<ApprovalId>,
    },
    ApprovalForgotten {
        forgotten: bool,
    },
    ApprovalInternalError {
        reason: String,
    },
    /// A `RequestLease` was admitted via the delegation gate (F-M2-003,
    /// HORO-793) — the approval gate had refused it, and a matching
    /// `DelegationGrant` admitted it instead. Never the plain `Granted`
    /// variant: keeping this separate means an audit query can tell a
    /// delegated grant from an ordinary one without inspecting anything
    /// else in the record.
    GrantedByDelegation {
        lease_id: LeaseId,
        expires_at: MonotonicTime,
        delegation: RecordedDelegation,
    },
    /// The delegation gate itself found no admitting grant — reported
    /// only for the rich audit trail; the client-facing wire response is
    /// identical to an ordinary `ApprovalRequired` (see
    /// `eltanin_agent::authz`'s module docs on this).
    DelegationRefused {
        exceeded: BTreeSet<ExceededBound>,
    },
    /// The delegation gate could not resolve at least one dimension from
    /// available evidence — fails closed to the same client-facing
    /// `ApprovalRequired` as `DelegationRefused`.
    DelegationIndeterminate {
        reason: String,
    },
}

/// One audit record: what was asked, who asked (as observed), what
/// actually happened, and what the client actually saw. Serialized one
/// per line as `Versioned<AuditRecord>` JSON — see
/// [`crate::sink::AuditFileSink`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub event_id: AuditEventId,
    pub recorded_at: WallClockTime,
    pub operation: RecordedOperation,
    pub requested: RecordedRequest,
    pub peer: RecordedPeer,
    pub outcome: RecordedOutcome,
    pub response: AgentResponse,
}

impl AuditRecord {
    /// This record's schema version — always
    /// [`eltanin_core::envelope::DOMAIN_SCHEMA_VERSION`] for a freshly
    /// constructed record; a record read back from disk carries whatever
    /// version its `Versioned` envelope named, which
    /// [`crate::explain::read_log`] checks explicitly.
    #[must_use]
    pub fn current_schema_version() -> u16 {
        DOMAIN_SCHEMA_VERSION
    }

    /// The [`LeaseId`] this record concerns, if any — a `Granted`
    /// outcome's own id, or a `ReleaseLease` request's target id. This
    /// is how [`crate::explain::Selector::Lease`] links a grant record
    /// to its later release record: both name the same `LeaseId`, one as
    /// the outcome, the other as the request.
    #[must_use]
    pub fn lease_id(&self) -> Option<&LeaseId> {
        match (&self.outcome, &self.requested) {
            (
                RecordedOutcome::Granted { lease_id, .. }
                | RecordedOutcome::GrantedByDelegation { lease_id, .. },
                _,
            )
            | (_, RecordedRequest::ReleaseLease { lease_id }) => Some(lease_id),
            _ => None,
        }
    }
}
