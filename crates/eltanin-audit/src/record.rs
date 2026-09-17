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
use eltanin_core::risk::RiskSignal;
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
    /// Reserved for shadow-enforcement mode (F-M2-006, HORO-796 subtask
    /// 3): what *would* have been granted had the agent been enforcing
    /// rather than observing. Never produced by any code path in this
    /// subtask — the type exists now so the schema bump (`DOMAIN_SCHEMA_VERSION`
    /// 5 → 6) covers the whole HORO-796 ticket in one bump, per that
    /// bump's own rationale.
    WouldGrant {
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
    /// The risk layer (F-M2-004, HORO-794) classified an approval/
    /// delegation refusal as remediable via step-up — the client-facing
    /// wire response is `DenialReason::StepUpRequired`; `signals` names
    /// every fired `RiskSignal`, recorded here for the audit trail only.
    StepUpRequired {
        signals: BTreeSet<RiskSignal>,
    },
    /// The risk layer (F-M2-004, HORO-794) classified an approval/
    /// delegation refusal as hard-denied — the client-facing wire
    /// response is `DenialReason::RiskDenied`; `signals` names every
    /// fired `RiskSignal` (at least one of which is configured
    /// `SignalDisposition::Deny`).
    RiskDenied {
        signals: BTreeSet<RiskSignal>,
    },
}

/// Which enforcement posture was active when a record was produced.
/// `Shadow` is reserved for HORO-796 subtask 3 (shadow-enforcement
/// mode) — nothing in this subtask ever produces it; every record
/// constructed today is `Enforce`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedEnforcementMode {
    Enforce,
    Shadow,
}

/// One audit record: what was asked, who asked (as observed), what
/// actually happened, and what the client actually saw. Serialized one
/// per line, wrapped in [`LogEntry::Decision`] then `Versioned<LogEntry>`
/// JSON — see [`crate::sink::AuditFileSink`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub event_id: AuditEventId,
    pub recorded_at: WallClockTime,
    pub operation: RecordedOperation,
    pub requested: RecordedRequest,
    pub peer: RecordedPeer,
    pub outcome: RecordedOutcome,
    pub response: AgentResponse,
    /// Which enforcement posture produced this record. Always `Enforce`
    /// today — populating `Shadow` is HORO-796 subtask 3's job.
    pub mode: RecordedEnforcementMode,
    /// The [`SessionId`] active for this request, when one is. Lives at
    /// the top level (not nested in a grant-specific outcome variant) so
    /// it can eventually be populated for approval/delegation/risk
    /// refusals too, not just successful grants — see
    /// `RecordedOutcome::SessionEstablished`, which already embeds a
    /// bare `SessionId` the same way; that type is a correlation
    /// identifier only, "not a capability or a secret" per its own
    /// module docs, so embedding it here needs no new safety argument.
    /// Always `None` today — actual population is later HORO-796
    /// subtask wiring.
    pub session: Option<SessionId>,
}

/// One agent-emitted event that is not itself a request/response
/// decision — e.g. a lease expiring on its own or the audit log
/// rotating. Shares [`AuditEventId`]'s sequence space with
/// [`AuditRecord`] (both are minted the same way, by
/// [`crate::sink::AuditFileSink`]), so a gap in one is a gap in the
/// other and both are visible to [`crate::explain`]'s gap detection.
///
/// Nothing in this subtask constructs a
/// [`RecordedAgentEvent::LeaseExpired`] outside of tests — emitting it
/// from the agent on an actual lease expiry is HORO-796 subtask 2's job.
/// [`RecordedAgentEvent::AuditLogRotated`] *is* produced by this
/// subtask, by [`crate::sink::AuditFileSink`]'s own rotation logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentEventRecord {
    pub event_id: AuditEventId,
    pub recorded_at: WallClockTime,
    pub event: RecordedAgentEvent,
}

/// What kind of agent-emitted event [`AgentEventRecord`] carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "event")]
pub enum RecordedAgentEvent {
    /// A lease expired on its own (no `ReleaseLease` request). `backend`
    /// is `None` when no teardown was attempted because another live
    /// lease still names the same resource.
    LeaseExpired {
        lease_id: LeaseId,
        resource: ResourceIdentity,
        expired_at: MonotonicTime,
        backend: Option<EnforcementResult>,
    },
    /// The audit log rotated to a new generation. Always the first entry
    /// written into the new generation — see
    /// [`crate::sink::AuditFileSink`]'s rotation docs.
    AuditLogRotated {
        /// This marker's own sequence number in the new generation.
        rotated_at_sequence: u64,
        /// The *previous* rotation's `rotated_at_sequence - 1` — the
        /// highest sequence number that generation, now overwritten,
        /// ever held. `None` on the very first rotation, when nothing
        /// has been discarded yet.
        discarded_through_sequence: Option<u64>,
    },
}

/// One line of the audit log: either a request/response decision
/// ([`AuditRecord`]) or an agent-emitted event ([`AgentEventRecord`]).
/// Internally tagged on `"record"` — for [`LogEntry::Decision`] this
/// adds exactly one new key (`"record":"decision"`) to the wire shape
/// [`AuditRecord`] already had; every other field is unchanged. This is
/// the structural fix that lets [`crate::explain::read_log`] tell a
/// decision from an agent event without probing the payload's shape.
// `AuditRecord` (the `Decision` arm) is the overwhelmingly common case —
// every request/response decision produces one, while `Agent` is rare
// (only a log rotation or a future lease-expiry event). Boxing the large
// variant to satisfy clippy's `large_enum_variant` would move a heap
// allocation onto that hot, common path purely to shrink the size of the
// rare one — the wrong trade-off here, so this is a deliberate, narrow
// suppression rather than an oversight.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "record")]
pub enum LogEntry {
    Decision(AuditRecord),
    Agent(AgentEventRecord),
}

impl LogEntry {
    /// The [`AuditEventId`] of this entry, regardless of which arm it
    /// is — both arms carry one, minted the same way by
    /// [`crate::sink::AuditFileSink`].
    #[must_use]
    pub fn event_id(&self) -> &AuditEventId {
        match self {
            LogEntry::Decision(record) => &record.event_id,
            LogEntry::Agent(event) => &event.event_id,
        }
    }
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
