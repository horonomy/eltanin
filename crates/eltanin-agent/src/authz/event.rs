//! Internal-fidelity authorization events — the correlation seam for
//! F-M1-009 (Audit & Explain, not yet started) (HORO-840).
//!
//! `eltanin-protocol`'s wire responses are deliberately lossy (see
//! `crates/eltanin-protocol/src/response.rs`'s module docs): `ErrorCode`
//! carries no free-text detail, `DenialReason`/`ReleaseOutcome` collapse
//! several distinct internal outcomes into one wire variant. That detail
//! has to go *somewhere* or AC #3 ("Backend/policy/lease errors fail
//! safely and remain explainable") is unmet by a client-visible response
//! alone. [`AuthorizationEvent`] is that somewhere: full internal
//! fidelity, recorded once per request, entirely off the wire.
//!
//! This module implements no audit trail itself — [`NullSink`] is the
//! default, [`StderrSink`] the only real one. F-M1-009 owns turning
//! these events into a persistent, queryable trail; this seam only
//! guarantees the information needed to do that is captured now, so a
//! future ticket does not have to retrofit richer internal state into
//! [`crate::authz`] to get it.

use eltanin_core::approval::{ApprovalDisposition, ApprovalId};
use eltanin_core::delegation::ExceededBound;
use eltanin_core::lease::{LeaseError, LeaseId, LeaseValidity, MonotonicTime, RevocationOutcome};
use eltanin_core::peer::PeerContext;
use eltanin_core::policy::PolicyDecision;
use eltanin_core::resource::{Action, EnforcementResult, ResourceIdentity};
use eltanin_core::session::{SessionId, SessionTerminationOutcome};

use eltanin_backend::contract::BackendError;
use eltanin_protocol::request::ClientRequest;
use eltanin_protocol::response::AgentResponse;

use super::session::SessionAdmissionError;

/// Which wire operation this event reports on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
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

/// What actually happened internally, at full fidelity — the richer
/// counterpart to the deliberately lossy wire response.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthorizationOutcome {
    Granted {
        lease_id: LeaseId,
        expires_at: MonotonicTime,
    },
    PolicyDenied {
        decision: PolicyDecision,
    },
    PeerNotAuthorizable,
    LeaseIssueFailed {
        error: LeaseError,
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
        validity: LeaseValidity,
    },
    ReleaseUnknownLease,
    StatusReported,
    /// The pre-policy session-admission gate refused a `RequestLease`
    /// because [`crate::authz::AuthorizationConfig`]'s
    /// `session_requirement` is `Required` and the peer verified as no
    /// session's member. Reported *before* policy is ever consulted —
    /// see `crate::authz`'s module docs on why this must never be
    /// conflated with a `PolicyDenied` outcome.
    SessionRequired,
    SessionEstablished {
        session_id: SessionId,
        expires_at: MonotonicTime,
    },
    SessionEstablishFailed {
        error: SessionAdmissionError,
    },
    /// The verified sessions returned to a `ListSessions` call — at most
    /// one, today.
    SessionListed {
        sessions: Vec<SessionId>,
    },
    SessionTerminated {
        outcome: SessionTerminationOutcome,
    },
    /// `TerminateSession` (or a lookup this crate performed on its
    /// behalf) found no session the calling peer verifies as a member
    /// of.
    SessionNotFound,
    /// The pre-policy approval-admission gate (F-M2-002, HORO-792)
    /// found no [`eltanin_core::approval::RecallVerdict::Matched`]
    /// non-`Deny` candidate for this `RequestLease`. Reported *before*
    /// policy is ever consulted, same structural placement as
    /// [`AuthorizationOutcome::SessionRequired`].
    ApprovalRequired,
    /// The approval-admission gate matched a `Deny` disposition
    /// (deny-overrides). Also pre-policy.
    ApprovalDenied,
    /// The approval gate's own capability re-check
    /// (`ComputeBackend::observe`) failed — an internal error, not a
    /// policy or approval decision.
    ApprovalGateObserveFailed {
        error: BackendError,
    },
    ApprovalRecorded {
        id: ApprovalId,
        resource: ResourceIdentity,
        action: Action,
        disposition: ApprovalDisposition,
    },
    /// The calling peer's own recorded approvals, returned by
    /// `ListApprovals`.
    ApprovalListed {
        approvals: Vec<ApprovalId>,
    },
    ApprovalForgotten {
        forgotten: bool,
    },
    /// `eltanin approve` could not complete for a reason that is neither
    /// a policy nor an approval decision (a monotonic-clock overflow
    /// computing a `Once` expiry, or a durable-store persist failure —
    /// see `crate::authz::AuthorizationHandler::handle_approve`).
    ApprovalInternalError {
        reason: String,
    },
    /// The delegation gate (F-M2-003, HORO-793) admitted a `RequestLease`
    /// the approval gate had refused. Reported *after* a real lease was
    /// issued/enforced — never a claim of authority the backend has not
    /// actually granted.
    GrantedByDelegation {
        lease_id: LeaseId,
        expires_at: MonotonicTime,
        parent_lease: LeaseId,
        depth: u8,
        holder_pid: u32,
    },
    /// The delegation gate found no admitting grant for this
    /// `RequestLease`. Client-facing wire response is identical to
    /// `ApprovalRequired` — see `crate::authz`'s module docs.
    DelegationRefused {
        exceeded: std::collections::BTreeSet<ExceededBound>,
    },
    /// The delegation gate could not resolve at least one dimension from
    /// available evidence.
    DelegationIndeterminate {
        reason: String,
    },
}

/// One authorization event: what was asked, who asked (as observed —
/// regardless of outcome), what actually happened, and what the client
/// actually saw. `peer` is recorded even when the outcome is a denial —
/// an audit trail needs the identity of a *refused* request as much as
/// a granted one. `request` (added for F-M1-009/HORO-824) is what was
/// actually asked — without it, a denied record would say "denied by
/// rule X" without naming what was denied, since `PolicyDecision` alone
/// carries effect/reason/policy only.
pub struct AuthorizationEvent<'a> {
    pub operation: Operation,
    pub request: &'a ClientRequest,
    pub peer: &'a PeerContext,
    pub outcome: &'a AuthorizationOutcome,
    pub response: &'a AgentResponse,
}

/// Records [`AuthorizationEvent`]s. Called exactly once per request, at
/// the end of `crate::authz::AuthorizationHandler`'s `RequestHandler::handle` impl, after
/// every lock this crate holds internally has already been released.
pub trait EventSink: Send + Sync {
    fn record(&self, event: &AuthorizationEvent<'_>);
}

/// Discards every event. The default when no richer sink is wired in.
pub struct NullSink;

impl EventSink for NullSink {
    fn record(&self, _event: &AuthorizationEvent<'_>) {}
}

/// Debug-formats each event to stderr — captured by `journald`/systemd
/// under a normal service unit, with no new logging dependency. Not an
/// audit trail (no persistence, no structure a query can rely on): a
/// stopgap for a build with no richer sink configured — see
/// `crate::authz::audit::AuditEventSink` (F-M1-009, HORO-824) for the
/// real one.
pub struct StderrSink;

impl EventSink for StderrSink {
    fn record(&self, event: &AuthorizationEvent<'_>) {
        eprintln!(
            "eltanin-agent authz event: operation={:?} request={:?} peer_pid={} outcome={:?} \
             response={:?}",
            event.operation,
            event.request,
            event.peer.credential().pid(),
            event.outcome,
            event.response
        );
    }
}
