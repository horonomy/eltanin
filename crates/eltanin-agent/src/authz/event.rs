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

use eltanin_core::lease::{LeaseError, LeaseId, LeaseValidity, MonotonicTime, RevocationOutcome};
use eltanin_core::peer::PeerContext;
use eltanin_core::policy::PolicyDecision;
use eltanin_core::resource::EnforcementResult;
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
