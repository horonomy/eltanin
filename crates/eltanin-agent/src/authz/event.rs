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
use eltanin_core::policy::PolicyDecision;
use eltanin_core::resource::EnforcementResult;
use eltanin_linux::peer::PeerContext;

use eltanin_backend::contract::BackendError;
use eltanin_protocol::response::AgentResponse;

/// Which wire operation this event reports on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    RequestLease,
    ReleaseLease,
    AgentStatus,
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
}

/// One authorization event: what was asked, who asked (as observed —
/// regardless of outcome), what actually happened, and what the client
/// actually saw. `peer` is recorded even when the outcome is a denial —
/// an audit trail needs the identity of a *refused* request as much as
/// a granted one.
pub struct AuthorizationEvent<'a> {
    pub operation: Operation,
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
/// stopgap until F-M1-009 supplies a real one.
pub struct StderrSink;

impl EventSink for StderrSink {
    fn record(&self, event: &AuthorizationEvent<'_>) {
        eprintln!(
            "eltanin-agent authz event: operation={:?} peer_pid={} outcome={:?} response={:?}",
            event.operation,
            event.peer.credential().pid(),
            event.outcome,
            event.response
        );
    }
}
