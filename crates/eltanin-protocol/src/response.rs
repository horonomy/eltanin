//! Wire response types.
//!
//! **The load-bearing structural fact of this module**: [`AgentResponse`]
//! derives `Deserialize`. Every type in `eltanin-core` that must never
//! be reconstructed from bytes — [`eltanin_core::lease::ComputeLease`],
//! [`eltanin_core::policy::PolicyDecision`],
//! [`eltanin_core::policy::DecisionReason`],
//! [`eltanin_core::policy::PolicyProvenance`],
//! [`eltanin_core::lease::LeaseValidity`] — is `Serialize`-only by
//! construction. Embedding any of them here would fail to compile. "No
//! reusable plaintext bearer credential" (HORO-788's security
//! requirement) is therefore enforced by the compiler, not by review
//! discipline: this module cannot hand a client anything it could later
//! replay as if it were the original authorization artifact.

use std::time::Duration;

use eltanin_core::lease::LeaseId;
use serde::{Deserialize, Serialize};

use crate::request::RequestId;

/// A client-facing, non-replayable view of a granted lease. Carries
/// `remaining: Duration` rather than the lease's actual
/// [`eltanin_core::lease::MonotonicTime`] fields — a `MonotonicTime`
/// reading is nanoseconds since an epoch chosen by one issuer instance
/// and is meaningless to any process other than that issuer (see
/// `lease.rs`'s module docs); the agent computes `remaining` at send
/// time instead, the same idiom `LeaseValidity::Valid { remaining }`
/// already establishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseView {
    pub lease_id: LeaseId,
    pub remaining: Duration,
}

/// A deliberately lossy, client-facing projection of
/// [`eltanin_core::policy::DecisionReason`]. The rule ids and evidence
/// detail behind a denial belong to the audit trail (F-M1-009), not to
/// an unprivileged client — telling a caller exactly which rule fired
/// and why would hand it a map of the policy it's trying to get past.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    NoMatchingRule,
    ExplicitDeny,
    IndeterminateEvidence,
}

/// A deliberately coarser, client-facing projection of
/// [`eltanin_core::lease::RevocationOutcome`]. `RevocationOutcome`
/// distinguishes `NotIssued`/`AlreadyRevoked`/`ForeignIssuer` — exposing
/// that distinction to a client would let it enumerate which lease ids
/// exist and which issuer holds them. Every non-`Released` case
/// collapses to `Refused`; the rich outcome still reaches the audit
/// trail (F-M1-009) unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseOutcome {
    Released,
    Refused,
}

/// Minimal liveness/version probe response. Deliberately does not
/// include the agent's [`eltanin_core::lease::IssuerInstanceId`] — not
/// secret, but there is no MVP 1.0 caller that needs it and no reason to
/// hand it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatusView {
    pub protocol_version: u16,
}

/// A closed set of protocol-level error codes. Deliberately has **no**
/// free-text field: a `message: String` would eventually carry a
/// `serde_json` parse error string built from attacker-controlled input
/// straight into a client-visible response. Detail belongs in the
/// agent's own log, never on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "error")]
pub enum ErrorCode {
    UnsupportedVersion { found: u16, expected: u16 },
    MalformedRequest,
    Oversized,
    UnknownOperation,
    Internal,
}

/// The agent's answer to one [`crate::request::ClientRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum AgentResponse {
    LeaseGranted { lease: LeaseView },
    LeaseDenied { reason: DenialReason },
    LeaseReleased { outcome: ReleaseOutcome },
    Status { status: AgentStatusView },
    Error { code: ErrorCode },
}

/// One versioned, best-effort-correlated response body.
///
/// `request_id` is `Option` on purpose: correlation is recoverable when
/// the request's *body* was malformed (the envelope and header still
/// parsed), but not when the whole payload wasn't even a JSON object —
/// there is nothing to recover an id from. Fabricating one in that case
/// would misrepresent what the agent actually observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseBody {
    pub request_id: Option<RequestId>,
    pub body: AgentResponse,
}

/// A full wire response: [`ResponseBody`] wrapped in
/// [`eltanin_core::envelope::Versioned`].
pub type Response = eltanin_core::envelope::Versioned<ResponseBody>;
