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

use eltanin_core::approval::{ApprovalDisposition, ApprovalId};
use eltanin_core::lease::LeaseId;
use eltanin_core::resource::{Action, ResourceIdentity};
use eltanin_core::session::SessionId;
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
///
/// `NoTrustedSession` (F-M2-001, HORO-791) is a **pre-policy** denial:
/// the agent's session-admission gate refused the request *before*
/// `PolicySet::evaluate` was ever consulted, exactly like the existing
/// `IndeterminateEvidence` case a non-`authorizable()` peer already
/// produces (see `crates/eltanin-agent/src/authz/mod.rs`'s module
/// docs). It must never be conflated with `ExplicitDeny`/
/// `NoMatchingRule`/`IndeterminateEvidence` — those all mean "policy was
/// consulted and did not allow it," which is not what happened here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    NoMatchingRule,
    ExplicitDeny,
    IndeterminateEvidence,
    NoTrustedSession,
    /// F-M2-002/HORO-792: the approval-admission gate found no
    /// [`eltanin_core::approval::RecallVerdict::Matched`] candidate for
    /// this `(resource, action)` — pre-policy, exactly like
    /// `NoTrustedSession`. The CLI's failure path maps this to the
    /// exact `eltanin approve` command to run next.
    ApprovalRequired,
    /// F-M2-002/HORO-792: a `Deny` approval matched (deny-overrides).
    /// Also pre-policy — this is never `PolicySet::evaluate` speaking.
    ApprovalDenied,
    /// F-M2-004/HORO-794: the risk layer classified an approval/
    /// delegation refusal as remediable via step-up — running
    /// `eltanin approve --remember` (or `--once`) is expected to clear
    /// it, same as a plain `ApprovalRequired`. Which trust change(s)
    /// caused this is recorded in the audit trail only
    /// (`eltanin_core::risk::RiskSignal`), never on the wire — same
    /// "lossy wire, rich audit" discipline as every other pre-policy
    /// denial reason here.
    StepUpRequired,
    /// F-M2-004/HORO-794: the risk layer classified an approval/
    /// delegation refusal as hard-denied — the fired signal(s) are
    /// configured `SignalDisposition::Deny`, so re-approving will not
    /// admit this request. Pre-policy, like every other variant above.
    RiskDenied,
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

/// A client-facing, non-replayable view of one established Trusted
/// Compute Session (F-M2-001, HORO-791). Deliberately **not**
/// `eltanin_core::session::TrustedSession` itself, which is `Serialize`
/// only and carries a `MonotonicTime` pair meaningless outside the
/// issuing agent instance — same idiom as [`LeaseView`] projecting
/// `ComputeLease`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionView {
    pub session_id: SessionId,
    pub remaining: Duration,
    pub resources: Vec<ResourceIdentity>,
}

/// A deliberately coarser, client-facing projection of
/// [`eltanin_core::session::SessionTerminationOutcome`] — every
/// non-`Terminated` case collapses to `Refused`, for the same
/// enumeration-resistance reason [`ReleaseOutcome`] already collapses
/// [`eltanin_core::lease::RevocationOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationOutcome {
    Terminated,
    Refused,
}

/// A client-facing, non-replayable view of one recorded approval
/// (F-M2-002, HORO-792). Deliberately **not**
/// `eltanin_core::approval::Approval` itself — the module docs' "load-
/// bearing structural fact" above forbids embedding it here even though
/// `Approval` (unlike `ComputeLease`/`PolicyDecision`) is reconstructible
/// from disk via `ApprovalSet::from_document`: that path exists for
/// this agent's own durable store, not for the wire, and this module's
/// discipline is "no type that must never be bearer authority is
/// embedded here," applied uniformly regardless of whether a given type
/// happens to have *some* other `Deserialize` path elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalView {
    pub id: ApprovalId,
    pub resource: ResourceIdentity,
    pub action: Action,
    pub disposition: ApprovalDisposition,
}

/// A deliberately coarser, client-facing projection of whether
/// `eltanin approve forget` actually removed an entry — every
/// non-`Forgotten` case (unknown id, foreign owner) collapses to
/// `Refused`, same enumeration-resistance reason as
/// [`ReleaseOutcome`]/[`TerminationOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgetOutcome {
    Forgotten,
    Refused,
}

/// Which enforcement posture the agent is currently running under
/// (F-M2-006, HORO-796 subtask 3). Lives here, not
/// `eltanin_agent::authz`, because [`AgentStatusView`] must report it and
/// this crate cannot depend back on `eltanin-agent` — mirrors
/// `eltanin_audit::record::RecordedEnforcementMode`'s identical
/// dependency-direction reasoning, one crate boundary over.
/// `eltanin_agent::authz::AuthorizationHandler` holds this type directly
/// (no separate agent-internal copy) rather than duplicating it, since
/// unlike `SessionRequirement`/`ApprovalRequirement`/`RevocationRequirement`
/// (agent-internal only, no wire representation) this configuration must
/// already cross the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Every granted `RequestLease` actually reaches
    /// `ComputeBackend::enforce` and is inserted into the lease store.
    #[default]
    Enforce,
    /// Every gate and policy evaluation runs identically to `Enforce`,
    /// but a would-be grant is never enforced or stored — see
    /// `eltanin_agent::authz`'s module docs for the full contract.
    Shadow,
}

/// The coarse, client-facing verdict a shadow-mode `RequestLease`
/// reports via [`AgentResponse::ShadowObserved`] (F-M2-006, HORO-796
/// subtask 3). Deliberately as lossy as [`DenialReason`]'s own
/// discipline: the specific gate/policy reason that produced this
/// verdict stays in the audit trail
/// (`eltanin_audit::record::RecordedOutcome`), never on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowVerdict {
    /// Every gate and `PolicySet::evaluate` would have admitted this
    /// request — nothing was actually granted or enforced.
    WouldAllow,
    /// A gate or `PolicySet::evaluate` would have refused this request.
    WouldDeny,
    /// The risk layer (F-M2-004, HORO-794) would have classified this
    /// refusal as remediable via step-up.
    WouldStepUp,
}

/// Minimal liveness/version probe response. Deliberately does not
/// include the agent's [`eltanin_core::lease::IssuerInstanceId`] — not
/// secret, but there is no MVP 1.0 caller that needs it and no reason to
/// hand it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatusView {
    pub protocol_version: u16,
    /// Which enforcement posture is currently active (F-M2-006,
    /// HORO-796 subtask 3) — lets an operator (or a later validation
    /// tool, HORO-797) confirm whether an agent is actually running in
    /// shadow mode without inferring it from side effects.
    pub enforcement_mode: EnforcementMode,
    /// Whether this deployment requires an active Trusted Compute
    /// Session before `RequestLease` is granted (F-M2-001, HORO-791;
    /// operator-configurable via `ELTANIN_AGENT_SESSION_REQUIRED`,
    /// HORO-797 prep). Unlike `enforcement_mode`, the agent-internal
    /// `SessionRequirement`/`ApprovalRequirement`/`RevocationRequirement`
    /// enums themselves have no wire representation (see this struct's
    /// module-level context) — this is a plain `bool` projection of
    /// `SessionRequirement::Required`, added specifically so a client
    /// (`eltanin status`, `eltanin session start`) can disclose plainly
    /// when a gate is not active rather than leaving that silent.
    pub session_required: bool,
    /// Whether this deployment requires a matching remembered approval
    /// before `RequestLease` is granted (F-M2-002, HORO-792;
    /// operator-configurable via `ELTANIN_AGENT_APPROVAL_REQUIRED` +
    /// `ELTANIN_AGENT_APPROVAL_STORE`, HORO-797 prep). See
    /// `session_required`'s doc for why this is a plain `bool`.
    pub approval_required: bool,
    /// Whether this deployment requires `Capability::DeviceRevoke`
    /// support as a grant-time precondition (F-M2-005, HORO-795;
    /// operator-configurable via `ELTANIN_AGENT_REVOCATION_REQUIRED`,
    /// HORO-797 prep). See `session_required`'s doc for why this is a
    /// plain `bool`.
    pub revocation_required: bool,
    /// Whether this deployment has bounded compute delegation configured
    /// (F-M2-003, HORO-793; operator-configurable via
    /// `ELTANIN_AGENT_GATE_CONFIG`, HORO-1278). See `session_required`'s
    /// doc for why this is a plain `bool` — the rich detail (bounds,
    /// exceeded dimensions) lives in the audit trail only, never on the
    /// wire. Does not bump `DOMAIN_SCHEMA_VERSION` — additive wire
    /// disclosure, following the same precedent
    /// `session_required`/`approval_required`/`revocation_required`
    /// themselves set when they were added.
    pub delegation_configured: bool,
    /// Whether this deployment has risk-based step-up classification
    /// configured (F-M2-004, HORO-794; operator-configurable via
    /// `ELTANIN_AGENT_GATE_CONFIG`, HORO-1278). See
    /// `delegation_configured`'s doc for the same rationale and the same
    /// no-schema-bump precedent.
    pub step_up_configured: bool,
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
    LeaseGranted {
        lease: LeaseView,
    },
    LeaseDenied {
        reason: DenialReason,
    },
    LeaseReleased {
        outcome: ReleaseOutcome,
    },
    Status {
        status: AgentStatusView,
    },
    Error {
        code: ErrorCode,
    },
    /// A Trusted Compute Session was established (F-M2-001, HORO-791).
    SessionEstablished {
        session: SessionView,
    },
    /// The calling peer's currently-verified Trusted Compute Sessions —
    /// at most one, today.
    SessionList {
        sessions: Vec<SessionView>,
    },
    SessionTerminated {
        outcome: TerminationOutcome,
    },
    /// An approval was recorded (F-M2-002, HORO-792).
    ApprovalRecorded {
        approval: ApprovalView,
    },
    /// The calling peer's own recorded approvals.
    ApprovalList {
        approvals: Vec<ApprovalView>,
    },
    ApprovalForgotten {
        outcome: ForgetOutcome,
    },
    /// The agent is running in [`EnforcementMode::Shadow`] and this
    /// response is to a `RequestLease` — nothing was actually granted
    /// or enforced; `verdict` reports only what *would* have happened
    /// (F-M2-006, HORO-796 subtask 3). Never produced by any other
    /// operation — see `eltanin_agent::authz`'s module docs on shadow
    /// mode's scope.
    ShadowObserved {
        verdict: ShadowVerdict,
    },
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
