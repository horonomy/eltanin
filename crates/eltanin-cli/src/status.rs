//! `eltanin status` — liveness/version/enforcement-posture probe CLI
//! (F-M2-006, HORO-796 subtask 4).
//!
//! Deliberately as thin as [`crate::session`]/[`crate::approve`]: one
//! request, one response, no supervise loop. Surfaces
//! [`eltanin_protocol::response::AgentStatusView::enforcement_mode`] so an
//! operator can confirm whether the agent is running
//! [`EnforcementMode::Enforce`] or [`EnforcementMode::Shadow`] without
//! inferring it from side effects — the exact gap `AgentStatusView`'s own
//! doc comment names this command as closing. Also surfaces
//! `AgentStatusView`'s `session_required`/`approval_required`/
//! `revocation_required` gate flags (HORO-797 prep) so an operator can
//! confirm which of `eltanin session start`/`eltanin approve`/
//! revocation-capability gating are actually active, rather than
//! inferring a silently-permissive posture from side effects. Also
//! surfaces `delegation_configured`/`step_up_configured` (HORO-1278) so
//! an operator can confirm whether bounded compute delegation
//! (F-M2-003) and risk-based step-up (F-M2-004) are active without
//! inspecting the agent's own configuration — this module reports
//! exactly what the wire type exposes and nothing more, deliberately
//! not inventing a richer view the agent does not actually expose.

use eltanin_protocol::request::ClientRequest;
use eltanin_protocol::response::{AgentResponse, AgentStatusView, EnforcementMode, ErrorCode};

use crate::client::AgentClient;
use crate::failure::LaunchFailure;

/// The result of one `eltanin status` invocation: either a
/// human-readable report (printed to stdout, exit 0) or a
/// [`LaunchFailure`] (printed and mapped to an exit code exactly like
/// `eltanin run`'s own failures — see `crate::failure`). No new exit
/// code is introduced by this module.
pub enum StatusCliOutcome {
    Ok(String),
    Failure(LaunchFailure),
}

/// Run an `eltanin status` invocation against the local agent.
#[must_use]
pub fn run() -> StatusCliOutcome {
    let client = match AgentClient::from_env() {
        Ok(client) => client,
        Err(error) => return StatusCliOutcome::Failure(error.into()),
    };
    let response = match client.exchange(ClientRequest::AgentStatus {}) {
        Ok(response) => response,
        Err(error) => return StatusCliOutcome::Failure(LaunchFailure::from(error)),
    };
    match response {
        AgentResponse::Status { status } => StatusCliOutcome::Ok(describe_status(status)),
        AgentResponse::LeaseDenied { reason } => {
            StatusCliOutcome::Failure(LaunchFailure::Denied(reason))
        }
        AgentResponse::Error { code } => StatusCliOutcome::Failure(LaunchFailure::AgentError(code)),
        // AgentStatus is never denied or shadow-observed by the agent
        // (see `eltanin_agent::handler`'s `AgentStatus` handling) — any
        // other response shape reaching here means this client sent an
        // op the agent answered with an unrelated response type, an
        // internal error rather than a status the wire actually reported.
        _ => StatusCliOutcome::Failure(LaunchFailure::AgentError(ErrorCode::Internal)),
    }
}

fn describe_status(status: AgentStatusView) -> String {
    let mode = match status.enforcement_mode {
        EnforcementMode::Enforce => format!(
            "protocol version {}; enforcement mode: enforce (leases are actually granted and \
             enforced)",
            status.protocol_version
        ),
        EnforcementMode::Shadow => format!(
            "protocol version {}; enforcement mode: shadow — UNENFORCED/OBSERVED-ONLY: every \
             decision is evaluated but never granted or enforced; see `eltanin run`'s shadow-mode \
             output for what a specific request would have done",
            status.protocol_version
        ),
    };
    format!("{mode}\n{}", describe_gates(status))
}

/// Disclose, plainly, which of the session/approval/revocation gates
/// this agent is actually enforcing (HORO-797 prep) — mirroring the same
/// "state an unenforced/weak posture loudly rather than silently"
/// discipline `enforcement_mode`'s own shadow-mode language already
/// established just above, applied to the three requirement gates
/// D1/D1b named as silently non-operator-configurable before this
/// ticket.
fn describe_gates(status: AgentStatusView) -> String {
    let session = if status.session_required {
        "session required: yes (RequestLease is refused without an active Trusted Compute \
         Session)"
    } else {
        "session required: NO — this agent does not require a Trusted Compute Session; \
         `eltanin session start` has no enforcement effect here"
    };
    let approval = if status.approval_required {
        "approval required: yes (RequestLease is refused without a matching remembered \
         approval)"
    } else {
        "approval required: NO — this agent does not require a remembered approval"
    };
    let revocation = if status.revocation_required {
        "revocation required: yes (a resource lacking DeviceRevoke support is never leased)"
    } else {
        "revocation required: NO — this agent does not require DeviceRevoke support to lease a \
         resource"
    };
    let delegation = if status.delegation_configured {
        "delegation configured: yes (a descendant of an already-admitted requester may be \
         silently admitted under a matching delegation grant)"
    } else {
        "delegation configured: NO — this agent does not admit any request via bounded compute \
         delegation"
    };
    let step_up = if status.step_up_configured {
        "step-up configured: yes (an approval/delegation refusal may be classified into a \
         step-up-required or risk-denied response)"
    } else {
        "step-up configured: NO — this agent does not classify refusals with risk-based step-up"
    };
    format!("{session}\n{approval}\n{revocation}\n{delegation}\n{step_up}")
}
