//! `eltanin status` — liveness/version/enforcement-posture probe CLI
//! (F-M2-006, HORO-796 subtask 4).
//!
//! Deliberately as thin as [`crate::session`]/[`crate::approve`]: one
//! request, one response, no supervise loop. Surfaces
//! [`eltanin_protocol::response::AgentStatusView::enforcement_mode`] so an
//! operator can confirm whether the agent is running
//! [`EnforcementMode::Enforce`] or [`EnforcementMode::Shadow`] without
//! inferring it from side effects — the exact gap `AgentStatusView`'s own
//! doc comment names this command as closing. There is no additional
//! shadow-specific state to surface beyond the mode itself: the wire type
//! carries only `protocol_version` and `enforcement_mode`, so this
//! module reports both and nothing more, deliberately not inventing a
//! richer view the agent does not actually expose.

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
    match status.enforcement_mode {
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
    }
}
