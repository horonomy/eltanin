//! `eltanin approve --profile <name> (--once|--remember|--deny)` /
//! `eltanin approve list` / `eltanin approve forget <id>` — remembered-
//! authorization CLI (F-M2-002, HORO-792).
//!
//! Deliberately as thin as [`crate::session`]: no supervise loop, no
//! lease-holding responsibility. Reuses `--profile`'s existing
//! [`crate::profile`] resolution wholesale — exactly like
//! `crate::session` already does — resolving `--profile <name>` to the
//! `(resource, action)` pair [`eltanin_protocol::request::ApproveRequest`]
//! carries. There is no wire-level `--profile` concept; see ADR 0010 for
//! why.

use eltanin_protocol::request::{ApproveRequest, ClientRequest, ForgetApprovalRequest};
use eltanin_protocol::response::{AgentResponse, ApprovalView, ErrorCode, ForgetOutcome};

use crate::args::ApproveInvocation;
use crate::client::AgentClient;
use crate::failure::LaunchFailure;
use crate::profile::load_profile;

/// The result of one `eltanin approve` invocation: either a
/// human-readable success message (printed to stdout, exit 0) or a
/// [`LaunchFailure`] (printed and mapped to an exit code exactly like
/// `eltanin run`'s own failures — see `crate::failure`). No new exit
/// code is introduced by this module.
pub enum ApproveCliOutcome {
    Ok(String),
    Failure(LaunchFailure),
}

/// Run a parsed [`ApproveInvocation`] against the local agent.
#[must_use]
pub fn run(invocation: &ApproveInvocation) -> ApproveCliOutcome {
    match invocation {
        ApproveInvocation::Record {
            profile,
            disposition,
        } => record(profile, *disposition),
        ApproveInvocation::List => list(),
        ApproveInvocation::Forget { id } => forget(id),
    }
}

fn agent_client() -> Result<AgentClient, LaunchFailure> {
    Ok(AgentClient::from_env()?)
}

fn describe_approval(view: &ApprovalView) -> String {
    format!(
        "{:?}: {:?}/{:?} ({:?})",
        view.id, view.resource, view.action, view.disposition
    )
}

/// Every non-success `AgentResponse` this module's three requests can
/// receive collapses through here — mirrors `crate::session::classify`
/// exactly, for the same reason (see that function's own doc comment).
fn classify(response: AgentResponse) -> Result<AgentResponse, LaunchFailure> {
    match &response {
        AgentResponse::LeaseDenied { reason } => Err(LaunchFailure::Denied(*reason)),
        AgentResponse::Error { code } => Err(LaunchFailure::AgentError(*code)),
        _ => Ok(response),
    }
}

fn record(
    profile: &crate::profile::ProfileName,
    disposition: eltanin_core::approval::ApprovalDisposition,
) -> ApproveCliOutcome {
    let document = match load_profile(profile) {
        Ok(document) => document,
        Err(e) => return ApproveCliOutcome::Failure(e.into()),
    };
    let client = match agent_client() {
        Ok(client) => client,
        Err(failure) => return ApproveCliOutcome::Failure(failure),
    };
    let response = client.exchange(ClientRequest::Approve(ApproveRequest {
        resource: document.resource,
        action: document.action,
        disposition,
    }));
    let response = match response {
        Ok(response) => response,
        Err(error) => return ApproveCliOutcome::Failure(LaunchFailure::from(error)),
    };
    match classify(response) {
        Ok(AgentResponse::ApprovalRecorded { approval }) => {
            ApproveCliOutcome::Ok(format!("recorded {}", describe_approval(&approval)))
        }
        Ok(_) => ApproveCliOutcome::Failure(LaunchFailure::AgentError(ErrorCode::Internal)),
        Err(failure) => ApproveCliOutcome::Failure(failure),
    }
}

fn list() -> ApproveCliOutcome {
    let client = match agent_client() {
        Ok(client) => client,
        Err(failure) => return ApproveCliOutcome::Failure(failure),
    };
    let response = match client.exchange(ClientRequest::ListApprovals {}) {
        Ok(response) => response,
        Err(error) => return ApproveCliOutcome::Failure(LaunchFailure::from(error)),
    };
    match classify(response) {
        Ok(AgentResponse::ApprovalList { approvals }) if approvals.is_empty() => {
            ApproveCliOutcome::Ok("no recorded approvals".to_string())
        }
        Ok(AgentResponse::ApprovalList { approvals }) => {
            let lines: Vec<String> = approvals.iter().map(describe_approval).collect();
            ApproveCliOutcome::Ok(lines.join("\n"))
        }
        Ok(_) => ApproveCliOutcome::Failure(LaunchFailure::AgentError(ErrorCode::Internal)),
        Err(failure) => ApproveCliOutcome::Failure(failure),
    }
}

fn forget(id: &eltanin_core::approval::ApprovalId) -> ApproveCliOutcome {
    let client = match agent_client() {
        Ok(client) => client,
        Err(failure) => return ApproveCliOutcome::Failure(failure),
    };
    let response = client.exchange(ClientRequest::ForgetApproval(ForgetApprovalRequest {
        id: id.clone(),
    }));
    let response = match response {
        Ok(response) => response,
        Err(error) => return ApproveCliOutcome::Failure(LaunchFailure::from(error)),
    };
    match classify(response) {
        Ok(AgentResponse::ApprovalForgotten {
            outcome: ForgetOutcome::Forgotten,
        }) => ApproveCliOutcome::Ok("approval forgotten".to_string()),
        Ok(AgentResponse::ApprovalForgotten {
            outcome: ForgetOutcome::Refused,
        }) => {
            // Refused collapses every non-Forgotten case (unknown id,
            // foreign owner) into one wire shape by design — see
            // ForgetOutcome's own docs. Reported as an internal-shaped
            // error rather than Denied: no policy was consulted here.
            ApproveCliOutcome::Failure(LaunchFailure::AgentError(ErrorCode::Internal))
        }
        Ok(_) => ApproveCliOutcome::Failure(LaunchFailure::AgentError(ErrorCode::Internal)),
        Err(failure) => ApproveCliOutcome::Failure(failure),
    }
}
