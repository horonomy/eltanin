//! `eltanin session start|list|end` — Trusted Compute Session lifecycle
//! CLI (F-M2-001, HORO-791).
//!
//! Deliberately thin, unlike [`crate::launch`]: no supervise loop, no
//! signal handling, no lease-holding responsibility. A session's
//! lifetime belongs to the agent, not to this process — `eltanin
//! session start` establishes it and exits; the terminal the user then
//! works in is the session's kernel anchor (its own POSIX session), not
//! this short-lived CLI invocation. `eltanin run --profile <p> -- <cmd>`
//! is completely unchanged by this module — see `crate::launch`.
//!
//! Reuses `--profile`'s existing [`crate::profile`] resolution wholesale:
//! each `--profile` given to `session start` resolves to a
//! [`crate::profile::ProfileDocument`], and this module unions their
//! `resource` fields into the session's [`CreateSessionRequest::resources`].
//! The action component of each profile is ignored at session level —
//! actions stay per-lease, decided later by `eltanin run`, unchanged.

use std::time::Duration;

use eltanin_core::resource::ResourceIdentity;
use eltanin_protocol::request::{ClientRequest, CreateSessionRequest};
use eltanin_protocol::response::{AgentResponse, ErrorCode, SessionView, TerminationOutcome};

use crate::args::SessionInvocation;
use crate::client::AgentClient;
use crate::failure::LaunchFailure;
use crate::profile::{load_profile, ProfileName};

/// The result of one `eltanin session` invocation: either a
/// human-readable success message (printed to stdout, exit 0) or a
/// [`LaunchFailure`] (printed and mapped to an exit code exactly like
/// `eltanin run`'s own failures — see `crate::failure`).
pub enum SessionCliOutcome {
    Ok(String),
    Failure(LaunchFailure),
}

/// Run a parsed [`SessionInvocation`] against the local agent.
#[must_use]
pub fn run(invocation: &SessionInvocation) -> SessionCliOutcome {
    match invocation {
        SessionInvocation::Start { profiles, ttl } => start(profiles, *ttl),
        SessionInvocation::List => list(),
        SessionInvocation::End => end(),
    }
}

fn resolve_resources(profiles: &[ProfileName]) -> Result<Vec<ResourceIdentity>, LaunchFailure> {
    let mut resources = Vec::with_capacity(profiles.len());
    for profile in profiles {
        resources.push(load_profile(profile)?.resource);
    }
    Ok(resources)
}

fn agent_client() -> Result<AgentClient, LaunchFailure> {
    Ok(AgentClient::from_env()?)
}

fn describe_session(view: &SessionView) -> String {
    format!(
        "session {:?}: {}s remaining, {} resource(s)",
        view.session_id,
        view.remaining.as_secs(),
        view.resources.len()
    )
}

/// Every non-success `AgentResponse` this module's three requests can
/// receive collapses through here — `LeaseDenied`/`Error` are the only
/// two shapes a session op can actually be refused with (see
/// `eltanin_agent::authz`'s `CreateSession` handling, which maps every
/// non-grant outcome to one of these two). Any other response shape
/// reaching here would mean this client sent an op the agent answered
/// with an unrelated response type — an internal error, not a policy or
/// session decision, so it maps to `Error{Internal}` rather than
/// inventing a more specific cause the wire never actually carried.
fn classify(response: AgentResponse) -> Result<AgentResponse, LaunchFailure> {
    match &response {
        AgentResponse::LeaseDenied { reason } => Err(LaunchFailure::Denied(*reason)),
        AgentResponse::Error { code } => Err(LaunchFailure::AgentError(*code)),
        _ => Ok(response),
    }
}

fn start(profiles: &[ProfileName], ttl: Duration) -> SessionCliOutcome {
    let resources = match resolve_resources(profiles) {
        Ok(resources) => resources,
        Err(failure) => return SessionCliOutcome::Failure(failure),
    };
    let client = match agent_client() {
        Ok(client) => client,
        Err(failure) => return SessionCliOutcome::Failure(failure),
    };
    let response = client.exchange(ClientRequest::CreateSession(CreateSessionRequest {
        resources,
        ttl,
    }));
    let response = match response {
        Ok(response) => response,
        Err(error) => return SessionCliOutcome::Failure(LaunchFailure::from(error)),
    };
    match classify(response) {
        Ok(AgentResponse::SessionEstablished { session }) => {
            SessionCliOutcome::Ok(format!("established {}", describe_session(&session)))
        }
        Ok(_) => SessionCliOutcome::Failure(LaunchFailure::AgentError(ErrorCode::Internal)),
        Err(failure) => SessionCliOutcome::Failure(failure),
    }
}

fn list() -> SessionCliOutcome {
    let client = match agent_client() {
        Ok(client) => client,
        Err(failure) => return SessionCliOutcome::Failure(failure),
    };
    let response = match client.exchange(ClientRequest::ListSessions {}) {
        Ok(response) => response,
        Err(error) => return SessionCliOutcome::Failure(LaunchFailure::from(error)),
    };
    match classify(response) {
        Ok(AgentResponse::SessionList { sessions }) if sessions.is_empty() => {
            SessionCliOutcome::Ok("no active Trusted Compute Session".to_string())
        }
        Ok(AgentResponse::SessionList { sessions }) => {
            let lines: Vec<String> = sessions.iter().map(describe_session).collect();
            SessionCliOutcome::Ok(lines.join("\n"))
        }
        Ok(_) => SessionCliOutcome::Failure(LaunchFailure::AgentError(ErrorCode::Internal)),
        Err(failure) => SessionCliOutcome::Failure(failure),
    }
}

fn end() -> SessionCliOutcome {
    let client = match agent_client() {
        Ok(client) => client,
        Err(failure) => return SessionCliOutcome::Failure(failure),
    };
    let response = match client.exchange(ClientRequest::TerminateSession {}) {
        Ok(response) => response,
        Err(error) => return SessionCliOutcome::Failure(LaunchFailure::from(error)),
    };
    match classify(response) {
        Ok(AgentResponse::SessionTerminated {
            outcome: TerminationOutcome::Terminated,
        }) => SessionCliOutcome::Ok("session terminated".to_string()),
        Ok(AgentResponse::SessionTerminated {
            outcome: TerminationOutcome::Refused,
        }) => {
            // Refused collapses every non-`Terminated` case (no active
            // session for this peer, a foreign issuer, ...) into one
            // wire shape by design — see `TerminationOutcome`'s own
            // docs. Reported as an internal-shaped error rather than
            // `Denied`: no policy was consulted here at all.
            SessionCliOutcome::Failure(LaunchFailure::AgentError(ErrorCode::Internal))
        }
        Ok(_) => SessionCliOutcome::Failure(LaunchFailure::AgentError(ErrorCode::Internal)),
        Err(failure) => SessionCliOutcome::Failure(failure),
    }
}
