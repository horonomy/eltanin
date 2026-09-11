//! Failure taxonomy and user-facing messages for `eltanin run`
//! (F-M1-008, HORO-845).
//!
//! Every failure carries a human-readable message and a concrete next
//! action — never just an exit code. Denial and connection/protocol
//! failure are always distinguished; a failure classified from
//! `AgentResponse::Error{code: ErrorCode::Internal}` never invents a
//! more specific cause than the wire actually carries — `Internal`
//! deliberately collapses backend failure, enforcement refusal, and
//! capacity exhaustion into one wire variant, by design
//! (`docs/product/SECURITY_MODEL.md`).

use eltanin_protocol::response::{AgentResponse, DenialReason, ErrorCode};

use crate::args::UsageError;
use crate::client::ClientError;
use crate::context::GovernedContextError;
use crate::exit::ExitCode;
use crate::profile::{ProfileLoadError, ProfileNameError};

/// A classified `eltanin run` failure, distinct from a normal
/// workload-exit-status passthrough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchFailure {
    Usage(String),
    ProfileUnresolved(String),
    AgentUnavailable(String),
    AgentError(ErrorCode),
    Denied(DenialReason),
    GovernedContextFailed(String),
    AuthorizationLapsed,
}

impl LaunchFailure {
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Usage(_) => ExitCode::Usage,
            Self::ProfileUnresolved(_) => ExitCode::ProfileUnresolved,
            Self::AgentUnavailable(_) => ExitCode::AgentUnavailable,
            Self::AgentError(_) => ExitCode::AgentError,
            Self::Denied(_) => ExitCode::Denied,
            Self::GovernedContextFailed(_) => ExitCode::GovernedContextFailed,
            Self::AuthorizationLapsed => ExitCode::AuthorizationLapsed,
        }
    }

    /// A human-readable statement of what went wrong. Never empty.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Usage(detail) => format!("usage error: {detail}"),
            Self::ProfileUnresolved(detail) => format!("could not resolve --profile: {detail}"),
            Self::AgentUnavailable(detail) => {
                format!("could not reach the eltanin agent: {detail}")
            }
            Self::AgentError(code) => format!(
                "the agent reported an error: {}",
                describe_error_code(*code)
            ),
            Self::Denied(reason) => format!("request denied: {}", describe_denial_reason(*reason)),
            Self::GovernedContextFailed(detail) => {
                format!("could not establish a governed execution context: {detail}")
            }
            Self::AuthorizationLapsed => {
                "authorization lapsed mid-run; the workload was terminated".to_string()
            }
        }
    }

    /// A concrete next step for the user. Never empty. A denial's next
    /// action names `eltanin-explain --pid <this process's pid>`
    /// (`eltanin_audit::explain::Selector::Pid`) — never `RequestId`,
    /// per F-M1-009's forward obligation that a caller-supplied wire id
    /// is never used for audit correlation.
    #[must_use]
    pub fn next_action(&self) -> String {
        match self {
            Self::Usage(_) => {
                "run `eltanin run --profile <name> -- <program> [args...]`".to_string()
            }
            Self::ProfileUnresolved(_) => {
                "check the profile name and that its document exists and is valid".to_string()
            }
            Self::AgentUnavailable(_) => {
                "check that eltanin-agentd is running and ELTANIN_AGENT_SOCKET (if set) points \
                 at its socket"
                    .to_string()
            }
            Self::AgentError(_) => {
                "check the agent's own logs (stderr / journald) for the underlying cause"
                    .to_string()
            }
            Self::Denied(_) => {
                "run `eltanin-explain --pid <this process's pid>` for the full decision record, \
                 or contact your policy administrator"
                    .to_string()
            }
            Self::GovernedContextFailed(_) => {
                "check that eltanin run has permission to establish its execution context on \
                 this host"
                    .to_string()
            }
            Self::AuthorizationLapsed => {
                "request a fresh lease and re-run the workload".to_string()
            }
        }
    }
}

/// Classify a non-grant `AgentResponse` into a [`LaunchFailure`].
/// `AgentResponse::LeaseGranted` has no failure to classify — call sites
/// only reach this after already handling the grant path.
#[must_use]
pub fn classify_response(response: &AgentResponse) -> Option<LaunchFailure> {
    match response {
        AgentResponse::LeaseGranted { .. } => None,
        AgentResponse::LeaseDenied { reason } => Some(LaunchFailure::Denied(*reason)),
        AgentResponse::Error { code } => Some(LaunchFailure::AgentError(*code)),
        // eltanin run never sends ReleaseLease/AgentStatus as its
        // initial request, so LeaseReleased/Status are unreachable here;
        // classify them as an agent error rather than panicking, since
        // "unreachable" is a claim about this crate's own call sites,
        // not a wire-level guarantee.
        AgentResponse::LeaseReleased { .. } | AgentResponse::Status { .. } => {
            Some(LaunchFailure::AgentError(ErrorCode::Internal))
        }
    }
}

impl From<UsageError> for LaunchFailure {
    fn from(error: UsageError) -> Self {
        Self::Usage(error.to_string())
    }
}

impl From<ProfileNameError> for LaunchFailure {
    fn from(error: ProfileNameError) -> Self {
        Self::ProfileUnresolved(error.to_string())
    }
}

impl From<ProfileLoadError> for LaunchFailure {
    fn from(error: ProfileLoadError) -> Self {
        Self::ProfileUnresolved(error.to_string())
    }
}

impl From<ClientError> for LaunchFailure {
    fn from(error: ClientError) -> Self {
        Self::AgentUnavailable(error.to_string())
    }
}

impl From<GovernedContextError> for LaunchFailure {
    fn from(error: GovernedContextError) -> Self {
        Self::GovernedContextFailed(error.to_string())
    }
}

fn describe_denial_reason(reason: DenialReason) -> &'static str {
    match reason {
        DenialReason::NoMatchingRule => "no policy rule allows this request",
        DenialReason::ExplicitDeny => "a policy rule explicitly denies this request",
        DenialReason::IndeterminateEvidence => {
            "required evidence could not be observed with sufficient confidence"
        }
    }
}

fn describe_error_code(code: ErrorCode) -> String {
    match code {
        ErrorCode::UnsupportedVersion { found, expected } => {
            format!("protocol version mismatch (found {found}, expected {expected})")
        }
        ErrorCode::MalformedRequest => "the request was malformed".to_string(),
        ErrorCode::Oversized => "the request exceeded the protocol's size limit".to_string(),
        ErrorCode::UnknownOperation => {
            "the agent did not recognize the requested operation".to_string()
        }
        ErrorCode::Internal => {
            "an internal agent error occurred (backend failure, enforcement refusal, or \
             capacity exhaustion — the wire protocol does not distinguish which)"
                .to_string()
        }
    }
}
