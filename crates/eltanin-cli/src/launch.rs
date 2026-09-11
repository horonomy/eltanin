//! S0-S11 orchestrator (F-M1-008, HORO-846) — the crate's single
//! `Command::spawn` call site.
//!
//! See `docs/product/CLI_CONTRACT.md`'s launch state machine. The
//! sequencing invariant this module exists to uphold: [`Command::spawn`]
//! is reached *only* from the `AgentResponse::LeaseGranted` match arm in
//! [`run`] — every other arm returns a [`LaunchOutcome::Failure`] before
//! reaching it. There is no stage between "send `RequestLease`" and
//! "spawn" for anything else to happen in.

use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, ExitStatus};
use std::time::Instant;

use eltanin_protocol::request::{ClientRequest, LeaseRequest};
use eltanin_protocol::response::AgentResponse;

use crate::args::RunInvocation;
use crate::client::AgentClient;
use crate::context::{GovernedContext, NullContext};
use crate::exit::{workload_signal_exit_code, ExitCode};
use crate::failure::{classify_response, LaunchFailure};
use crate::profile::load_profile;
use crate::supervise::{release, supervise, RunOutcome};
use crate::{context, signals};

/// The final outcome of a launch attempt.
pub enum LaunchOutcome {
    /// `eltanin run` failed before or during the launch — the workload
    /// may or may not have run; the caller should print
    /// `failure.message()`/`failure.next_action()` and exit with
    /// `failure.exit_code().code()`.
    Failure(LaunchFailure),
    /// A concrete process exit code: the workload's own status (or its
    /// signal-derived `128+N`), or an `eltanin run` code (76) computed
    /// here rather than via [`LaunchFailure`], since it isn't a failure
    /// *of* `eltanin run` — the workload was correctly terminated after
    /// a lapsed authorization.
    Exit(u8),
}

/// Drive `invocation` through the full S0-S11 sequence.
#[must_use]
pub fn run(invocation: &RunInvocation) -> LaunchOutcome {
    // S1: resolve --profile (client-side only, no agent contact yet).
    let profile = match load_profile(&invocation.profile) {
        Ok(profile) => profile,
        Err(e) => return LaunchOutcome::Failure(e.into()),
    };
    let request = LeaseRequest {
        resource: profile.resource,
        action: profile.action,
    };

    // S2: establish the governed execution context, before connecting.
    let governed_context = NullContext;
    if let Err(e) = governed_context.establish() {
        return LaunchOutcome::Failure(e.into());
    }

    // S3/S4: connect and request a lease. No Command::spawn on any path
    // through this match that isn't LeaseGranted.
    let client = match AgentClient::from_env() {
        Ok(client) => client,
        Err(e) => {
            teardown(&governed_context);
            return LaunchOutcome::Failure(e.into());
        }
    };
    let (lease_id, remaining, grant_observed_at) = match request_initial_lease(&client, &request) {
        Ok(granted) => granted,
        Err(failure) => {
            teardown(&governed_context);
            return LaunchOutcome::Failure(failure);
        }
    };

    // S5: install signal handlers before the workload exists.
    let signal_receiver = match signals::install() {
        Ok(receiver) => receiver,
        Err(e) => {
            // The lease was already granted (enforcement already
            // applied) — release it before reporting failure, same as
            // any other post-grant failure path.
            release(&client, &lease_id);
            teardown(&governed_context);
            return LaunchOutcome::Failure(LaunchFailure::AgentUnavailable(format!(
                "failed to install signal handlers: {e}"
            )));
        }
    };

    // S6: spawn. The one Command::spawn call site in this crate.
    let mut command = Command::new(&invocation.program);
    command.args(&invocation.args);
    // Own process group: a terminal Ctrl-C is otherwise delivered to
    // the child *and* to eltanin (both share eltanin's pgid), so
    // signals::install's forwarding would deliver it twice, violating
    // "exactly once." Named trade-off: an interactive workload that
    // reads the TTY becomes a background process group and receives
    // SIGTTIN — acceptable for MVP 1.0's batch-GPU-compute target; see
    // docs/product/CLI_CONTRACT.md's signal section.
    command.process_group(0);

    match command.spawn() {
        Ok(child) => {
            let outcome = supervise(
                &client,
                &request,
                lease_id,
                remaining,
                grant_observed_at,
                child,
                &signal_receiver,
            );
            teardown(&governed_context);
            outcome_to_exit(outcome)
        }
        Err(e) => {
            // Enforcement was already applied at S4 — release and tear
            // down even though the workload never ran.
            release(&client, &lease_id);
            teardown(&governed_context);
            let code = spawn_failure_code(&e);
            LaunchOutcome::Exit(code)
        }
    }
}

fn request_initial_lease(
    client: &AgentClient,
    request: &LeaseRequest,
) -> Result<(eltanin_core::lease::LeaseId, std::time::Duration, Instant), LaunchFailure> {
    let grant_observed_at = Instant::now();
    let response = client
        .exchange(ClientRequest::RequestLease(request.clone()))
        .map_err(LaunchFailure::from)?;
    match response {
        AgentResponse::LeaseGranted { lease } => {
            Ok((lease.lease_id, lease.remaining, grant_observed_at))
        }
        other => Err(
            classify_response(&other).unwrap_or(LaunchFailure::AgentUnavailable(
                "the agent's response could not be classified".to_string(),
            )),
        ),
    }
}

fn outcome_to_exit(outcome: RunOutcome) -> LaunchOutcome {
    match outcome {
        RunOutcome::WorkloadExited(status) => LaunchOutcome::Exit(status_to_exit_code(status)),
        RunOutcome::AuthorizationLapsed { suppressed } => {
            if let Some(status) = suppressed {
                eprintln!(
                    "eltanin run: authorization lapsed mid-run; the workload's own exit \
                     status ({}) is suppressed in favor of exit {}",
                    status_to_exit_code(status),
                    ExitCode::AuthorizationLapsed.code()
                );
            }
            LaunchOutcome::Exit(ExitCode::AuthorizationLapsed.code())
        }
    }
}

/// Convert a workload's [`ExitStatus`] into the exit-code taxonomy's
/// passthrough rule: its own code verbatim, or `128+N` if terminated by
/// signal `N`.
fn status_to_exit_code(status: ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        // A negative or out-of-u8-range code cannot occur on a Unix
        // waitpid() status — code() only ever returns the low 8 bits.
        u8::try_from(code).unwrap_or(u8::MAX)
    } else if let Some(signal) = status.signal() {
        workload_signal_exit_code(u8::try_from(signal).unwrap_or(u8::MAX))
    } else {
        // Unreachable on a real Unix ExitStatus (it is always either an
        // exit code or a terminating signal), but a taxonomy-correct
        // fallback rather than a panic if that ever changes.
        ExitCode::AgentError.code()
    }
}

fn spawn_failure_code(error: &std::io::Error) -> u8 {
    match error.kind() {
        std::io::ErrorKind::NotFound => 127,
        _ => 126,
    }
}

fn teardown(governed_context: &impl GovernedContext) {
    if let Err(context::GovernedContextError::Failed { reason }) = governed_context.teardown() {
        eprintln!("eltanin run: failed to tear down governed execution context: {reason}");
    }
}
