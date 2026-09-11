//! S6-S11: spawn-adjacent supervision — signal forwarding, lease
//! renewal, workload wait, and release (F-M1-008, HORO-846).
//!
//! See `docs/product/CLI_CONTRACT.md`'s launch state machine and its
//! "Lease renewal (within S7)" section for the full contract this
//! module implements.

use std::io::Write as _;
use std::process::{Child, ExitStatus};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use eltanin_core::lease::LeaseId;
use eltanin_protocol::request::{ClientRequest, LeaseRequest, ReleaseRequest};
use eltanin_protocol::response::AgentResponse;
use rustix::process::{kill_process, kill_process_group, Pid, Signal};

use crate::client::AgentClient;

/// How often the supervisor loop wakes to check the child, drain queued
/// signals, and check renewal/lapse deadlines.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// How long a lapsed-authorization termination waits for the workload
/// to exit after `SIGTERM` before escalating to `SIGKILL`.
const TERMINATION_GRACE: Duration = Duration::from_secs(5);

/// Minimum spacing between renewal attempts, so a very short granted
/// `remaining` cannot produce a hot loop against the agent.
const MIN_RENEWAL_RETRY_INTERVAL: Duration = Duration::from_millis(500);

/// How long to wait after a failed renewal attempt before retrying.
const RENEWAL_RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// Bounded retry for `ReleaseLease` (S9): a failure here is a stderr
/// warning, never a change to the workload's exit status.
const RELEASE_RETRY_BACKOFFS: &[Duration] =
    &[Duration::from_millis(100), Duration::from_millis(200)];

/// The result of supervising a spawned workload through to exit or a
/// lapsed-authorization termination.
#[derive(Debug, Clone, Copy)]
pub enum RunOutcome {
    /// The workload exited on its own (normally or via signal).
    WorkloadExited(ExitStatus),
    /// Authorization lapsed mid-run — renewal kept failing until the
    /// current lease's deadline — and `eltanin run` terminated the
    /// workload. `suppressed` is the workload's own status if it
    /// happened to exit during the termination grace period, so it can
    /// be named in the exit-76 message rather than silently lost.
    AuthorizationLapsed { suppressed: Option<ExitStatus> },
}

/// Renewal state tracked across the poll loop.
struct Renewal {
    lease_id: LeaseId,
    /// When the current lease expires, computed from a clock reading
    /// taken *before* the grant request was sent — never later than the
    /// agent's true expiry.
    deadline: Instant,
    /// When to next attempt a renewal (roughly half of `remaining` at
    /// grant time; reset on every attempt, success or failure).
    renew_at: Instant,
}

/// Supervise `child` through to exit, maintaining the lease it was
/// granted under.
///
/// `request` is the same `(resource, action)` the initial grant used —
/// a renewal is a fresh `RequestLease` over it, not an "extend"
/// operation (MVP 1.0 has no such operation; see
/// `docs/adr/0003-scoped-expiring-compute-lease.md`).
#[must_use]
pub fn supervise(
    client: &AgentClient,
    request: &LeaseRequest,
    initial_lease_id: LeaseId,
    initial_remaining: Duration,
    grant_observed_at: Instant,
    mut child: Child,
    signals: &Receiver<i32>,
) -> RunOutcome {
    let mut renewal = Renewal {
        lease_id: initial_lease_id,
        deadline: grant_observed_at + initial_remaining,
        renew_at: grant_observed_at + initial_remaining / 2,
    };
    let child_pid = child.id();

    loop {
        if let Some(status) = child.try_wait().unwrap_or(None) {
            release(client, &renewal.lease_id);
            return RunOutcome::WorkloadExited(status);
        }

        for signal in signals.try_iter() {
            forward_to_child(child_pid, signal);
        }

        let now = Instant::now();
        if now >= renewal.deadline {
            let suppressed = terminate_for_lapsed_authorization(&mut child);
            release(client, &renewal.lease_id);
            return RunOutcome::AuthorizationLapsed { suppressed };
        }
        if now >= renewal.renew_at {
            renew(client, request, &mut renewal);
        }

        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Attempt a renewal. On grant, adopt the new lease and release the
/// old one (acquire-then-release — the resource is never briefly
/// unleased, and the old release cannot tear down the new grant's
/// enforcement, since another live lease on the same resource already
/// exists by the time it's released). On denial, error, or a
/// connection failure, **retry** rather than terminate — the old lease
/// is still valid until its own deadline, so terminating early on a
/// renewal setback would be a fail-*closed* bug that kills authorized
/// work. Only crossing `deadline` (checked by the caller) terminates.
fn renew(client: &AgentClient, request: &LeaseRequest, renewal: &mut Renewal) {
    let attempted_at = Instant::now();
    match client.exchange(ClientRequest::RequestLease(request.clone())) {
        Ok(AgentResponse::LeaseGranted { lease }) => {
            let old_lease_id = std::mem::replace(&mut renewal.lease_id, lease.lease_id);
            renewal.deadline = attempted_at + lease.remaining;
            renewal.renew_at = attempted_at + lease.remaining / 2;
            release(client, &old_lease_id);
        }
        Ok(_) | Err(_) => {
            renewal.renew_at = next_renewal_retry(attempted_at, renewal.deadline);
        }
    }
}

fn next_renewal_retry(attempted_at: Instant, deadline: Instant) -> Instant {
    let backed_off = attempted_at + RENEWAL_RETRY_BACKOFF;
    let floored = attempted_at + MIN_RENEWAL_RETRY_INTERVAL;
    backed_off.max(floored).min(deadline)
}

/// Forward `signal` to the direct child only — the literal reading of
/// "every signal that would have reached the workload... is forwarded
/// to it exactly once." An unrecognized signal number is dropped rather
/// than forwarded blind.
fn forward_to_child(child_pid: u32, signal: i32) {
    let Some(pid) = pid_from_u32(child_pid) else {
        return;
    };
    let Some(sig) = Signal::from_named_raw(signal) else {
        eprintln!("eltanin run: dropping unrecognized signal {signal}, not forwarded");
        return;
    };
    if let Err(e) = kill_process(pid, sig) {
        eprintln!("eltanin run: failed to forward signal {signal} to the workload: {e}");
    }
}

/// Terminate the workload's whole process group on a lapsed
/// authorization: the fail-closed goal here is that no descendant keeps
/// touching the protected resource, not politeness to one pid — unlike
/// [`forward_to_child`], which only ever targets the direct child.
/// `eltanin run` puts the child in its own process group at spawn
/// (`launch.rs`), so the child's pid is also its process group id.
fn terminate_for_lapsed_authorization(child: &mut Child) -> Option<ExitStatus> {
    let Some(pgid) = pid_from_u32(child.id()) else {
        return child.try_wait().unwrap_or(None);
    };
    let _ = kill_process_group(pgid, Signal::TERM);

    let deadline = Instant::now() + TERMINATION_GRACE;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap_or(None) {
            return Some(status);
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    let _ = kill_process_group(pgid, Signal::KILL);
    // Reap the process so it doesn't become a zombie; std's own
    // SIGKILL-then-wait is a safe fallback if the group-level kill
    // above somehow missed the direct child (e.g. it already exited).
    let _ = child.kill();
    child.wait().ok()
}

fn pid_from_u32(pid: u32) -> Option<Pid> {
    i32::try_from(pid).ok().and_then(Pid::from_raw)
}

/// Release `lease_id` with bounded retry. A failure warns on stderr and
/// names the `eltanin-explain --pid` next action — it never changes the
/// workload's exit status, since this always runs after the exit status
/// is already known (or about to be returned).
pub(crate) fn release(client: &AgentClient, lease_id: &LeaseId) {
    let attempts = 1 + RELEASE_RETRY_BACKOFFS.len();
    for attempt in 0..attempts {
        match client.exchange(ClientRequest::ReleaseLease(ReleaseRequest {
            lease_id: lease_id.clone(),
        })) {
            Ok(AgentResponse::LeaseReleased { .. }) => return,
            _ => {
                if let Some(backoff) = RELEASE_RETRY_BACKOFFS.get(attempt) {
                    std::thread::sleep(*backoff);
                }
            }
        }
    }
    let mut stderr = std::io::stderr();
    let _ = writeln!(
        stderr,
        "eltanin run: failed to release lease {lease_id:?} after {attempts} attempts; run \
         `eltanin-explain --pid {}` for the full decision record",
        std::process::id()
    );
}
