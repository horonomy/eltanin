//! Signal handler installation (S5, F-M1-008, HORO-846).
//!
//! Mirrors `eltanin_agent::daemon::run`'s pattern exactly: a dedicated
//! thread blocks on a `signal-hook` iterator (self-pipe backed, not a
//! raw signal handler) and pushes each received signal number onto a
//! channel — no unsafe or non-signal-safe work runs on the signal path,
//! same founder decision (D2, HORO-840) as the agent daemon.
//!
//! Installed at S5, *before* the workload is spawned (S6): a signal
//! arriving in the S5→S6 window is queued on the channel rather than
//! lost, and is forwarded the instant the child exists — the channel,
//! not direct forwarding from the signal thread, is what makes handler
//! installation before spawn actually meaningful.

use std::io;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2};
use signal_hook::iterator::Signals;

/// Every signal `eltanin run` forwards to the workload. Deliberately
/// bounded — `signal-hook` itself refuses to register
/// `SIGKILL`/`SIGSTOP`/`SIGILL`/`SIGFPE`/`SIGSEGV`, and job-control
/// signals (`SIGTSTP`/`SIGCONT`) are out of scope: the contract asks for
/// forwarding, not job control.
pub const FORWARDED: &[i32] = &[SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2];

/// Install signal handlers for every signal in [`FORWARDED`] and start
/// the driving thread. Returns a [`Receiver`] the supervisor polls
/// non-blockingly for signals to forward.
///
/// # Errors
///
/// Returns [`io::Error`] if the signals cannot be registered.
pub fn install() -> io::Result<Receiver<i32>> {
    let mut signals = Signals::new(FORWARDED)?;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for signal in signals.forever() {
            // The workload may already have exited by the time this is
            // drained — the supervisor checks try_wait() before acting
            // on a queued signal, so a send failure here (the receiver
            // dropped because the process is exiting) is expected, not
            // an error to report.
            let _ = sender.send(signal);
        }
    });
    Ok(receiver)
}
