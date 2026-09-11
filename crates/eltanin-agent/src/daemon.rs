//! Transport composition and `SIGTERM`/`SIGINT` wiring (F-M1-006,
//! HORO-840).
//!
//! [`run`] binds the socket, builds the [`AgentServer`], installs the
//! signal thread, and blocks until shutdown. It names only transport
//! types (`AgentConfig`, `BoundSocket`, `AgentServer`,
//! `RequestHandler`, `PeerContextSource`) — never anything from
//! [`crate::authz`] — so `tests/agent_architecture_guard.rs` scans it as
//! an ordinary transport module.

use std::sync::Arc;
use std::thread;

use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use crate::config::AgentConfig;
use crate::handler::RequestHandler;
use crate::listener::{BoundSocket, StartupError};
use crate::peer::PeerContextSource;
use crate::server::{AgentServer, ShutdownReport};

/// Bind `config`'s socket, run the accept loop, and drain on
/// `SIGTERM`/`SIGINT`.
///
/// The signal thread does no unsafe or non-signal-safe custom work: it
/// blocks on [`Signals::forever`] (a `signal-hook` iterator backed by a
/// self-pipe, not a raw signal handler) and, on any of the two watched
/// signals, calls [`crate::server::ShutdownHandle::shutdown`] — an
/// ordinary safe method, idempotent under repeated calls (see its own
/// docs), and this loop's `break` after the first signal means a second
/// `SIGTERM` during drain simply has no signal thread left to act on it,
/// never a second concurrent `shutdown()` racing the first from this
/// thread. Repeated signals cannot double-close the socket, double-
/// release a slot, or corrupt lease/backend state: `shutdown()` only
/// ever sets a flag and wakes `accept()`, and every state-mutating path
/// in [`AgentServer::run`]'s accept loop and drain runs on the one
/// original accept-loop thread, never on this signal thread.
///
/// # Errors
///
/// Returns [`StartupError`] if the socket cannot be bound.
pub fn run(
    config: AgentConfig,
    handler: Arc<dyn RequestHandler>,
    peers: Arc<dyn PeerContextSource>,
) -> Result<ShutdownReport, StartupError> {
    let socket = BoundSocket::bind(&config)?;
    let server = AgentServer::new(socket, config, handler, peers);
    let shutdown = server.shutdown_handle();

    // signal-hook's own docs: constructing `Signals` registers the
    // handlers; the iterator must be driven (here, on a dedicated
    // thread) for signals to actually be delivered to this process
    // rather than merely queued.
    let mut signals =
        Signals::new([SIGTERM, SIGINT]).map_err(|e| StartupError::Io { reason: e.to_string() })?;
    thread::spawn(move || {
        // Exactly one shutdown per process lifetime: the first signal
        // observed breaks out of the loop, so no later SIGTERM/SIGINT
        // (delivered during drain or after) reaches another
        // `shutdown()` call from this thread.
        if signals.forever().next().is_some() {
            shutdown.shutdown();
        }
    });

    server.run()
}
