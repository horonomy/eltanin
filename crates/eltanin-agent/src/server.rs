//! Accept loop, connection cap, and shutdown coordination (F-M1-006,
//! HORO-839).

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::config::AgentConfig;
use crate::connection::serve_connection;
use crate::handler::RequestHandler;
use crate::listener::{BoundSocket, StartupError};
use crate::peer::PeerContextSource;

/// A cloneable handle that requests [`AgentServer::run`] stop accepting
/// new connections and begin its drain.
#[derive(Clone)]
pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
    socket_path: PathBuf,
}

impl ShutdownHandle {
    /// Request shutdown. Safe to call from any thread, any number of
    /// times.
    pub fn shutdown(&self) {
        self.flag.store(true, Ordering::SeqCst);
        // accept() has no timeout, so the flag alone cannot unblock a
        // loop with no new connections arriving. A self-connect wakes
        // it; the woken iteration observes the flag and breaks before
        // this connection is ever dispatched to a handler.
        let _ = UnixStream::connect(&self.socket_path);
    }
}

/// What happened during [`AgentServer::run`]'s drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    /// Connections whose handler thread finished within `drain_timeout`.
    pub drained: usize,
    /// Connections still running when `drain_timeout` elapsed. Rust
    /// cannot forcibly kill a thread — these are detached, not
    /// terminated, and are bounded in wall-clock time by `io_timeout`
    /// regardless, since [`serve_connection`] applies it to every read
    /// and write.
    pub abandoned: usize,
}

/// Owns the accept loop for one bound socket.
pub struct AgentServer {
    socket: BoundSocket,
    config: AgentConfig,
    handler: Arc<dyn RequestHandler>,
    peers: Arc<dyn PeerContextSource>,
    shutdown_flag: Arc<AtomicBool>,
}

impl AgentServer {
    #[must_use]
    pub fn new(
        socket: BoundSocket,
        config: AgentConfig,
        handler: Arc<dyn RequestHandler>,
        peers: Arc<dyn PeerContextSource>,
    ) -> Self {
        Self {
            socket,
            config,
            handler,
            peers,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            flag: Arc::clone(&self.shutdown_flag),
            socket_path: self.socket.path().to_path_buf(),
        }
    }

    /// Accept connections until [`ShutdownHandle::shutdown`] is called,
    /// then drain outstanding connections up to `drain_timeout` before
    /// returning. Consumes `self`: the socket (and its `Drop`-based
    /// path cleanup) lives exactly as long as one `run` call.
    ///
    /// # Errors
    ///
    /// This implementation always returns `Ok` — the `Result` return
    /// type is kept so a future accept-loop-level failure mode does not
    /// require changing this method's signature.
    pub fn run(self) -> Result<ShutdownReport, StartupError> {
        let active = Arc::new(AtomicUsize::new(0));
        let mut connection_threads: Vec<JoinHandle<()>> = Vec::new();
        let max_connections = self.config.max_connections();
        let io_timeout = self.config.io_timeout();

        for incoming in self.socket.listener().incoming() {
            if self.shutdown_flag.load(Ordering::SeqCst) {
                break;
            }
            let Ok(stream) = incoming else { continue };

            if active.load(Ordering::SeqCst) >= max_connections {
                // Over capacity: close immediately with no response.
                // ErrorCode has no Busy/Overloaded variant — see this
                // crate's lib.rs docs on why that is an accepted MVP
                // 1.0 limitation rather than a reason to change a
                // separately-merged wire schema.
                drop(stream);
                continue;
            }
            active.fetch_add(1, Ordering::SeqCst);

            let handler = Arc::clone(&self.handler);
            let peers = Arc::clone(&self.peers);
            let slot = Arc::clone(&active);
            connection_threads.push(thread::spawn(move || {
                struct SlotGuard(Arc<AtomicUsize>);
                impl Drop for SlotGuard {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                let _slot_guard = SlotGuard(slot);
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    serve_connection(stream, io_timeout, handler.as_ref(), peers.as_ref());
                }));
            }));
        }

        Ok(drain(connection_threads, self.config.drain_timeout()))
    }
}

/// Join every handle, waiting no longer than `drain_timeout` in total.
/// `std::thread::JoinHandle` has no timed join, so completion is
/// polled — the poll interval only affects how promptly a *finished*
/// thread is reaped, never how long shutdown can block, which is capped
/// by `drain_timeout` regardless of how many connections are still
/// running.
fn drain(handles: Vec<JoinHandle<()>>, drain_timeout: Duration) -> ShutdownReport {
    let deadline = Instant::now() + drain_timeout;
    let mut drained = 0;
    let mut abandoned = 0;
    for handle in handles {
        loop {
            if handle.is_finished() {
                let _ = handle.join();
                drained += 1;
                break;
            }
            if Instant::now() >= deadline {
                abandoned += 1;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    ShutdownReport { drained, abandoned }
}
