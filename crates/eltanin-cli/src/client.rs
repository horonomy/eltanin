//! UDS client speaking the agent's framed protocol (F-M1-008, HORO-846).
//!
//! The transport is one-request-per-connection
//! (`crates/eltanin-agent/src/connection.rs::serve_connection` reads
//! exactly one frame, dispatches, writes one frame, closes — see
//! `docs/architecture/domain-model.md`'s "lease lifetime is bound to
//! TTL, never to connection lifetime" note). [`AgentClient::exchange`]
//! therefore opens a fresh connection for every request — the initial
//! `RequestLease`, every renewal, and the final `ReleaseLease` are each
//! their own connect/send/recv/close cycle.

use std::env;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use eltanin_core::envelope::Versioned;
use eltanin_protocol::framing::{decode_frame_len, decode_response, encode_request, ProtocolError};
use eltanin_protocol::request::{ClientRequest, RequestBody, RequestId};
use eltanin_protocol::response::AgentResponse;

/// The agent's default socket path (mirrors
/// `eltanin_agent::config::DEFAULT_SOCKET_PATH`, including its per-`target_os`
/// arm added by HORO-1013 — see that constant's doc comment for the
/// macOS rationale) — copied here rather than adding an `eltanin-agent`
/// dependency for one constant; `eltanin-cli` is a client of the
/// agent's wire protocol (`eltanin-protocol`), not of its
/// implementation. `crates/eltanin-cli/tests/docs_sync.rs` pins these
/// two literals together so they cannot silently drift.
#[cfg(target_os = "macos")]
const DEFAULT_SOCKET_PATH: &str = "/var/run/eltanin/agent.sock";

#[cfg(not(target_os = "macos"))]
const DEFAULT_SOCKET_PATH: &str = "/run/eltanin/agent.sock";

/// Client-side I/O timeout. The agent applies its own timeout
/// server-side (`AgentConfig`'s `io_timeout`), but nothing protects
/// *this* side — without a client-side timeout, a wedged or malicious
/// agent could hang `eltanin run` forever while the workload it's
/// supervising (if already spawned) runs unsupervised. Matches the
/// agent's own default.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Why an exchange with the agent failed. Every variant maps to
/// [`crate::exit::ExitCode::AgentUnavailable`] via `LaunchFailure` — the wire
/// distinguishes an `AgentResponse::Error{code}` (a response was
/// received) from these (no usable response was ever received), and
/// only the former reaches [`crate::failure::classify_response`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    #[error("ELTANIN_AGENT_SOCKET is set but not valid UTF-8")]
    SocketPathNotUtf8,
    #[error("could not connect to the agent at {path}: {reason}")]
    Connect { path: String, reason: String },
    #[error("I/O error talking to the agent: {reason}")]
    Io { reason: String },
    #[error("the agent's response could not be decoded: {reason}")]
    Protocol { reason: String },
    #[error("the agent's response named request id {got:?}, expected {expected:?}")]
    RequestIdMismatch {
        expected: RequestId,
        got: Option<RequestId>,
    },
}

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

fn next_request_id() -> RequestId {
    RequestId(NEXT_REQUEST_ID.fetch_add(1, Ordering::SeqCst))
}

/// A client of one agent's Unix Domain Socket.
pub struct AgentClient {
    socket_path: PathBuf,
}

impl AgentClient {
    /// Resolve the agent's socket path from `ELTANIN_AGENT_SOCKET`,
    /// falling back to the documented default. A *set-but-non-UTF-8*
    /// value is a distinct case from "unset" and must not silently fall
    /// through to the default — the same class of bug review caught on
    /// `eltanin-agentd`'s `ELTANIN_AUDIT_LOG` handling (HORO-824).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::SocketPathNotUtf8`] if the variable is set
    /// but not valid Unicode.
    pub fn from_env() -> Result<Self, ClientError> {
        match env::var_os("ELTANIN_AGENT_SOCKET") {
            None => Ok(Self {
                socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
            }),
            Some(path) => {
                let path = path
                    .into_string()
                    .map_err(|_| ClientError::SocketPathNotUtf8)?;
                Ok(Self {
                    socket_path: PathBuf::from(path),
                })
            }
        }
    }

    /// Send `request`, read exactly one response, and return it. Opens
    /// a fresh connection every call — see the module docs for why.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the connection, write, read, or
    /// decode fails, or if the response names a different request id
    /// than the one sent.
    pub fn exchange(&self, request: ClientRequest) -> Result<AgentResponse, ClientError> {
        let request_id = next_request_id();
        let envelope = Versioned::current(RequestBody {
            request_id,
            body: request,
        });
        let framed = encode_request(&envelope).map_err(|e| ClientError::Protocol {
            reason: e.to_string(),
        })?;

        let mut stream =
            UnixStream::connect(&self.socket_path).map_err(|e| ClientError::Connect {
                path: self.socket_path.display().to_string(),
                reason: e.to_string(),
            })?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
            .map_err(|e| ClientError::Io {
                reason: e.to_string(),
            })?;

        stream
            .write_all(&framed)
            .and_then(|()| stream.flush())
            .map_err(|e| ClientError::Io {
                reason: e.to_string(),
            })?;

        let mut header = [0u8; 4];
        read_exact(&mut stream, &mut header)?;
        let len = decode_frame_len(header).map_err(|e| ClientError::Protocol {
            reason: e.to_string(),
        })?;
        let mut body = vec![0u8; len];
        read_exact(&mut stream, &mut body)?;

        let response =
            decode_response(&body).map_err(|e: ProtocolError| ClientError::Protocol {
                reason: e.to_string(),
            })?;

        if response.payload.request_id != Some(request_id) {
            return Err(ClientError::RequestIdMismatch {
                expected: request_id,
                got: response.payload.request_id,
            });
        }
        Ok(response.payload.body)
    }
}

fn read_exact(stream: &mut UnixStream, buf: &mut [u8]) -> Result<(), ClientError> {
    stream.read_exact(buf).map_err(|e| ClientError::Io {
        reason: e.to_string(),
    })
}
