//! The stable request-dispatch seam for HORO-840 (F-M1-006, HORO-839).
//!
//! [`RequestHandler`] is the one call [`crate::connection`] makes per
//! decoded request. HORO-839 ships it and a trivial default
//! implementation; HORO-840 implements the real one (policy evaluation,
//! lease issue/release) without this crate needing to change.

use eltanin_linux::peer::PeerContext;
use eltanin_protocol::request::ClientRequest;
use eltanin_protocol::response::{AgentResponse, AgentStatusView, ErrorCode};

/// Answers one decoded [`ClientRequest`] against one connection's
/// derived [`PeerContext`].
///
/// # `&self`, not `&mut self`
///
/// The handler is shared across concurrently-served connections
/// (`Arc<dyn RequestHandler>`). An implementation holding mutable state
/// (e.g. a `LeaseIssuer`) must put it behind its own `Mutex` internally.
///
/// **Consequence an implementation must handle**: [`crate::connection`]
/// wraps this call in `catch_unwind` for isolation, so a panic while an
/// internal lock is held poisons that `Mutex` — every later request
/// would then fail for the life of the process unless the
/// implementation recovers the guard explicitly (e.g.
/// `.unwrap_or_else(PoisonError::into_inner)`), rather than `.unwrap()`.
/// Without that, thread-isolation-via-`catch_unwind` turns one
/// connection's panic into a permanent agent outage instead of a single
/// bad response.
///
/// # No `RequestId`, no clock
///
/// The transport owns request correlation (it echoes the id it
/// decoded) and, separately, owns nothing about time — an
/// implementation that needs `now` (to call
/// `eltanin_core::lease::LeaseIssuer::issue`) owns its own
/// [`crate::runtime::AgentClock`]. A handler cannot break either
/// concern because its signature has no way to touch them.
///
/// # `peer.authorizable()` is the gate
///
/// A `RequestLease` implementation calls
/// `eltanin_protocol::request::provenance_for` with
/// `peer.authorizable()?.clone()`, never `peer.observed()` directly —
/// `None` means the kernel credential and `/proc` evidence disagreed or
/// were insufficient, and must be denied
/// (`AgentResponse::LeaseDenied { reason: IndeterminateEvidence }`),
/// never silently treated as good enough. `peer.observed()` is what
/// still goes to the audit trail (F-M1-009) regardless of the outcome.
///
/// # Closes half of HORO-838's `ReleaseLease` obligation
///
/// `peer` is exactly the freshly-derived peer identity
/// `docs/product/SECURITY_MODEL.md`'s "Local IPC trust boundary"
/// section names as what a `ReleaseLease` handler must compare (via
/// `compare_process`/`compare_executable`, both `Same`) against the
/// stored lease's workload identity before calling
/// `eltanin_core::lease::LeaseIssuer::revoke`. No further primitive is
/// needed from this crate for that check.
pub trait RequestHandler: Send + Sync {
    fn handle(&self, request: &ClientRequest, peer: &PeerContext) -> AgentResponse;
}

/// Answers `AgentStatus` genuinely; every other operation returns
/// `Error { Internal }`.
///
/// Deliberately **not** `LeaseDenied` for `RequestLease`/`ReleaseLease`:
/// a denial is a policy statement this handler never makes, since it
/// has no policy backend wired in at all. "No policy backend in this
/// build" is `Internal`, honestly, not a disguised denial that would
/// misrepresent what actually happened.
pub struct StatusOnlyHandler;

impl RequestHandler for StatusOnlyHandler {
    fn handle(&self, request: &ClientRequest, _peer: &PeerContext) -> AgentResponse {
        match request {
            ClientRequest::AgentStatus {} => AgentResponse::Status {
                status: AgentStatusView {
                    protocol_version: eltanin_core::envelope::DOMAIN_SCHEMA_VERSION,
                },
            },
            ClientRequest::RequestLease(_) | ClientRequest::ReleaseLease(_) => {
                AgentResponse::Error {
                    code: ErrorCode::Internal,
                }
            }
        }
    }
}
