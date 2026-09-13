//! Trusted Compute Session integration (F-M2-001, HORO-791): platform
//! session-evidence collection, admission configuration, and the
//! pre-policy admission gate. Lives under `authz/` alongside the
//! existing policy/lease integration — see `tests/agent_architecture_guard.rs`'s
//! `authz`-anchored exemption, which this module relies on unchanged
//! (no product-logic scan registration needed for a new file under
//! `authz/`).
//!
//! # Platform session-evidence collection has no injectable seam
//!
//! Unlike peer-credential derivation (`crate::peer::PeerContextSource`),
//! this module calls `eltanin_linux`/`eltanin_macos`'s plain,
//! pid-keyed `collect_session_key`/`collect_workload_identity`
//! functions directly, `target_os`-selected exactly like
//! `crate::runtime::issuer_instance_id` already does for this agent's
//! own instance id. No test seam is introduced for the same reason
//! `runtime.rs` has none: these functions are pure reads of currently
//! observable kernel state for a given pid, with no side effects to
//! stub and no meaningful non-determinism to control in a test.

use eltanin_core::identity::{Evidence, WorkloadIdentity};
use eltanin_core::session::{EmptyScope, SessionError, SessionKey};

#[cfg(not(target_os = "macos"))]
use eltanin_linux as platform;
#[cfg(target_os = "macos")]
use eltanin_macos as platform;

/// Collect `pid`'s current [`SessionKey`], via the platform collector
/// selected at compile time.
#[must_use]
pub(crate) fn collect_session_key(pid: u32) -> Evidence<SessionKey> {
    platform::collect_session_key(pid)
}

/// Collect `pid`'s current [`WorkloadIdentity`] — used both to derive a
/// new session's anchor leader at establishment time and to re-observe
/// an existing session's anchor leader for liveness, via the same
/// platform collector selected at compile time.
#[must_use]
pub(crate) fn collect_workload_identity(pid: u32) -> WorkloadIdentity {
    platform::collect_workload_identity(pid)
}

/// Agent deployment configuration: whether `RequestLease` requires an
/// active Trusted Compute Session before policy is ever consulted. This
/// is deployment config, not a new `Condition`/policy-DSL variant —
/// `eltanin_core::policy::PolicySet::evaluate` is completely untouched
/// by this ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionRequirement {
    Required,
    #[default]
    NotRequired,
}

/// Why [`crate::authz::AuthorizationHandler`]'s `CreateSession` handling
/// could not establish a session. A thin, `Clone`/`Eq` wrapper over
/// [`SessionError`] plus the one additional failure
/// ([`SessionScope`](eltanin_core::session::SessionScope) construction)
/// that happens before a [`SessionError`] could even be produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionAdmissionError {
    #[error(transparent)]
    EmptyScope(#[from] EmptyScope),
    #[error(transparent)]
    Authority(#[from] SessionError),
}
