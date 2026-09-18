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

use eltanin_core::identity::{Evidence, EvidenceSource, WorkloadIdentity};
use eltanin_core::session::{EmptyScope, HostId, SessionError, SessionKey, SessionNonce};

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

/// Collect this host's locally-resolved identity (HORO-1278), via
/// `rustix::system::uname`'s nodename — never network-resolved. See
/// [`HostId`]'s own doc for what this does and does not defend against:
/// a hostname is mutable by the host's own owner and is not a security
/// boundary against a local attacker; its only job is cross-host session
/// reuse rejection for the (currently inert, since session state is
/// agent-in-memory, single-host) case where session state might someday
/// be shared/persisted across hosts.
///
/// `uname(2)` itself cannot fail for an ordinary call — the only failure
/// mode this function can report is a non-UTF-8 nodename, which is
/// reported as [`Evidence::Missing`] rather than lossily converted,
/// matching this module's platform collectors' "never a default value"
/// discipline.
#[must_use]
pub(crate) fn collect_host_id() -> Evidence<HostId> {
    let uname = rustix::system::uname();
    match uname.nodename().to_str() {
        Ok(nodename) => Evidence::Present {
            value: HostId(nodename.to_string()),
            source: EvidenceSource::KernelObserved,
        },
        Err(_) => Evidence::Missing {
            reason: "hostname is not valid UTF-8".to_string(),
        },
    }
}

/// Generate a fresh [`SessionNonce`] by reading 32 bytes from the OS
/// CSPRNG (`/dev/urandom`), for
/// `eltanin_core::session::SessionAuthority::establish` to bind onto a
/// newly established `eltanin_core::session::TrustedSession`.
/// Lives here, not in `eltanin-core`, deliberately: that crate reads no
/// non-deterministic external state itself (mirroring its own
/// `MonotonicTime` being injected, never read from a clock inside it) —
/// this is the one call site that performs the actual I/O, exactly the
/// same division of responsibility `crate::runtime::AgentClock` already
/// establishes for time.
///
/// This value does no security work today (see [`SessionNonce`]'s own
/// doc) — reading `/dev/urandom` failing is therefore not treated as
/// fatal to session establishment; a failure falls back to an
/// all-zero nonce rather than aborting `CreateSession` over an inert
/// extension seam.
#[must_use]
pub(crate) fn generate_session_nonce() -> SessionNonce {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    let read = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes));
    if read.is_err() {
        bytes = [0u8; 32];
    }
    SessionNonce::from_bytes(bytes)
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
