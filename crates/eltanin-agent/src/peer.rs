//! Injectable peer-identity derivation (F-M1-006, HORO-839; platform
//! selection added by HORO-1013).
//!
//! [`PeerContextSource`] is the seam that keeps [`crate::connection`]
//! and [`crate::server`] platform-neutral and testable without a real
//! peer-credential-capable environment: tests supply a stub
//! implementation, while [`OsPeerContextSource`] is the real one a
//! deployed agent uses — backed by `eltanin_linux::peer` on Linux and
//! `eltanin_macos::peer` on macOS, selected at compile time by
//! `target_os` so exactly one platform collector ever enters a given
//! build's dependency graph.

use std::os::unix::net::UnixStream;

use eltanin_core::peer::{PeerContext, PeerCredentialError};

#[cfg(not(target_os = "macos"))]
use eltanin_linux as platform;
#[cfg(target_os = "macos")]
use eltanin_macos as platform;

/// Derives a [`PeerContext`] for one connected socket.
pub trait PeerContextSource: Send + Sync {
    /// # Errors
    ///
    /// Returns [`PeerCredentialError`] if the peer's credential itself
    /// cannot be derived. A best-effort observation read failing
    /// *after* the credential is obtained is not an error here — see
    /// the platform collector's own `collect_peer_context` docs.
    fn derive(&self, stream: &UnixStream) -> Result<PeerContext, PeerCredentialError>;
}

/// The real, OS-backed [`PeerContextSource`] — `eltanin_linux::peer` on
/// Linux, `eltanin_macos::peer` on macOS.
pub struct OsPeerContextSource;

impl PeerContextSource for OsPeerContextSource {
    fn derive(&self, stream: &UnixStream) -> Result<PeerContext, PeerCredentialError> {
        platform::peer::collect_peer_context(stream)
    }
}
