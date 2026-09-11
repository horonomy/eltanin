//! Injectable peer-identity derivation (F-M1-006, HORO-839).
//!
//! [`PeerContextSource`] is the seam that keeps [`crate::connection`]
//! and [`crate::server`] platform-neutral and testable without a real
//! Linux `/proc`/`SO_PEERCRED` environment: tests supply a stub
//! implementation, while [`LinuxPeerContextSource`] is the real one a
//! deployed agent uses.

use std::os::unix::net::UnixStream;

use eltanin_linux::peer::{collect_peer_context, PeerContext, PeerCredentialError};

/// Derives a [`PeerContext`] for one connected socket.
pub trait PeerContextSource: Send + Sync {
    /// # Errors
    ///
    /// Returns [`PeerCredentialError`] if the peer's credential itself
    /// cannot be derived. A `/proc` read failing *after* the credential
    /// is obtained is not an error here — see
    /// [`eltanin_linux::peer::collect_peer_context`]'s own docs.
    fn derive(&self, stream: &UnixStream) -> Result<PeerContext, PeerCredentialError>;
}

/// The real, Linux-backed [`PeerContextSource`].
pub struct LinuxPeerContextSource;

impl PeerContextSource for LinuxPeerContextSource {
    fn derive(&self, stream: &UnixStream) -> Result<PeerContext, PeerCredentialError> {
        collect_peer_context(stream)
    }
}
