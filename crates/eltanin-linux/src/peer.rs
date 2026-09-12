//! Peer credential derivation for a connected Unix Domain Socket peer
//! (F-M1-006, HORO-839).
//!
//! [`collect_peer_context`] is the one function in this crate that
//! answers "who is on the other end of this socket": it reads the
//! kernel-captured `SO_PEERCRED` credential (pid/effective-uid/
//! effective-gid, fixed at `connect()` time and immune to anything the
//! peer does afterwards) and cross-checks it against a fresh `/proc`
//! read for that pid, so the caller gets both an unforgeable credential
//! and an explicit signal for whether the two sources still agree. The
//! shared credential contract ([`PeerCredential`], [`PeerConsistency`],
//! [`PeerContext`], [`PeerCredentialError`]) lives in
//! `eltanin_core::peer` (relocated there by HORO-1013 so
//! `crates/eltanin-macos` can produce the same contract without
//! depending on this crate) and is re-exported here for existing
//! callers.
//!
//! # Why cross-check at all
//!
//! `SO_PEERCRED` is captured once, at `connect()`. A `/proc/<pid>` read
//! happens afterwards, at an arbitrary later instant. Between those two
//! points the pid could have been reused by an unrelated process (the
//! peer exited and something else got the same pid), or — on a
//! namespace-unaware kernel path — describe a process this agent cannot
//! actually see.
//!
//! **What this cross-check does and does not catch, precisely.** The
//! uid comparison in [`PeerConsistency`] only ever *reduces confidence*
//! that a PID-reuse race happened — it detects it exclusively when the
//! recycled pid landed on a process running as a **different** uid than
//! the original peer. In this crate's MVP 1.0 primary deployment
//! (`eltanin-agent`'s own docs: agent and every workload run as the
//! same uid), a recycled pid almost always still belongs to that same
//! uid, so [`PeerConsistency::Consistent`] provides essentially no
//! protection against a same-uid PID-reuse race in that mode — it is
//! real defense-in-depth for a multi-uid host, not a general PID-reuse
//! guard. `SO_PEERCRED` carries no start-time field, so nothing derived
//! from it alone can be cross-checked against a `ProcessStartToken`
//! atomically captured at `connect()` time; closing this residually
//! requires either an OS-level atomic peer handle (e.g. a `pidfd`
//! obtained immediately post-accept) or accepting the same PID-reuse
//! race `WorkloadIdentity::compare_process` already documents for every
//! other `/proc`-based collector in this crate. Left as a named,
//! honestly-scoped limitation rather than an unstated assumption; not
//! closed by this module.
//!
//! # Real vs. effective uid
//!
//! `SO_PEERCRED` reports the peer's **effective** uid/gid (the kernel's
//! `cred_to_ucred()` fills the `ucred` structure from `cred->euid`).
//! [`eltanin_core::identity::WorkloadIdentity::uid`] is the **real**
//! uid ([`crate::collect_workload_identity`]'s established semantics —
//! not changed here). [`eltanin_core::peer::classify_consistency`]
//! reconciles these — see its own docs.
//!
//! # Known limitation
//!
//! `SO_PEERCRED`'s `uid`/`gid` pass through the kernel's
//! `from_kuid_munged()`/`from_kgid_munged()`, so a peer whose real
//! identity is unmappable into this agent's user namespace is reported
//! as the overflow id (typically 65534) rather than failing outright.
//! `/proc/<pid>/status` is munged into the same namespace, so the two
//! sources normally still agree in that case — but an operator relying
//! on the numeric uid value for anything beyond the consistency check
//! this module performs should be aware the overflow id is not a real
//! identity.

pub use eltanin_core::peer::{PeerConsistency, PeerContext, PeerCredential, PeerCredentialError};

/// Derive the connected peer's credential and cross-checked context for
/// `stream`.
///
/// # Errors
///
/// Returns [`PeerCredentialError::Io`] if the kernel credential itself
/// cannot be read (the socket option call failed);
/// [`PeerCredentialError::UnsupportedPlatform`] on any non-Linux target.
/// A `/proc` read failing *after* the credential is obtained is not an
/// error from this function — it is reported as
/// [`PeerConsistency::Indeterminate`], since the credential itself was
/// still successfully derived.
pub fn collect_peer_context(
    stream: &std::os::unix::net::UnixStream,
) -> Result<PeerContext, PeerCredentialError> {
    imp::collect_peer_context(stream)
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{PeerContext, PeerCredential, PeerCredentialError};
    use std::os::unix::net::UnixStream;

    pub(super) fn collect_peer_context(
        stream: &UnixStream,
    ) -> Result<PeerContext, PeerCredentialError> {
        let ucred =
            rustix::net::sockopt::socket_peercred(stream).map_err(|e| PeerCredentialError::Io {
                reason: e.to_string(),
            })?;
        let pid = ucred.pid.as_raw_nonzero().get();
        // `as_raw_nonzero()` guarantees this is > 0, so the cast is
        // exact for any pid a real Linux kernel can assign.
        let pid = u32::try_from(pid).unwrap_or(0);
        let credential = PeerCredential::from_kernel(pid, ucred.uid.as_raw(), ucred.gid.as_raw());

        if pid == 0 {
            let observed = crate::collect_execution_context(0);
            return Ok(PeerContext::peer_unmapped(credential, observed));
        }

        let observed = crate::collect_execution_context(pid);
        let (real_uid, effective_uid) = crate::read_status_ids(pid, "Uid:");

        Ok(PeerContext::from_kernel_observation(
            credential,
            observed,
            &real_uid,
            &effective_uid,
        ))
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::{PeerContext, PeerCredentialError};
    use std::os::unix::net::UnixStream;

    pub(super) fn collect_peer_context(
        _stream: &UnixStream,
    ) -> Result<PeerContext, PeerCredentialError> {
        Err(PeerCredentialError::UnsupportedPlatform)
    }
}
