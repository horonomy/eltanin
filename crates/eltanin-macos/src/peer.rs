//! Peer credential derivation for a connected Unix Domain Socket peer on
//! macOS (F-M1-010, HORO-1013).
//!
//! [`collect_peer_context`] combines two distinct macOS socket options:
//!
//! - `SOL_LOCAL`/`LOCAL_PEERCRED` (`nix::sys::socket::sockopt::LocalPeerCred`)
//!   returns an `xucred`: the peer's **effective** uid/gid, captured
//!   once at `connect()` time (XNU's `unp_connect` copies the
//!   connecting process's credential into `unp_peercred` under
//!   `UNP_HAVEPC`) — connect-time-fixed, the same strength guarantee as
//!   Linux's `SO_PEERCRED` uid/gid.
//! - `SOL_LOCAL`/`LOCAL_PEERPID` (`nix::sys::socket::sockopt::LocalPeerPid`)
//!   returns the peer's pid — **not** connect-time-fixed. XNU stores it
//!   in the socket's `last_pid` field, which
//!   `so_update_last_owner_locked` updates on socket operations, so
//!   passing the connected file descriptor to another process and
//!   having that process operate on the socket changes the pid this
//!   option reports.
//!
//! # Why the peer-consistency cross-check matters more here than on Linux
//!
//! Because `LOCAL_PEERPID` is not connect-time-fixed, this crate's
//! effective-uid cross-check (`eltanin_core::peer::classify_consistency`,
//! comparing `xucred`'s connect-time uid against the uid a fresh
//! `libproc` lookup reports for the `LOCAL_PEERPID` pid) is the *only*
//! thing binding the strong, connect-time-fixed credential to the pid
//! everything downstream keys on. A cross-uid file-descriptor hand-off
//! between `connect()` and this collector's read produces
//! `PeerConsistency::CredentialDivergence` (or `Indeterminate` if the
//! new pid cannot be inspected at all), so [`PeerContext::authorizable`]
//! returns `None` and the request fails closed. A **same-uid**
//! hand-off is not caught by this cross-check — named here as a
//! residual limitation, in exactly the shape
//! `crates/eltanin-linux/src/peer.rs`'s module docs already use for
//! Linux's own same-uid PID-reuse gap. See ADR 0008 for the full
//! analysis and the rejected `LOCAL_PEERTOKEN` alternative (it would not
//! close this gap either, since XNU derives it from the same `last_pid`
//! field).
//!
//! [`PeerContext`]: eltanin_core::peer::PeerContext
//!
//! # Mitigation, not closure
//!
//! [`crate::peer::collect_peer_context`] is called by
//! `eltanin-agent::connection::serve_connection` immediately after
//! `accept()`, before the first request frame is read — narrowing, but
//! not eliminating, the window in which a hand-off could occur.

use eltanin_core::peer::{PeerContext, PeerCredentialError};

/// Derive the connected peer's credential and cross-checked context for
/// `stream`.
///
/// # Errors
///
/// Returns [`PeerCredentialError::Io`] if the kernel credential itself
/// cannot be read (either socket option call failed, or `xucred`'s
/// version/group-count fields are not in the shape this collector
/// expects); [`PeerCredentialError::UnsupportedPlatform`] on any
/// non-macOS target. A subsequent process-state read failing after the
/// credential is obtained is not an error from this function — it is
/// reported as `PeerConsistency::Indeterminate`, since the credential
/// itself was still successfully derived.
pub fn collect_peer_context(
    stream: &std::os::unix::net::UnixStream,
) -> Result<PeerContext, PeerCredentialError> {
    imp::collect_peer_context(stream)
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{PeerContext, PeerCredentialError};
    use eltanin_core::identity::{Evidence, EvidenceSource};
    use nix::sys::socket::{getsockopt, sockopt};
    use std::os::unix::net::UnixStream;

    /// `XuCred::version()` this collector was written against
    /// (`nix::sys::socket::XuCred` is a safe wrapper over the kernel's
    /// `xucred` struct — see `nix::libc::XUCRED_VERSION`). A version
    /// mismatch means the kernel ABI shape differs from what this code
    /// assumes — refuse rather than guess.
    const XUCRED_VERSION: u32 = nix::libc::XUCRED_VERSION;

    // `effective_uid`/`effective_gid` are the correct, precise names for
    // these two independently-derived values (see the module docs above
    // on why "uid"/"gid" alone would be ambiguous with a real-uid/gid) —
    // clippy's similarity heuristic is a false positive here, not a
    // naming problem to fix.
    #[allow(clippy::similar_names)]
    pub(super) fn collect_peer_context(
        stream: &UnixStream,
    ) -> Result<PeerContext, PeerCredentialError> {
        let xucred =
            getsockopt(stream, sockopt::LocalPeerCred).map_err(|e| PeerCredentialError::Io {
                reason: format!("LOCAL_PEERCRED: {e}"),
            })?;

        if xucred.version() != XUCRED_VERSION {
            return Err(PeerCredentialError::Io {
                reason: format!(
                    "LOCAL_PEERCRED returned unexpected xucred version {} (expected {XUCRED_VERSION})",
                    xucred.version()
                ),
            });
        }
        // `XuCred::groups()` returns the kernel's fixed-size `cr_groups`
        // array (always 16 entries on Darwin) — its first entry is the
        // effective gid by convention, documented as such by both the
        // kernel and `nix`'s own doc comment on `groups()`. `nix`
        // exposes no `cr_ngroups` accessor to check separately (the
        // field exists in `libc::xucred` but `XuCred` does not surface
        // it), so this collector relies on the documented convention
        // rather than a length check `nix`'s safe wrapper cannot
        // express.
        let effective_uid = xucred.uid();
        let Some(&effective_gid) = xucred.groups().first() else {
            return Err(PeerCredentialError::Io {
                reason: "LOCAL_PEERCRED returned an empty group list; no effective gid available"
                    .to_string(),
            });
        };

        let peer_pid =
            getsockopt(stream, sockopt::LocalPeerPid).map_err(|e| PeerCredentialError::Io {
                reason: format!("LOCAL_PEERPID: {e}"),
            })?;

        // Unlike Linux's SO_PEERCRED, LOCAL_PEERCRED carries no pid at
        // all — LOCAL_PEERPID is a separate, live-read (not
        // connect-time-fixed) socket option. There is no pid-0
        // "unmapped namespace" case on macOS (no pid namespaces), so
        // a non-positive pid here means the kernel could not identify
        // the peer at all, treated the same as eltanin-linux's
        // PeerUnmapped case for the same reason: it must never fall
        // through to inspecting pid 0.
        if peer_pid <= 0 {
            let credential =
                eltanin_core::peer::PeerCredential::from_kernel(0, effective_uid, effective_gid);
            let observed = crate::collect_execution_context(0);
            return Ok(PeerContext::peer_unmapped(credential, observed));
        }
        // SAFETY-FREE: `peer_pid > 0` was just checked; this cast is
        // exact for any pid a real Darwin kernel can assign (`pid_t`
        // is `i32`, and the process id space is far below `u32::MAX`).
        let pid = u32::try_from(peer_pid).unwrap_or(0);

        let credential =
            eltanin_core::peer::PeerCredential::from_kernel(pid, effective_uid, effective_gid);
        let observed = crate::collect_execution_context(pid);
        let (real_uid, effective_uid_observed) = read_uids(pid);

        Ok(PeerContext::from_kernel_observation(
            credential,
            observed,
            &real_uid,
            &effective_uid_observed,
        ))
    }

    /// Read the (real, effective) uid pair libproc reports for `pid`,
    /// mirroring `eltanin-linux::read_status_ids`'s two-value shape so
    /// `classify_consistency` can reconcile either against the peer's
    /// kernel-reported effective uid.
    fn read_uids(pid: u32) -> (Evidence<u32>, Evidence<u32>) {
        let signed_pid = match i32::try_from(pid) {
            Ok(p) => p,
            Err(e) => {
                let reason = format!("pid {pid} out of range: {e}");
                return (
                    Evidence::Missing {
                        reason: reason.clone(),
                    },
                    Evidence::Missing { reason },
                );
            }
        };
        match libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(signed_pid, 0) {
            Ok(info) => (
                Evidence::Present {
                    value: info.pbi_ruid,
                    source: EvidenceSource::KernelObserved,
                },
                Evidence::Present {
                    value: info.pbi_uid,
                    source: EvidenceSource::KernelObserved,
                },
            ),
            Err(e) => {
                let reason = format!("proc_pidinfo({pid}): {e}");
                (
                    Evidence::Missing {
                        reason: reason.clone(),
                    },
                    Evidence::Missing { reason },
                )
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use eltanin_core::peer::PeerConsistency;

        #[test]
        fn a_self_connected_peer_reports_its_own_credential_as_consistent() {
            let (a, b) = UnixStream::pair().expect("create a connected socket pair");
            let context =
                collect_peer_context(&a).expect("LOCAL_PEERCRED/LOCAL_PEERPID must succeed");
            drop(b); // keep the peer end alive until after derivation

            assert_eq!(context.credential().pid(), std::process::id());
            assert_eq!(context.consistency(), &PeerConsistency::Consistent);
            assert!(
                context.authorizable().is_some(),
                "a Consistent peer must be authorizable"
            );
            assert_eq!(context.observed().workload.pid, std::process::id());
        }

        #[test]
        fn effective_uid_matches_the_process_euid() {
            let (a, b) = UnixStream::pair().expect("create a connected socket pair");
            let context =
                collect_peer_context(&a).expect("LOCAL_PEERCRED/LOCAL_PEERPID must succeed");
            drop(b);

            let self_identity = crate::collect_workload_identity(std::process::id());
            let real_uid = self_identity.uid.value().copied();
            assert_eq!(Some(context.credential().effective_uid()), real_uid);
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::{PeerContext, PeerCredentialError};
    use std::os::unix::net::UnixStream;

    pub(super) fn collect_peer_context(
        _stream: &UnixStream,
    ) -> Result<PeerContext, PeerCredentialError> {
        Err(PeerCredentialError::UnsupportedPlatform)
    }
}
