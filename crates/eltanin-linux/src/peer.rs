//! Peer credential derivation for a connected Unix Domain Socket peer
//! (F-M1-006, HORO-839).
//!
//! [`collect_peer_context`] is the one function in this crate that
//! answers "who is on the other end of this socket": it reads the
//! kernel-captured `SO_PEERCRED` credential (pid/effective-uid/
//! effective-gid, fixed at `connect()` time and immune to anything the
//! peer does afterwards) and cross-checks it against a fresh `/proc`
//! read for that pid, so the caller gets both an unforgeable credential
//! and an explicit signal for whether the two sources still agree.
//!
//! # Why cross-check at all
//!
//! `SO_PEERCRED` is captured once, at `connect()`. A `/proc/<pid>` read
//! happens afterwards, at an arbitrary later instant. Between those two
//! points the pid could have been reused by an unrelated process (the
//! peer exited and something else got the same pid), or — on a
//! namespace-unaware kernel path — describe a process this agent cannot
//! actually see. Neither failure mode is hypothetical: it is the same
//! PID-reuse threat `eltanin_core::identity::WorkloadIdentity::compare_process`
//! already exists to catch, applied one layer earlier, before a
//! `WorkloadIdentity` value is ever constructed for the wrong process.
//!
//! # Real vs. effective uid
//!
//! `SO_PEERCRED` reports the peer's **effective** uid/gid (the kernel's
//! `cred_to_ucred()` fills the `ucred` structure from `cred->euid`).
//! [`eltanin_core::identity::WorkloadIdentity::uid`] is the **real**
//! uid ([`crate::collect_workload_identity`]'s established semantics —
//! not changed here). A cross-check that naively compared
//! `peer.effective_uid == identity.uid` would flag every setuid/setgid
//! peer as a credential mismatch and fail closed in the field while
//! passing every CI test (test processes have real == effective uid).
//! [`PeerConsistency::Consistent`] therefore requires the peer's
//! effective uid to match **either** the real **or** the effective uid
//! `/proc` reports for that pid — both are read from `/proc/<pid>/status`
//! in the same parse via the crate's internal `read_status_ids` helper.
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

use eltanin_core::identity::{Evidence, ExecutionContext};

/// The kernel-reported credential of a connected peer, captured at
/// `connect()` time. Fixed for the lifetime of the connection —
/// re-deriving it does not re-read anything; it is what the kernel
/// handed over at accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredential {
    pid: u32,
    /// The peer's **effective** uid — see the module docs on why this is
    /// not directly comparable to [`eltanin_core::identity::WorkloadIdentity::uid`].
    effective_uid: u32,
    effective_gid: u32,
}

impl PeerCredential {
    /// Construct a credential directly — for test doubles only in
    /// practice. Unlike `eltanin_core::lease::ComputeLease` (which
    /// exists to make a serialized authorization artifact unforgeable),
    /// [`PeerCredential`]/[`PeerContext`] are observation records, the
    /// same category as `eltanin_core::identity::WorkloadIdentity` —
    /// their fields are private for encapsulation, not to enforce a
    /// "never reconstructed outside kernel derivation" invariant, so a
    /// public constructor here doesn't weaken anything the rest of this
    /// module's docs claim. Production code has exactly one way to
    /// obtain a real one: [`collect_peer_context`].
    #[must_use]
    pub fn new(pid: u32, uid: u32, gid: u32) -> Self {
        Self {
            pid,
            effective_uid: uid,
            effective_gid: gid,
        }
    }

    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    #[must_use]
    pub fn effective_uid(&self) -> u32 {
        self.effective_uid
    }

    #[must_use]
    pub fn effective_gid(&self) -> u32 {
        self.effective_gid
    }
}

/// Whether the kernel's connect-time credential and a subsequent
/// `/proc` read describe the same process. Three states — never a
/// `bool` — following this crate's and `eltanin-core`'s established
/// pattern (see [`eltanin_core::identity::IdentityComparison`]):
/// "insufficient evidence to tell" must never be representable as, or
/// confused with, either a confirmed match or a confirmed mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerConsistency {
    /// The peer's effective uid matches the real or effective uid
    /// `/proc` reports for that pid.
    Consistent,
    /// The peer's effective uid matches **neither** the real nor the
    /// effective uid observed for that pid — named for what was
    /// observed (the two sources disagree), not for a presumed cause.
    /// The realistic cause is PID reuse between `connect()` and the
    /// `/proc` read; it could also mean `/proc` was read for a
    /// namespace-remapped view of a different underlying process.
    CredentialDivergence {
        peer_effective_uid: u32,
        observed_real_uid: Evidence<u32>,
        observed_effective_uid: Evidence<u32>,
    },
    /// `SO_PEERCRED` reported pid 0: the peer lives in a pid namespace
    /// this agent cannot map into its own. A distinct variant so this
    /// can never fall through to reading `/proc/0/...`, which does not
    /// name the peer at all.
    PeerUnmapped,
    /// `/proc` evidence was insufficient to cross-check at all (the
    /// peer had already exited, permission was denied, or
    /// `/proc/<pid>/status` was otherwise unreadable).
    Indeterminate { reason: String },
}

/// A connected peer's credential plus what `/proc` observed about it,
/// and whether the two agree. Production code obtains one real way:
/// [`collect_peer_context`]; [`PeerContext::new`] exists for test
/// doubles — see [`PeerCredential::new`]'s doc comment for why that
/// doesn't weaken this type's guarantees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerContext {
    credential: PeerCredential,
    consistency: PeerConsistency,
    observed: ExecutionContext,
}

impl PeerContext {
    #[must_use]
    pub fn new(
        credential: PeerCredential,
        consistency: PeerConsistency,
        observed: ExecutionContext,
    ) -> Self {
        Self {
            credential,
            consistency,
            observed,
        }
    }

    #[must_use]
    pub fn credential(&self) -> &PeerCredential {
        &self.credential
    }

    #[must_use]
    pub fn consistency(&self) -> &PeerConsistency {
        &self.consistency
    }

    /// What `/proc` actually reported, unmodified — always available
    /// regardless of `consistency()`, since this is what an audit trail
    /// (F-M1-009) must record even for a request that is ultimately
    /// refused.
    #[must_use]
    pub fn observed(&self) -> &ExecutionContext {
        &self.observed
    }

    /// `observed()`, but only when `consistency()` is
    /// [`PeerConsistency::Consistent`] — the fail-closed gate a caller
    /// must use before treating this context as authorization-grade
    /// evidence. Structural, not a convention: a caller that skips
    /// `consistency()` and always uses [`Self::observed`] directly is
    /// the bug this method exists to make easy to avoid.
    #[must_use]
    pub fn authorizable(&self) -> Option<&ExecutionContext> {
        matches!(self.consistency, PeerConsistency::Consistent).then_some(&self.observed)
    }
}

/// Why [`collect_peer_context`] could not derive a peer's credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerCredentialError {
    #[error("failed to read peer socket credential: {reason}")]
    Io { reason: String },
    #[error("peer credential derivation is not supported on this platform")]
    UnsupportedPlatform,
}

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
    use super::{Evidence, PeerConsistency, PeerContext, PeerCredential, PeerCredentialError};
    use eltanin_core::identity::EvidenceSource;
    use std::os::unix::net::UnixStream;

    pub(super) fn collect_peer_context(
        stream: &UnixStream,
    ) -> Result<PeerContext, PeerCredentialError> {
        let ucred =
            rustix::net::sockopt::socket_peercred(stream).map_err(|e| PeerCredentialError::Io {
                reason: e.to_string(),
            })?;
        let pid = ucred.pid.as_raw_nonzero().get();
        let credential = PeerCredential {
            // `as_raw_nonzero()` guarantees this is > 0, so the cast is
            // exact for any pid a real Linux kernel can assign.
            pid: u32::try_from(pid).unwrap_or(0),
            effective_uid: ucred.uid.as_raw(),
            effective_gid: ucred.gid.as_raw(),
        };

        if credential.pid == 0 {
            let observed = crate::collect_execution_context(0);
            return Ok(PeerContext {
                credential,
                consistency: PeerConsistency::PeerUnmapped,
                observed,
            });
        }

        let observed = crate::collect_execution_context(credential.pid);
        let (real_uid, effective_uid) = crate::read_status_ids(credential.pid, "Uid:");
        let consistency = classify(credential.effective_uid, &real_uid, &effective_uid);

        Ok(PeerContext {
            credential,
            consistency,
            observed,
        })
    }

    fn classify(
        peer_effective_uid: u32,
        observed_real_uid: &Evidence<u32>,
        observed_effective_uid: &Evidence<u32>,
    ) -> PeerConsistency {
        let matches = |evidence: &Evidence<u32>| match evidence {
            Evidence::Present { value, source } => {
                *source != EvidenceSource::SelfAsserted && *value == peer_effective_uid
            }
            Evidence::Missing { .. } | Evidence::Unsupported => false,
        };

        if matches(observed_real_uid) || matches(observed_effective_uid) {
            return PeerConsistency::Consistent;
        }

        let both_unreadable = matches!(observed_real_uid, Evidence::Missing { .. })
            && matches!(observed_effective_uid, Evidence::Missing { .. });
        if both_unreadable {
            let reason = match observed_real_uid {
                Evidence::Missing { reason } => reason.clone(),
                _ => unreachable!("both_unreadable guarantees Missing"),
            };
            return PeerConsistency::Indeterminate { reason };
        }

        PeerConsistency::CredentialDivergence {
            peer_effective_uid,
            observed_real_uid: observed_real_uid.clone(),
            observed_effective_uid: observed_effective_uid.clone(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn present(value: u32) -> Evidence<u32> {
            Evidence::Present {
                value,
                source: EvidenceSource::KernelObserved,
            }
        }

        fn missing() -> Evidence<u32> {
            Evidence::Missing {
                reason: "test".into(),
            }
        }

        #[test]
        fn matching_real_uid_is_consistent() {
            assert_eq!(
                classify(1000, &present(1000), &present(1000)),
                PeerConsistency::Consistent
            );
        }

        #[test]
        fn matching_effective_uid_alone_is_consistent() {
            // The setuid case this cross-check exists for: real uid
            // differs from the peer's effective uid, but the effective
            // uid observed via /proc agrees.
            assert_eq!(
                classify(0, &present(1000), &present(0)),
                PeerConsistency::Consistent
            );
        }

        #[test]
        fn matching_neither_is_credential_divergence() {
            assert_eq!(
                classify(2000, &present(1000), &present(1000)),
                PeerConsistency::CredentialDivergence {
                    peer_effective_uid: 2000,
                    observed_real_uid: present(1000),
                    observed_effective_uid: present(1000),
                }
            );
        }

        #[test]
        fn both_sides_unreadable_is_indeterminate_not_divergence() {
            assert!(matches!(
                classify(1000, &missing(), &missing()),
                PeerConsistency::Indeterminate { .. }
            ));
        }

        #[test]
        fn one_side_unreadable_and_the_other_mismatching_is_divergence_not_indeterminate() {
            // A concrete mismatching observation is a real signal, not
            // an evidence gap, even when the other field is missing.
            assert!(matches!(
                classify(2000, &missing(), &present(1000)),
                PeerConsistency::CredentialDivergence { .. }
            ));
        }

        #[test]
        fn a_self_asserted_match_is_never_treated_as_consistent() {
            let self_asserted = Evidence::Present {
                value: 1000,
                source: EvidenceSource::SelfAsserted,
            };
            assert!(matches!(
                classify(1000, &self_asserted, &missing()),
                PeerConsistency::CredentialDivergence { .. }
            ));
        }
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
