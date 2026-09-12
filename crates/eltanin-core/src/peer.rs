//! Canonical local IPC peer credential contract (F-M1-006, HORO-839;
//! relocated to `eltanin-core` by HORO-1013 so a second platform
//! adapter — `crates/eltanin-macos` — can produce the same contract as
//! `crates/eltanin-linux` without either depending on the other).
//!
//! [`PeerContext`] is what a platform collector (`crate::peer` consumer
//! in `eltanin-linux`/`eltanin-macos`) hands back after deriving a
//! connected Unix Domain Socket peer's credential and cross-checking it
//! against independently observed process state: an unforgeable
//! [`PeerCredential`], an explicit [`PeerConsistency`] verdict on
//! whether the two sources still agree, and the raw
//! [`eltanin_core::identity::ExecutionContext`] observed for audit
//! purposes regardless of that verdict.
//!
//! # Production code has exactly one way to construct an authorizable `PeerContext`
//!
//! [`PeerContext::from_kernel_observation`] and
//! [`PeerContext::peer_unmapped`] are the only ways to obtain a
//! [`PeerContext`] outside tests, and neither accepts a caller-supplied
//! [`PeerConsistency`] value — `from_kernel_observation` always
//! re-derives it via [`classify_consistency`] from the credential and
//! the freshly observed uid evidence. No production code path anywhere
//! in this workspace can hand-construct
//! `PeerConsistency::Consistent` and thereby make an unverified
//! `PeerContext` pass [`PeerContext::authorizable`]. [`PeerContext::for_test`]
//! exists for test doubles only, gated behind the `test-support`
//! feature (not merely documented as test-only) so no downstream crate
//! can construct one in a normal build.

use crate::identity::{Evidence, EvidenceSource, ExecutionContext};

/// The kernel-reported credential of a connected peer, captured at
/// `connect()` time (or, on platforms without a connect-time-fixed pid,
/// captured as close to it as the platform allows — see the collecting
/// crate's own module docs for its platform's exact guarantee).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredential {
    pid: u32,
    /// The peer's **effective** uid — see the collecting crate's module
    /// docs on why this is not directly comparable to
    /// [`eltanin_core::identity::WorkloadIdentity::uid`].
    effective_uid: u32,
    effective_gid: u32,
}

impl PeerCredential {
    /// Construct a credential from a real kernel-derived observation.
    /// The one non-test way to build a [`PeerCredential`] — every
    /// platform collector (`eltanin-linux`, `eltanin-macos`) calls this
    /// with values read directly from an OS peer-credential mechanism,
    /// never from anything a caller could self-assert.
    #[must_use]
    pub fn from_kernel(pid: u32, effective_uid: u32, effective_gid: u32) -> Self {
        Self {
            pid,
            effective_uid,
            effective_gid,
        }
    }

    /// Construct a credential directly — for test doubles only. Gated
    /// behind the `test-support` feature (not merely documented as
    /// test-only) so that no production code path — in this crate or
    /// any downstream one — can construct a [`PeerContext`] that
    /// bypasses kernel derivation entirely and still satisfy
    /// [`PeerContext::authorizable`].
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn new(pid: u32, uid: u32, gid: u32) -> Self {
        Self::from_kernel(pid, uid, gid)
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

/// Whether the kernel's connect-time credential and a subsequent,
/// independently observed process state describe the same process.
/// Three states — never a `bool` — following this crate's established
/// pattern (see [`crate::identity::IdentityComparison`]): "insufficient
/// evidence to tell" must never be representable as, or confused with,
/// either a confirmed match or a confirmed mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerConsistency {
    /// The peer's effective uid matches the real or effective uid
    /// independently observed for that pid.
    Consistent,
    /// The peer's effective uid matches **neither** the real nor the
    /// effective uid observed for that pid — named for what was
    /// observed (the two sources disagree), not for a presumed cause.
    /// The realistic cause is PID reuse between credential capture and
    /// the independent observation; it could also mean the observation
    /// was for a namespace-remapped view of a different underlying
    /// process.
    CredentialDivergence {
        peer_effective_uid: u32,
        observed_real_uid: Evidence<u32>,
        observed_effective_uid: Evidence<u32>,
    },
    /// The kernel credential mechanism reported a peer this agent
    /// cannot map to a real pid (e.g. Linux `SO_PEERCRED` reporting pid
    /// 0 for a peer in an unmapped pid namespace). A distinct variant so
    /// this can never fall through to observing pid 0, which does not
    /// name the peer at all.
    PeerUnmapped,
    /// Independent observation was insufficient to cross-check at all
    /// (the peer had already exited, permission was denied, or the
    /// observation source was otherwise unreadable).
    Indeterminate { reason: String },
}

/// A connected peer's credential plus what was independently observed
/// about it, and whether the two agree. Production code has exactly two
/// real ways to obtain one: [`PeerContext::from_kernel_observation`] and
/// [`PeerContext::peer_unmapped`]; [`PeerContext::for_test`] exists for
/// test doubles only, behind the `test-support` feature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerContext {
    credential: PeerCredential,
    consistency: PeerConsistency,
    observed: ExecutionContext,
}

impl PeerContext {
    /// Build a [`PeerContext`] from a real kernel-derived `credential`
    /// plus independently observed process state, re-deriving
    /// [`PeerConsistency`] via [`classify_consistency`] rather than
    /// accepting one as a parameter — this is what makes it impossible
    /// for any caller to hand-assert [`PeerConsistency::Consistent`].
    #[must_use]
    pub fn from_kernel_observation(
        credential: PeerCredential,
        observed: ExecutionContext,
        observed_real_uid: &Evidence<u32>,
        observed_effective_uid: &Evidence<u32>,
    ) -> Self {
        let consistency = classify_consistency(
            credential.effective_uid,
            observed_real_uid,
            observed_effective_uid,
        );
        Self {
            credential,
            consistency,
            observed,
        }
    }

    /// Build a [`PeerContext`] for the [`PeerConsistency::PeerUnmapped`]
    /// case: the kernel credential mechanism reported a peer this agent
    /// cannot resolve to a real pid, so there is nothing to
    /// independently observe.
    #[must_use]
    pub fn peer_unmapped(credential: PeerCredential, observed: ExecutionContext) -> Self {
        Self {
            credential,
            consistency: PeerConsistency::PeerUnmapped,
            observed,
        }
    }

    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn new(
        credential: PeerCredential,
        consistency: PeerConsistency,
        observed: ExecutionContext,
    ) -> Self {
        Self::for_test(credential, consistency, observed)
    }

    /// Construct an arbitrary [`PeerContext`] — for test doubles only.
    /// Gated behind the `test-support` feature so no production build
    /// of any downstream crate can bypass kernel derivation and mint an
    /// authorizable context directly.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn for_test(
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

    /// What was independently observed, unmodified — always available
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

/// Why a platform collector could not derive a peer's credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerCredentialError {
    #[error("failed to read peer socket credential: {reason}")]
    Io { reason: String },
    #[error("peer credential derivation is not supported on this platform")]
    UnsupportedPlatform,
}

/// Reconcile a peer's kernel-reported **effective** uid against
/// independently observed **real**/**effective** uid evidence for the
/// same pid, producing the one [`PeerConsistency`] verdict every
/// platform collector in this workspace shares.
///
/// # Real vs. effective uid
///
/// A cross-check that naively compared the peer's effective uid only
/// against an observed *real* uid would flag every setuid/setgid peer
/// as a credential mismatch and fail closed in the field while passing
/// every CI test (test processes have real == effective uid).
/// [`PeerConsistency::Consistent`] therefore requires the peer's
/// effective uid to match **either** the observed real **or** the
/// observed effective uid.
///
/// A self-asserted match is never treated as consistent: `Consistent`
/// requires the matching observation's [`EvidenceSource`] to not be
/// [`EvidenceSource::SelfAsserted`] — this workspace's collectors never
/// produce self-asserted uid evidence today, but the type is
/// deserializable and must not silently trust it if a future caller
/// ever does.
#[must_use]
pub fn classify_consistency(
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
            classify_consistency(1000, &present(1000), &present(1000)),
            PeerConsistency::Consistent
        );
    }

    #[test]
    fn matching_effective_uid_alone_is_consistent() {
        // The setuid case this cross-check exists for: real uid differs
        // from the peer's effective uid, but the effective uid observed
        // independently agrees.
        assert_eq!(
            classify_consistency(0, &present(1000), &present(0)),
            PeerConsistency::Consistent
        );
    }

    #[test]
    fn matching_neither_is_credential_divergence() {
        assert_eq!(
            classify_consistency(2000, &present(1000), &present(1000)),
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
            classify_consistency(1000, &missing(), &missing()),
            PeerConsistency::Indeterminate { .. }
        ));
    }

    #[test]
    fn one_side_unreadable_and_the_other_mismatching_is_divergence_not_indeterminate() {
        // A concrete mismatching observation is a real signal, not an
        // evidence gap, even when the other field is missing.
        assert!(matches!(
            classify_consistency(2000, &missing(), &present(1000)),
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
            classify_consistency(1000, &self_asserted, &missing()),
            PeerConsistency::CredentialDivergence { .. }
        ));
    }
}
