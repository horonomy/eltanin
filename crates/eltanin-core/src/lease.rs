//! Scoped, short-lived Compute Lease (F-M1-005, HORO-836).
//!
//! A [`ComputeLease`] is the authorization-capability lifecycle artifact
//! an ALLOW [`PolicyDecision`] becomes — never a permanent privilege.
//! The only way to obtain one is [`LeaseIssuer::issue`], which
//! **re-evaluates** the policy over the exact [`ProvenanceRecord`] the
//! lease is bound to: there is no code path where a lease is issued for
//! one observation and bound to another, because `issue` never accepts
//! a pre-computed [`PolicyDecision`] — the same structural trick
//! [`crate::policy::PolicySet::evaluate`] and `eltanin-linux`'s
//! pid-only collectors use elsewhere in this campaign.
//!
//! # States and transitions
//!
//! ```text
//! Active --(now >= expires_at)--------> Expired   irreversible, no reverse edge
//! Active --(LeaseIssuer::revoke)------> Revoked   irreversible, issuer-only
//! Active --(narrow_expiry)------------> Active'   expires_at' <= expires_at
//! (no Extend, no Renew, no Resurrect — renewal is a fresh `issue` over
//!  freshly observed context, never an extension of an existing lease)
//! ```
//!
//! There is deliberately no `state` field on [`ComputeLease`] itself — a
//! state field on the value is the bearer-token bug in miniature: a
//! copy taken before revocation would still read `Active`. Revocation
//! lives with [`LeaseIssuer`]; expiry is a comparison [`LeaseIssuer::validate`]
//! makes against an explicitly injected "now", never a field the lease
//! carries and asserts about itself.
//!
//! # Time is injected, never read
//!
//! [`MonotonicTime`] is a plain `u64` nanosecond count with no relation
//! to wall-clock time. `eltanin-core` never calls `SystemTime::now()` or
//! `Instant::now()` — every timestamp this module produces or consumes
//! is a parameter. Two reasons this is not merely a testing convenience:
//!
//! - `SystemTime` is wall-clock and can move backward (NTP correction,
//!   manual clock change, suspend/resume), which could **un-expire** a
//!   lease — exactly the "expired lease is invalid even if it still
//!   looks familiar" invariant this module exists to uphold.
//! - `Instant` cannot be constructed at a chosen value or serialized, so
//!   golden fixtures and deterministic replay tests would be
//!   impossible; the `Instant -> MonotonicTime` adapter (capture a base
//!   `Instant` once, take nanosecond offsets from it) is exactly six
//!   lines and belongs to whichever crate actually owns a clock
//!   (F-M1-006's agent), not this pure domain crate.
//!
//! A [`MonotonicTime`] reading is only meaningful compared against
//! another reading from the **same** [`IssuerInstanceId`] — see below.
//!
//! # Restart and replay
//!
//! | Case | Mechanism | Result |
//! |---|---|---|
//! | Workload process restarts, or its PID is reused | [`crate::identity::WorkloadIdentity::compare_process`] on `pid` + `ProcessStartToken` | [`LeaseValidity::WorkloadMismatch`], or [`LeaseValidity::WorkloadIndeterminate`] when evidence is insufficient — never silently `Valid` |
//! | Process stays alive but `execve()`s into a different binary (pid + start token unchanged) | [`crate::identity::WorkloadIdentity::compare_executable`] on executable hash/path | [`LeaseValidity::ExecutableMismatch`], or `WorkloadIndeterminate` when evidence is insufficient — `compare_process` alone cannot see this, since neither field it checks changes across `execve()` |
//! | Agent/issuer restarts | Leases are in-memory only (no `Deserialize`); a new [`LeaseIssuer`] carries a new [`IssuerInstanceId`] | Any lease naming the old instance is [`LeaseValidity::ForeignIssuer`]. Re-authorization is a fresh `issue` |
//! | A serialized lease is replayed from disk or a log | No `Deserialize`, no public constructor | The bytes cannot become a [`ComputeLease`] at all — they are evidence, not authority |
//!
//! [`IssuerInstanceId`] must be derived from the issuing agent's own
//! kernel-observed `pid` + `ProcessStartToken` (e.g. via
//! `eltanin_linux::collect_workload_identity`), never a hardcoded
//! constant — grounding the restart epoch in kernel-observed state is
//! what prevents leases from silently surviving a restart.
//!
//! # No reusable plaintext bearer-token shortcut
//!
//! - [`ComputeLease`] is `Serialize` but **not** `Deserialize` — the
//!   serialized form is a record of an authorization, never a path back
//!   into one.
//! - [`LeaseId`] carries no entropy and is a correlation identifier
//!   only, never a capability — there is nothing in it to leak, guess,
//!   or replay, and "knows the id" was never meant to imply "is
//!   authorized."
//! - [`LeaseIssuer::validate`] requires the live issuer instance *and*
//!   freshly observed context matching the original binding. Holding a
//!   lease value is not sufficient by itself.
//!
//! **Known limitation, a contract on F-M1-006, not a property of this
//! crate alone**: [`LeaseIssuer::validate`]'s `presented` and `now`
//! parameters are caller-supplied, and [`ProvenanceRecord`] and
//! [`MonotonicTime`] are both `Deserialize`. Nothing in `eltanin-core`
//! stops a caller from fabricating either. The parent invariant
//! ("possession of serialized lease data alone must not silently prove
//! caller identity when the local agent can bind to observed context")
//! therefore depends on F-M1-006's agent sourcing `presented` from its
//! own collector and `now` from its own clock — **never** from anything
//! a client sends over IPC. This is the single obligation most likely
//! to be silently dropped by a future ticket; it is named explicitly
//! here for that reason.
//!
//! # Scope narrowing is structural, not merely checked
//!
//! [`ComputeLease`]'s fields are private with no `&mut` accessor, no
//! public constructor, and no `Deserialize`. The one lifecycle method,
//! [`ComputeLease::narrow_expiry`], computes `min(current, not_after)`
//! and consumes `self` — there is no widening counterpart and no
//! `renew`/`extend` method anywhere in this module. MVP 1.0's
//! `ComputeRequest` is a single resource + a single `Action`, so time
//! is the only narrowable dimension that exists; this module does not
//! invent a set-valued scope solely to make narrowing look more general
//! than the domain currently requires.
//!
//! # Known limitation: `narrow_expiry` does not mint a new identity
//!
//! `narrow_expiry` preserves [`LeaseId`], so two [`ComputeLease`] values
//! can share an id with different `expires_at`. Both would appear in an
//! audit stream (F-M1-009) without a way to attribute a compute event to
//! one specifically. Accepted for MVP 1.0 — narrowing restricts one
//! existing authorization rather than minting a new one, and revoking
//! the id invalidates every value sharing it — but documented rather
//! than silently left unaddressed, following the same pattern as
//! `eltanin-linux`'s ancestry-truncation gap (HORO-832) and `policy`'s
//! revision-immutability gap (HORO-834).

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::identity::IdentityComparison;
use crate::policy::{DecisionReason, Effect, PolicyDecision, PolicyProvenance, PolicySet};
use crate::provenance::ProvenanceRecord;

/// A monotonic instant, as nanoseconds since an epoch chosen by one
/// [`LeaseIssuer`] instance. Only meaningful compared against another
/// reading from the *same* [`IssuerInstanceId`] — see the module docs.
/// Never read from a system clock inside this crate; always supplied by
/// the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MonotonicTime(u64);

impl MonotonicTime {
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// `self + duration`, or `None` if that would overflow a `u64`
    /// nanosecond count.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let added = u64::try_from(duration.as_nanos()).ok()?;
        self.0.checked_add(added).map(Self)
    }

    /// `self - earlier`, saturating to [`Duration::ZERO`] if `earlier`
    /// is not actually earlier than `self`.
    #[must_use]
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }
}

/// Opaque tag for one live [`LeaseIssuer`] instance — its restart epoch.
/// Must be derived from the issuing agent's own kernel-observed
/// `pid`/`ProcessStartToken`, never a hardcoded constant; see the module
/// docs' restart/replay table.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IssuerInstanceId(String);

impl IssuerInstanceId {
    pub fn new(tag: impl Into<String>) -> Self {
        Self(tag.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A correlation identifier for one issued [`ComputeLease`]. Carries no
/// entropy and is **not** a capability or a secret — see the module
/// docs' "No reusable plaintext bearer-token shortcut" section.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LeaseId {
    pub issuer: IssuerInstanceId,
    pub sequence: u64,
}

/// One issued authorization: a narrowly scoped, expiring artifact bound
/// to the exact [`ProvenanceRecord`] it was issued against. Fields are
/// private and there is no public constructor outside
/// [`LeaseIssuer::issue`]; `Serialize` only, deliberately not
/// `Deserialize` — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComputeLease {
    id: LeaseId,
    origin: ProvenanceRecord,
    policy: PolicyProvenance,
    decision_reason: DecisionReason,
    issued_at: MonotonicTime,
    expires_at: MonotonicTime,
}

impl ComputeLease {
    #[must_use]
    pub fn id(&self) -> &LeaseId {
        &self.id
    }

    #[must_use]
    pub fn origin(&self) -> &ProvenanceRecord {
        &self.origin
    }

    #[must_use]
    pub fn policy(&self) -> &PolicyProvenance {
        &self.policy
    }

    #[must_use]
    pub fn decision_reason(&self) -> &DecisionReason {
        &self.decision_reason
    }

    #[must_use]
    pub fn issued_at(&self) -> MonotonicTime {
        self.issued_at
    }

    #[must_use]
    pub fn expires_at(&self) -> MonotonicTime {
        self.expires_at
    }

    /// The only lifecycle operation on a lease value: consumes `self`
    /// and returns a lease whose expiry is `min(self.expires_at,
    /// not_after)`. There is no widening counterpart — a later
    /// `not_after` is a no-op, never an extension.
    #[must_use]
    pub fn narrow_expiry(self, not_after: MonotonicTime) -> ComputeLease {
        ComputeLease {
            expires_at: self.expires_at.min(not_after),
            ..self
        }
    }
}

/// Why [`LeaseIssuer::issue`] refused to issue a lease.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LeaseError {
    #[error("policy did not allow the request")]
    Denied { decision: PolicyDecision },
    #[error("lease ttl must be greater than zero")]
    NonPositiveTtl,
    #[error("lease ttl {requested:?} exceeds issuer maximum {maximum:?}")]
    TtlExceedsMaximum {
        requested: Duration,
        maximum: Duration,
    },
    #[error("lease expiry would overflow the monotonic clock range")]
    ExpiryOverflow,
}

/// The result of [`LeaseIssuer::revoke`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationOutcome {
    Revoked,
    AlreadyRevoked,
    NotIssued,
    ForeignIssuer,
}

/// The result of [`LeaseIssuer::validate`]. A rich enum, not a `bool`,
/// following this crate's established pattern (see
/// [`IdentityComparison`], [`crate::policy::DecisionReason`]) — collapsing
/// "confirmed valid," "confirmed invalid for reason X," and "cannot be
/// determined" into a single boolean would lose exactly the information
/// an audit trail (F-M1-009) needs to reconstruct what happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "validity")]
pub enum LeaseValidity {
    Valid {
        remaining: Duration,
    },
    /// The lease names an [`IssuerInstanceId`] that is not this live
    /// issuer — an agent restart, or a second live issuer. Never
    /// treated as valid.
    ForeignIssuer {
        issued_by: IssuerInstanceId,
    },
    Revoked,
    ResourceMismatch,
    ActionMismatch,
    /// [`IdentityComparison::Different`]: PID reuse or a genuine
    /// workload restart.
    WorkloadMismatch,
    /// [`IdentityComparison::Indeterminate`]: fails closed, exactly as
    /// `policy`'s `IndeterminateEvidence` does — never `Valid`, never
    /// `WorkloadMismatch`.
    WorkloadIndeterminate,
    /// [`crate::identity::WorkloadIdentity::compare_executable`] reports
    /// [`IdentityComparison::Different`] — the pid/start token still
    /// match, but the executable image does not, i.e. an in-place
    /// `execve()` swap. `compare_process` alone cannot see this, since
    /// neither `pid` nor `ProcessStartToken` changes across `execve()`.
    ExecutableMismatch,
    Expired {
        expired_at: MonotonicTime,
    },
}

impl LeaseValidity {
    /// Convenience for a final allow/deny gate only. Code that records
    /// audit evidence should match on the full enum instead — collapsing
    /// to a bool here discards exactly the distinction this type exists
    /// to preserve.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, LeaseValidity::Valid { .. })
    }
}

/// Issues and validates [`ComputeLease`] values for one live process
/// instance. `max_ttl` is required at construction, not defaulted —
/// "short-lived" is a bound this crate enforces, but the actual number
/// is a deployment/agent decision (F-M1-006), not this crate's to guess.
pub struct LeaseIssuer {
    instance: IssuerInstanceId,
    max_ttl: Duration,
    next_sequence: u64,
    revoked: BTreeSet<u64>,
}

impl LeaseIssuer {
    #[must_use]
    pub fn new(instance: IssuerInstanceId, max_ttl: Duration) -> Self {
        Self {
            instance,
            max_ttl,
            next_sequence: 0,
            revoked: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn instance(&self) -> &IssuerInstanceId {
        &self.instance
    }

    /// Evaluate `policy` against `origin` and, only if the result is
    /// [`Effect::Allow`], issue a lease bound to exactly that `origin`.
    ///
    /// `issue` takes `&PolicySet`, never a pre-computed
    /// [`PolicyDecision`], on purpose: a `PolicyDecision` alone does not
    /// carry the context/request it was computed from, so accepting one
    /// would leave open "evaluated against context A, issued bound to
    /// context B." Re-evaluating here makes that mismatch unexpressable.
    /// Callers that already hold a `PolicyDecision` for logging purposes
    /// should take it from the returned lease's
    /// [`ComputeLease::decision_reason`]/[`ComputeLease::policy`] on
    /// success, or from [`LeaseError::Denied`] on failure — never call
    /// `PolicySet::evaluate` separately and pass its result in.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::Denied`] if evaluating `policy` over
    /// `origin` does not produce [`Effect::Allow`];
    /// [`LeaseError::NonPositiveTtl`] if `ttl` is zero;
    /// [`LeaseError::TtlExceedsMaximum`] if `ttl` exceeds this issuer's
    /// `max_ttl`; [`LeaseError::ExpiryOverflow`] if `now + ttl` would
    /// overflow the monotonic clock range.
    pub fn issue(
        &mut self,
        policy: &PolicySet,
        origin: ProvenanceRecord,
        now: MonotonicTime,
        ttl: Duration,
    ) -> Result<ComputeLease, LeaseError> {
        if ttl.is_zero() {
            return Err(LeaseError::NonPositiveTtl);
        }
        if ttl > self.max_ttl {
            return Err(LeaseError::TtlExceedsMaximum {
                requested: ttl,
                maximum: self.max_ttl,
            });
        }

        let decision = policy.evaluate(&origin.context, &origin.request);
        if decision.effect() != Effect::Allow {
            return Err(LeaseError::Denied { decision });
        }

        let expires_at = now.checked_add(ttl).ok_or(LeaseError::ExpiryOverflow)?;

        let id = LeaseId {
            issuer: self.instance.clone(),
            sequence: self.next_sequence,
        };
        self.next_sequence += 1;

        Ok(ComputeLease {
            id,
            origin,
            policy: decision.policy().clone(),
            decision_reason: decision.reason().clone(),
            issued_at: now,
            expires_at,
        })
    }

    /// Revoke the lease identified by `id`, if it was issued by this
    /// issuer instance.
    pub fn revoke(&mut self, id: &LeaseId) -> RevocationOutcome {
        if id.issuer != self.instance {
            return RevocationOutcome::ForeignIssuer;
        }
        if id.sequence >= self.next_sequence {
            return RevocationOutcome::NotIssued;
        }
        if !self.revoked.insert(id.sequence) {
            return RevocationOutcome::AlreadyRevoked;
        }
        RevocationOutcome::Revoked
    }

    /// Validate `lease` against freshly observed `presented` context/
    /// request and the current `now`.
    ///
    /// Check order (load-bearing, not incidental): issuer identity,
    /// then revocation, then resource, then action, then workload
    /// identity, then expiry. Binding checks come before expiry so an
    /// attempted cross-workload or cross-resource replay is reported as
    /// a mismatch rather than downgraded into a routine `Expired` line
    /// in an audit trail.
    #[must_use]
    pub fn validate(
        &self,
        lease: &ComputeLease,
        presented: &ProvenanceRecord,
        now: MonotonicTime,
    ) -> LeaseValidity {
        if lease.id.issuer != self.instance {
            return LeaseValidity::ForeignIssuer {
                issued_by: lease.id.issuer.clone(),
            };
        }
        if self.revoked.contains(&lease.id.sequence) {
            return LeaseValidity::Revoked;
        }
        if lease.origin.request.resource != presented.request.resource {
            return LeaseValidity::ResourceMismatch;
        }
        if lease.origin.request.action != presented.request.action {
            return LeaseValidity::ActionMismatch;
        }
        match lease
            .origin
            .context
            .workload
            .compare_process(&presented.context.workload)
        {
            IdentityComparison::Different => return LeaseValidity::WorkloadMismatch,
            IdentityComparison::Indeterminate => return LeaseValidity::WorkloadIndeterminate,
            IdentityComparison::Same => {}
        }
        // `compare_process` alone cannot see an in-place `execve()` swap
        // (pid and process_start survive execve unchanged) — checked
        // separately so the two substitution attacks stay distinguishable
        // in an audit trail.
        match lease
            .origin
            .context
            .workload
            .compare_executable(&presented.context.workload)
        {
            IdentityComparison::Different => return LeaseValidity::ExecutableMismatch,
            IdentityComparison::Indeterminate => return LeaseValidity::WorkloadIndeterminate,
            IdentityComparison::Same => {}
        }
        if now >= lease.expires_at {
            return LeaseValidity::Expired {
                expired_at: lease.expires_at,
            };
        }
        LeaseValidity::Valid {
            remaining: lease.expires_at.saturating_duration_since(now),
        }
    }
}
