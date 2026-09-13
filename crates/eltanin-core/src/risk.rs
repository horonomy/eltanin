//! Risk-based step-up classification (F-M2-004, HORO-794).
//!
//! # Headline decision — read this first
//!
//! The set of requests Eltanin refuses is unchanged by this ticket. What
//! changes is that a refusal now names the trust change that caused it,
//! and can be configured as step-up-remediable versus hard-denied. The
//! only genuinely stricter behavior is the new hard-`Deny` class;
//! nothing that was refused before is admitted now, and nothing that was
//! admitted before is refused now.
//!
//! This module is a **classification layer over refusals already
//! produced elsewhere** — [`crate::session::membership`] (HORO-791),
//! [`crate::approval::recall`] (HORO-792), and
//! [`crate::delegation::delegated_admission`] (HORO-793) — never a
//! fourth independent security check. [`assess`] reads no fresh
//! evidence of its own and confers no authority; it only names *why* a
//! refusal those three functions already produced happened, and lets a
//! deployment configure whether that reason is remediable (step-up) or
//! hard-denied. There is deliberately no "admit"/"proceed" variant on
//! [`StepUpVerdict`] at all — [`assess`] is reachable only from a gate's
//! own refusal arm, never from an admission path, so this layer can
//! never loosen a gate by construction.
//!
//! # Why there is no `Indeterminate` variant on `StepUpVerdict`
//!
//! Unlike [`crate::session::MembershipVerdict`],
//! [`crate::approval::RecallVerdict`], and
//! [`crate::delegation::DelegationVerdict`], [`StepUpVerdict`] has no
//! `Indeterminate` case. Every evidence-freshness failure that would
//! otherwise need one is already resolved to a named `Indeterminate` by
//! whichever gate produced the verdict [`assess`] is consuming — that
//! is exactly what [`RiskSignal::EvidenceIndeterminate`] surfaces
//! instead: a *named signal*, not a fourth indeterminate state for
//! callers to handle.
//!
//! # Prompt-storm guardrail
//!
//! [`assess`] never runs on an admitted request — only on a refusal
//! already produced by another gate. Every signal self-extinguishes the
//! moment `eltanin approve --remember` (already shipped, HORO-792) is
//! run: that re-derives the approval binding from fresh kernel state, so
//! the next [`crate::approval::recall`] call returns
//! [`crate::approval::RecallVerdict::Matched`], the approval gate
//! admits, and [`assess`] is never called again for that context. No
//! second remember-mechanism is introduced here.
//!
//! # Untrusted execution path can never hard-deny
//!
//! [`StepUpPolicy::new`] rejects mapping
//! [`RiskSignal::UntrustedExecutionPath`] to [`SignalDisposition::Deny`]
//! ([`StepUpPolicyError::PathSignalCannotDeny`]). This is not merely
//! "never the sole verdict" as a convention — it is structural, because
//! of what remediation means for this one signal specifically: running
//! `eltanin approve --remember` records the launcher's *path* into the
//! approval binding, so the very same untrusted path becomes the
//! matched, remembered launcher on the next request. A hard `Deny`
//! mapped to this signal would therefore be unremediable by the
//! mechanism this whole ticket relies on to avoid prompt storms — it
//! would be the one way this feature could produce a permanent block
//! rather than a step-up. Every other signal either self-extinguishes
//! the same way or corresponds to a dimension `--remember` cannot paper
//! over (e.g. a live privilege escalation), which is exactly why they
//! remain configurable as `Deny`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::approval::{ChangedDimension, RecallVerdict};
use crate::delegation::{DelegationVerdict, ExceededBound};
use crate::identity::{Evidence, ExecutionContext};
use crate::session::MembershipVerdict;

/// One named trust-change signal a refusal can be classified under.
/// Every variant composes an existing verdict already produced by the
/// session (HORO-791), approval (HORO-792), or delegation (HORO-793)
/// gate — [`assess`] never re-collects or re-derives evidence a second
/// time. `Ord` matters: this type lives only in
/// `BTreeSet<RiskSignal>`, so declaration order is serialization/
/// iteration order.
///
/// Deliberately excluded: a remote-origin-launch signal (no collector
/// anywhere in this workspace collects network/remote-origin
/// information for a process launch — see ADR 0012 for the explicit,
/// declared-unbuilt disclosure) and any CPU/GPU-utilization-based
/// signal (a hard guardrail from the ticket itself: "GPU usage looks
/// high" is never a risk basis here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSignal {
    /// No approval candidate exists for this launcher/context at all
    /// ([`crate::approval::ApprovalSet::candidates`] returned nothing),
    /// or a candidate's [`RecallVerdict::NotMatched`] names
    /// [`ChangedDimension::LauncherPath`].
    UnknownLauncher,
    /// `observed.workload.executable_path` starts with one of
    /// [`StepUpPolicy::untrusted_path_prefixes`] — a deployment-configured
    /// comparison, never a hardcoded `/tmp`/`~/Downloads` guess.
    UntrustedExecutionPath,
    /// A candidate's [`RecallVerdict::NotMatched`] names
    /// [`ChangedDimension::LauncherDigest`].
    LauncherIdentityChanged,
    /// A candidate's [`RecallVerdict::NotMatched`] names
    /// [`ChangedDimension::OwnerUid`], or the delegation verdict's
    /// `exceeded` set contains [`ExceededBound::OwnerUid`].
    PrivilegeTransition,
    /// [`RiskSignal::PrivilegeTransition`]'s trigger fired **and** the
    /// observed workload uid is present and equal to `0`. Never fires on
    /// either condition alone.
    PrivilegeEscalationToRoot,
    /// [`MembershipVerdict::NotMember`] or
    /// [`MembershipVerdict::Indeterminate`] — the requester does not
    /// verify as a member of any currently tracked session. Deliberately
    /// **not** keyed off [`ExceededBound::AncestryLinkage`]/
    /// [`ExceededBound::HolderLiveness`]: those two are excluded by
    /// construction from the narrowed delegation-exceeded set this
    /// module consumes (see `eltanin-agent`'s `linked_exceeded`), because
    /// a grant that fails ancestry linkage isn't about this requester at
    /// all — a lookup miss, not detachment.
    DetachedExecution,
    /// The delegation verdict's `exceeded` set — already narrowed by the
    /// caller to grants that passed ancestry linkage and holder liveness
    /// (see the module docs on the HORO-793 bug fix this ticket also
    /// carries) — contains [`ExceededBound::Resource`],
    /// [`ExceededBound::Action`], [`ExceededBound::Depth`], or
    /// [`ExceededBound::Duration`].
    DelegationScopeExpanded,
    /// A candidate's [`RecallVerdict::NotMatched`] names
    /// [`ChangedDimension::ResourceCapabilityState`] or
    /// [`ChangedDimension::PolicyRevision`].
    SecurityPostureChanged,
    /// A candidate's [`RecallVerdict::NotMatched`] names
    /// [`ChangedDimension::CgroupPath`], or the (narrowed) delegation
    /// verdict's `exceeded` set contains [`ExceededBound::CgroupPath`]
    /// or [`ExceededBound::SessionKey`].
    ContextBoundaryChanged,
    /// The (narrowed) delegation verdict's `exceeded` set contains
    /// [`ExceededBound::TrustTransition`].
    TrustTransition,
    /// Any consumed gate verdict was itself an `Indeterminate` case —
    /// the fail-closed evidence floor. See the module docs on why
    /// [`StepUpVerdict`] itself has no separate `Indeterminate` variant.
    EvidenceIndeterminate,
}

impl RiskSignal {
    /// Every [`RiskSignal`] variant, in declaration order. Exists so a
    /// deployment (and this crate's own tests) can enumerate the full
    /// signal set without hand-maintaining a second list that can drift
    /// from the enum.
    pub const ALL: &'static [RiskSignal] = &[
        RiskSignal::UnknownLauncher,
        RiskSignal::UntrustedExecutionPath,
        RiskSignal::LauncherIdentityChanged,
        RiskSignal::PrivilegeTransition,
        RiskSignal::PrivilegeEscalationToRoot,
        RiskSignal::DetachedExecution,
        RiskSignal::DelegationScopeExpanded,
        RiskSignal::SecurityPostureChanged,
        RiskSignal::ContextBoundaryChanged,
        RiskSignal::TrustTransition,
        RiskSignal::EvidenceIndeterminate,
    ];
}

/// What a [`StepUpPolicy`] does with one fired [`RiskSignal`]. A signal
/// with no entry in [`StepUpPolicy`]'s map defaults to `Informational`
/// — the same "safe blast-radius default" convention established by
/// `SessionRequirement::NotRequired`/`ApprovalRequirement::NotRequired`
/// (a deployment that configures nothing gets gate-off/no-stricter
/// behavior, never a silent new denial).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignalDisposition {
    /// Recorded in the audit trail only; never changes the outcome of
    /// the plain refusal the caller already produced.
    #[default]
    Informational,
    /// Elevates the refusal to [`StepUpVerdict::StepUpRequired`],
    /// naming the fired signals as the remediation-relevant reason.
    StepUp,
    /// Elevates the refusal to [`StepUpVerdict::RiskDenied`] — a hard
    /// deny, deliberately unavailable for
    /// [`RiskSignal::UntrustedExecutionPath`] (see the module docs).
    Deny,
}

/// Why [`StepUpPolicy::new`] rejected a configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StepUpPolicyError {
    #[error(
        "RiskSignal::UntrustedExecutionPath cannot be mapped to SignalDisposition::Deny — see \
         the eltanin_core::risk module docs for why this signal must stay remediable"
    )]
    PathSignalCannotDeny,
}

/// Deployment-configured classification policy every [`assess`] call is
/// evaluated against. Constructed only via the fallible [`Self::new`] —
/// mirrors [`crate::delegation::DelegationBounds::new`]'s "no `Default`,
/// no way to construct an unvalidated value" discipline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUpPolicy {
    dispositions: BTreeMap<RiskSignal, SignalDisposition>,
    untrusted_path_prefixes: BTreeSet<String>,
}

impl StepUpPolicy {
    /// # Errors
    ///
    /// Returns [`StepUpPolicyError::PathSignalCannotDeny`] if
    /// `dispositions` maps [`RiskSignal::UntrustedExecutionPath`] to
    /// [`SignalDisposition::Deny`].
    pub fn new(
        dispositions: BTreeMap<RiskSignal, SignalDisposition>,
        untrusted_path_prefixes: BTreeSet<String>,
    ) -> Result<Self, StepUpPolicyError> {
        if dispositions.get(&RiskSignal::UntrustedExecutionPath) == Some(&SignalDisposition::Deny) {
            return Err(StepUpPolicyError::PathSignalCannotDeny);
        }
        Ok(Self {
            dispositions,
            untrusted_path_prefixes,
        })
    }

    /// The configured disposition for `signal`, defaulting to
    /// [`SignalDisposition::Informational`] when unnamed.
    #[must_use]
    pub fn disposition(&self, signal: RiskSignal) -> SignalDisposition {
        self.dispositions.get(&signal).copied().unwrap_or_default()
    }

    #[must_use]
    pub fn untrusted_path_prefixes(&self) -> &BTreeSet<String> {
        &self.untrusted_path_prefixes
    }
}

/// Every gate verdict [`assess`] classifies. Borrowed, never
/// re-collected — this module reads no fresh evidence of its own.
pub struct GateVerdicts<'a> {
    /// The session gate's membership verdict for this peer (HORO-791).
    /// Always present — `membership_for_peer` runs regardless of
    /// `session_requirement`.
    pub membership: &'a MembershipVerdict,
    /// Every approval candidate's own recall verdict from the approval
    /// gate's refusal scan (HORO-792) — must contain no `Matched`
    /// verdict, since `assess` is reachable only from the refusal path,
    /// which returns immediately on the first `Matched`.
    pub recall: &'a [RecallVerdict],
    /// The delegation gate's verdict (HORO-793), when delegation is
    /// configured. When `Some(DelegationVerdict::NotAdmitted { exceeded })`,
    /// `exceeded` must already be the caller's linked-grant-only
    /// narrowing (`linked_exceeded`) — never the raw audit-facing
    /// union — so [`RiskSignal::DelegationScopeExpanded`] is never fired
    /// by an unrelated stored grant for a different resource.
    pub delegation: Option<&'a DelegationVerdict>,
}

/// The outcome of classifying an already-produced refusal. All three
/// variants are still refusals — there is deliberately no
/// "admit"/"proceed" variant at all, so this layer can never loosen a
/// gate by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "verdict")]
pub enum StepUpVerdict {
    /// Every fired signal is [`SignalDisposition::Informational`] (or no
    /// signal fired at all) — the caller's pre-existing plain refusal
    /// stands unchanged; `signals` is recorded for audit only.
    NoStepUp { signals: BTreeSet<RiskSignal> },
    /// At least one fired signal is configured [`SignalDisposition::StepUp`]
    /// and none is [`SignalDisposition::Deny`] — the caller should
    /// report a step-up-specific denial naming `signals`.
    StepUpRequired { signals: BTreeSet<RiskSignal> },
    /// At least one fired signal is configured [`SignalDisposition::Deny`]
    /// — deny-overrides, order-independent, mirroring
    /// [`crate::policy::PolicySet::evaluate`]'s own precedence
    /// discipline.
    RiskDenied { signals: BTreeSet<RiskSignal> },
}

/// Classify an already-produced refusal (`verdicts`) into a
/// [`StepUpVerdict`], per `policy`. `observed` is the same
/// [`ExecutionContext`] the refusing gate(s) already evaluated against
/// — used here only for [`RiskSignal::UntrustedExecutionPath`]'s
/// string-prefix comparison and [`RiskSignal::PrivilegeEscalationToRoot`]'s
/// observed-uid check, never re-collected.
///
/// `assess` is **not** a fourth independent security check: unlike
/// `membership`/`recall`/`delegated_admission`, it reads no fresh
/// evidence and confers no authority — it only classifies verdicts
/// those three already produced. See the module docs for the full
/// argument.
///
/// Precedence, deny-overrides, order-independent (mirrors
/// [`crate::policy::PolicySet::evaluate`]'s own precedence discipline):
/// 1. any fired signal maps to [`SignalDisposition::Deny`] →
///    [`StepUpVerdict::RiskDenied`].
/// 2. else any fired signal maps to [`SignalDisposition::StepUp`] →
///    [`StepUpVerdict::StepUpRequired`].
/// 3. else → [`StepUpVerdict::NoStepUp`].
#[must_use]
pub fn assess(
    verdicts: &GateVerdicts<'_>,
    observed: &ExecutionContext,
    policy: &StepUpPolicy,
) -> StepUpVerdict {
    let mut signals = BTreeSet::new();

    let no_candidates = verdicts.recall.is_empty();
    let recall_changed = |dimension: ChangedDimension| {
        verdicts.recall.iter().any(|verdict| {
            matches!(verdict, RecallVerdict::NotMatched { changed } if changed.contains(&dimension))
        })
    };

    if no_candidates || recall_changed(ChangedDimension::LauncherPath) {
        signals.insert(RiskSignal::UnknownLauncher);
    }

    if let Evidence::Present { value, .. } = &observed.workload.executable_path {
        if policy
            .untrusted_path_prefixes
            .iter()
            .any(|prefix| value.starts_with(prefix.as_str()))
        {
            signals.insert(RiskSignal::UntrustedExecutionPath);
        }
    }

    if recall_changed(ChangedDimension::LauncherDigest) {
        signals.insert(RiskSignal::LauncherIdentityChanged);
    }

    let delegation_exceeds = |bound: ExceededBound| {
        matches!(
            verdicts.delegation,
            Some(DelegationVerdict::NotAdmitted { exceeded }) if exceeded.contains(&bound)
        )
    };

    let privilege_transition =
        recall_changed(ChangedDimension::OwnerUid) || delegation_exceeds(ExceededBound::OwnerUid);
    if privilege_transition {
        signals.insert(RiskSignal::PrivilegeTransition);
    }

    let observed_uid_is_root =
        matches!(&observed.workload.uid, Evidence::Present { value, .. } if *value == 0);
    if privilege_transition && observed_uid_is_root {
        signals.insert(RiskSignal::PrivilegeEscalationToRoot);
    }

    if matches!(
        verdicts.membership,
        MembershipVerdict::NotMember | MembershipVerdict::Indeterminate { .. }
    ) {
        signals.insert(RiskSignal::DetachedExecution);
    }

    if let Some(DelegationVerdict::NotAdmitted { exceeded }) = verdicts.delegation {
        let scope_expanded = exceeded.iter().any(|bound| {
            matches!(
                bound,
                ExceededBound::Resource
                    | ExceededBound::Action
                    | ExceededBound::Depth
                    | ExceededBound::Duration
            )
        });
        if scope_expanded {
            signals.insert(RiskSignal::DelegationScopeExpanded);
        }
    }

    if recall_changed(ChangedDimension::ResourceCapabilityState)
        || recall_changed(ChangedDimension::PolicyRevision)
    {
        signals.insert(RiskSignal::SecurityPostureChanged);
    }

    if recall_changed(ChangedDimension::CgroupPath)
        || delegation_exceeds(ExceededBound::CgroupPath)
        || delegation_exceeds(ExceededBound::SessionKey)
    {
        signals.insert(RiskSignal::ContextBoundaryChanged);
    }

    if delegation_exceeds(ExceededBound::TrustTransition) {
        signals.insert(RiskSignal::TrustTransition);
    }

    let any_indeterminate = matches!(verdicts.membership, MembershipVerdict::Indeterminate { .. })
        || verdicts
            .recall
            .iter()
            .any(|verdict| matches!(verdict, RecallVerdict::Indeterminate { .. }))
        || matches!(
            verdicts.delegation,
            Some(DelegationVerdict::Indeterminate { .. })
        );
    if any_indeterminate {
        signals.insert(RiskSignal::EvidenceIndeterminate);
    }

    if signals
        .iter()
        .any(|signal| policy.disposition(*signal) == SignalDisposition::Deny)
    {
        return StepUpVerdict::RiskDenied { signals };
    }
    if signals
        .iter()
        .any(|signal| policy.disposition(*signal) == SignalDisposition::StepUp)
    {
        return StepUpVerdict::StepUpRequired { signals };
    }
    StepUpVerdict::NoStepUp { signals }
}
