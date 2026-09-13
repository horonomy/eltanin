//! Bounded compute delegation across agents, tools, and descendant
//! workloads (F-M2-003, HORO-793).
//!
//! # Headline decision — read this first, it is the whole security model
//!
//! A delegation edge is an explicit, agent-minted grant that is 1:1 with
//! a parent [`crate::lease::ComputeLease`]. Kernel-observed process
//! ancestry is **never** the source of delegated authority — only the
//! corroboration that the requesting descendant actually sits in the
//! claimed grant holder's process tree. Both uses of ancestry
//! ([`delegated_admission`]'s holder-liveness check and its
//! ancestry-linkage check) can only ever **reject**; neither can ever
//! **grant**. This mirrors `eltanin_core::policy`'s own rule — `ancestry`
//! is deliberately unmatchable by `Condition` (HORO-787: "parent process
//! alone cannot imply ALLOW") — and this module must never reintroduce
//! that bug by letting ancestry feed an ALLOW path directly rather than
//! merely corroborating or rejecting an already-agent-minted grant.
//!
//! # `DelegationGrant` is ephemeral, in-memory only
//!
//! Unlike [`crate::approval::Approval`] (durable, validated from disk),
//! [`DelegationGrant`] is `Serialize` only, with **no** `Deserialize` at
//! all — mirroring [`crate::session::TrustedSession`]'s discipline, not
//! `Approval`'s. A grant is bound to a live process plus a live lease;
//! neither survives an agent restart, so there is no on-disk shape for
//! this type whatsoever.
//!
//! # Structural coupling to the parent lease
//!
//! The only way to obtain a [`DelegationGrant`] is [`DelegationGrant::mint`],
//! which takes `&ComputeLease` (never raw fields) — `lease_id`,
//! `not_after`, and the scope seed all come from the real lease and
//! cannot be fabricated independently, the same structural trick
//! [`crate::lease::LeaseIssuer::issue`] and
//! [`crate::policy::PolicySet::evaluate`] use elsewhere in this crate.
//! [`DelegationScope`] has no public constructor at all — it is derived
//! entirely inside `mint` from the lease's own request, so there is no
//! way to construct an empty or independently-invented scope.
//!
//! # Ancestry ordering this module assumes
//!
//! [`delegated_admission`]'s ancestry-linkage and trust-transition scans
//! assume `requester.workload.ancestry[0]` is the requester's *immediate*
//! parent and increasing index walks *upward* toward the root — this is
//! exactly how `eltanin-linux`'s and `eltanin-macos`'s
//! `collect_workload_identity` build the vector (each step pushes the
//! next `ppid` found, walking away from the requester). If a future
//! collector ever reverses this order, [`delegated_admission`]'s check 4
//! span (`ancestry[0..k]`, exclusive of the holder at index `k`) would
//! silently invert to the wrong side of the holder.
//!
//! # Known, disclosed collector gap carried forward, not fixed here
//!
//! `eltanin-linux`'s ancestry walk can silently truncate on a
//! permission-denied `ppid` read (HORO-832) — it cannot distinguish
//! "reached the top of the tree" from "a read failed." This is safe for
//! delegation specifically because the failure mode is fail-closed: a
//! truncated walk just means [`delegated_admission`]'s ancestry-linkage
//! check misses the holder, falling back to `ExceededBound::AncestryLinkage`
//! and the ordinary approval gate/prompt — never a false grant.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Serialize;

use crate::identity::{
    Evidence, EvidenceSource, ExecutionContext, IdentityComparison, WorkloadIdentity,
};
use crate::lease::{ComputeLease, LeaseId, MonotonicTime};
use crate::resource::{Action, ComputeRequest, ResourceIdentity};
use crate::session::SessionKey;

/// Upper bound on ancestry-chain depth this module will ever trust —
/// matches `eltanin-linux`'s/`eltanin-macos`'s own `MAX_ANCESTRY_DEPTH`
/// collector bound (HORO-832/HORO-833). [`DelegationBounds::new`]
/// enforces `max_depth <= MAX_ANCESTRY_DEPTH` so a misconfigured deployment
/// can never demand delegation chains deeper than any collector could
/// ever corroborate.
pub const MAX_ANCESTRY_DEPTH: u8 = 32;

/// The set of resources/actions one [`DelegationGrant`] admits requests
/// for. Derived entirely inside [`DelegationGrant::mint`] from the
/// parent lease's own [`ComputeRequest`] — there is deliberately no
/// public constructor, so a [`DelegationScope`] can never be built
/// independently of a real, already-issued lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DelegationScope {
    resources: BTreeSet<ResourceIdentity>,
    actions: BTreeSet<Action>,
}

impl DelegationScope {
    fn from_request(request: &ComputeRequest) -> Self {
        let mut resources = BTreeSet::new();
        resources.insert(request.resource.clone());
        let mut actions = BTreeSet::new();
        actions.insert(request.action);
        Self { resources, actions }
    }

    #[must_use]
    pub fn resources(&self) -> &BTreeSet<ResourceIdentity> {
        &self.resources
    }

    #[must_use]
    pub fn actions(&self) -> &BTreeSet<Action> {
        &self.actions
    }
}

/// One agent-minted delegation edge, 1:1 with the parent
/// [`ComputeLease`] it narrows. `Serialize` only, deliberately **not**
/// `Deserialize` — see the module docs' "ephemeral, in-memory only"
/// section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DelegationGrant {
    lease_id: LeaseId,
    holder: WorkloadIdentity,
    owner_uid: u32,
    session_key: Option<SessionKey>,
    cgroup_path: Option<String>,
    scope: DelegationScope,
    depth: u8,
    not_after: MonotonicTime,
    parent: Option<LeaseId>,
}

impl DelegationGrant {
    /// The **only** constructor. `lease_id`/`not_after`/the scope seed
    /// all come from `lease` itself — never independently supplied — so
    /// a grant cannot be fabricated for authority a real lease never
    /// held.
    ///
    /// Returns `None` if `lease`'s action is not in
    /// `bounds.delegable_actions` — a lease bound to a non-delegable
    /// action is never eligible to seed a delegation edge at all.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn mint(
        lease: &ComputeLease,
        bounds: &DelegationBounds,
        holder: WorkloadIdentity,
        owner_uid: u32,
        session_key: Option<SessionKey>,
        cgroup_path: Option<String>,
        depth: u8,
        parent: Option<LeaseId>,
    ) -> Option<Self> {
        let request = &lease.origin().request;
        if !bounds.delegable_actions.contains(&request.action) {
            return None;
        }
        Some(Self {
            lease_id: lease.id().clone(),
            holder,
            owner_uid,
            session_key,
            cgroup_path,
            scope: DelegationScope::from_request(request),
            depth,
            not_after: lease.expires_at(),
            parent,
        })
    }

    #[must_use]
    pub fn lease_id(&self) -> &LeaseId {
        &self.lease_id
    }

    #[must_use]
    pub fn holder(&self) -> &WorkloadIdentity {
        &self.holder
    }

    #[must_use]
    pub fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    #[must_use]
    pub fn session_key(&self) -> Option<SessionKey> {
        self.session_key
    }

    #[must_use]
    pub fn cgroup_path(&self) -> Option<&str> {
        self.cgroup_path.as_deref()
    }

    #[must_use]
    pub fn scope(&self) -> &DelegationScope {
        &self.scope
    }

    #[must_use]
    pub fn depth(&self) -> u8 {
        self.depth
    }

    #[must_use]
    pub fn not_after(&self) -> MonotonicTime {
        self.not_after
    }

    #[must_use]
    pub fn parent(&self) -> Option<&LeaseId> {
        self.parent.as_ref()
    }
}

/// Why [`DelegationBounds::new`] refused a configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DelegationBoundsError {
    /// `delegable_actions` named an action this crate cannot honestly
    /// treat as delegable — today, only `Action::Unknown`'s
    /// `#[serde(other)]` catch-all falls in this case, since a
    /// malformed/未来 wire action must never silently become
    /// "delegable" by misconfiguration.
    #[error("Action::Unknown cannot be a delegable action")]
    ActionNotDelegable,
    #[error("max_depth {requested} exceeds the collector-verifiable maximum {maximum}")]
    DepthExceedsMax { requested: u8, maximum: u8 },
    /// Mirrors [`crate::lease::LeaseError::NonPositiveTtl`]'s "no safe
    /// default for a security-relevant duration" convention: a zero
    /// `min_remaining` would let a near-expired parent's admission slip
    /// through check 9 of [`delegated_admission`] and surface later as a
    /// misattributed `ExpiryOverflow` instead of a clean `Duration`
    /// refusal.
    #[error("min_remaining must be greater than zero")]
    NonPositiveMinRemaining,
}

/// Deployment-configured bounds every [`delegated_admission`] call is
/// evaluated against. Constructed only via the fallible [`Self::new`] —
/// there is no `Default` and no way to construct an unvalidated value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationBounds {
    max_depth: u8,
    max_child_ttl: Duration,
    min_remaining: Duration,
    delegable_actions: BTreeSet<Action>,
    transition_markers: BTreeSet<String>,
    require_same_session: bool,
    require_same_cgroup: bool,
}

impl DelegationBounds {
    /// # Errors
    ///
    /// Returns [`DelegationBoundsError::ActionNotDelegable`] if
    /// `delegable_actions` contains `Action::Unknown`;
    /// [`DelegationBoundsError::DepthExceedsMax`] if `max_depth` exceeds
    /// [`MAX_ANCESTRY_DEPTH`]; [`DelegationBoundsError::NonPositiveMinRemaining`]
    /// if `min_remaining` is zero.
    pub fn new(
        max_depth: u8,
        max_child_ttl: Duration,
        min_remaining: Duration,
        delegable_actions: impl IntoIterator<Item = Action>,
        transition_markers: impl IntoIterator<Item = String>,
        require_same_session: bool,
        require_same_cgroup: bool,
    ) -> Result<Self, DelegationBoundsError> {
        let delegable_actions: BTreeSet<Action> = delegable_actions.into_iter().collect();
        if delegable_actions.contains(&Action::Unknown) {
            return Err(DelegationBoundsError::ActionNotDelegable);
        }
        if max_depth > MAX_ANCESTRY_DEPTH {
            return Err(DelegationBoundsError::DepthExceedsMax {
                requested: max_depth,
                maximum: MAX_ANCESTRY_DEPTH,
            });
        }
        if min_remaining.is_zero() {
            return Err(DelegationBoundsError::NonPositiveMinRemaining);
        }
        Ok(Self {
            max_depth,
            max_child_ttl,
            min_remaining,
            delegable_actions,
            transition_markers: transition_markers.into_iter().collect(),
            require_same_session,
            require_same_cgroup,
        })
    }

    #[must_use]
    pub fn max_depth(&self) -> u8 {
        self.max_depth
    }

    #[must_use]
    pub fn max_child_ttl(&self) -> Duration {
        self.max_child_ttl
    }

    #[must_use]
    pub fn min_remaining(&self) -> Duration {
        self.min_remaining
    }

    #[must_use]
    pub fn delegable_actions(&self) -> &BTreeSet<Action> {
        &self.delegable_actions
    }

    #[must_use]
    pub fn transition_markers(&self) -> &BTreeSet<String> {
        &self.transition_markers
    }

    #[must_use]
    pub fn require_same_session(&self) -> bool {
        self.require_same_session
    }

    #[must_use]
    pub fn require_same_cgroup(&self) -> bool {
        self.require_same_cgroup
    }
}

/// Which dimension(s) [`delegated_admission`] found exceeded. A rich,
/// accumulating set — following this crate's established pattern (see
/// [`crate::approval::ChangedDimension`]) — rather than a single reason,
/// so an audit trail can see every bound a request failed, not just the
/// first one checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceededBound {
    Resource,
    Action,
    Duration,
    Depth,
    AncestryLinkage,
    TrustTransition,
    HolderLiveness,
    OwnerUid,
    SessionKey,
    CgroupPath,
}

/// The result of [`delegated_admission`]. A rich enum, not a `bool` —
/// same established pattern as [`crate::session::MembershipVerdict`]/
/// [`crate::approval::RecallVerdict`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "verdict")]
pub enum DelegationVerdict {
    Admitted {
        depth: u8,
        not_after: MonotonicTime,
        parent_lease: LeaseId,
    },
    NotAdmitted {
        exceeded: BTreeSet<ExceededBound>,
    },
    /// The evidence needed to decide at least one dimension could not be
    /// confirmed (missing/unsupported/self-asserted where admission
    /// needed a real value). Callers must treat this identically to
    /// `NotAdmitted` — never as `Admitted` — fail-closed, same
    /// discipline as [`crate::session::MembershipVerdict::Indeterminate`]/
    /// [`crate::approval::RecallVerdict::Indeterminate`].
    Indeterminate {
        reason: String,
    },
}

fn indeterminate(reason: impl Into<String>) -> DelegationVerdict {
    DelegationVerdict::Indeterminate {
        reason: reason.into(),
    }
}

/// Determine whether `requester` — freshly observed at call time — may
/// admit under `grant`, per `bounds`. `requester_session_key` is the
/// freshly re-collected [`Evidence<SessionKey>`] for the same requesting
/// peer `requester` describes (kept as a separate parameter rather than
/// folded into `ExecutionContext`, since session-key collection is
/// `authz::session`'s concern, not `identity`'s — the same shape
/// [`crate::session::membership`] already uses for its own `peer_key`
/// parameter). `observed_holder` is freshly re-observed for
/// `grant.holder().pid`, at call time, by the caller — never trusted
/// from `grant` itself, which only records what the holder looked like
/// at mint time.
///
/// The **one** combined signature, same discipline as
/// [`crate::session::membership`]/[`crate::approval::recall`]: evidence
/// freshness, holder liveness, ancestry linkage, and every scope/depth/
/// duration bound are checked together, never as a lookup step followed
/// by a separate check.
///
/// Checks run in this order (load-bearing, not incidental — see each
/// step's own comment); comparable dimensions accumulate into
/// `NotAdmitted`'s `exceeded` set, but any unusable/missing/self-asserted
/// evidence needed to decide a dimension makes the whole call return
/// [`DelegationVerdict::Indeterminate`] immediately — fail-closed, never
/// silently treated as "that dimension didn't match."
///
/// `#[allow(clippy::too_many_lines)]`: the ticket's own contract (and
/// this crate's established `recall`/`membership` precedent) requires
/// this to stay the **one** combined function — splitting it into
/// smaller helpers would reintroduce exactly the "lookup step, then
/// separate check" structure this design forbids.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn delegated_admission(
    grant: &DelegationGrant,
    bounds: &DelegationBounds,
    requester: &ExecutionContext,
    requester_session_key: &Evidence<SessionKey>,
    observed_holder: &WorkloadIdentity,
    request: &ComputeRequest,
    now: MonotonicTime,
) -> DelegationVerdict {
    let mut exceeded = BTreeSet::new();

    // 1. Holder liveness — corroboration only, can only reject.
    match grant.holder.compare_process(observed_holder) {
        IdentityComparison::Same => {}
        IdentityComparison::Different => {
            exceeded.insert(ExceededBound::HolderLiveness);
        }
        IdentityComparison::Indeterminate => {
            return indeterminate("grant holder liveness could not be confirmed");
        }
    }

    // 2. Ancestry linkage — scan the requester's freshly observed
    // ancestry (index 0 = immediate parent, increasing index walks
    // upward — see the module docs' "Ancestry ordering" section) for the
    // grant holder. Continue scanning past an individual unresolvable
    // entry rather than failing on the first one — an unreadable start
    // token partway up the chain (the documented eltanin-linux collector
    // gap, HORO-832) must not prevent a `Same` found further up from
    // being honored. Only report `Indeterminate` if the scan never finds
    // `Same` and encountered at least one entry it could not resolve;
    // if it never finds `Same` and every entry was cleanly `Different`,
    // that is a confirmed `AncestryLinkage` failure, not an
    // indeterminate one. This is corroboration only — it can never grant.
    let mut holder_index: Option<usize> = None;
    let mut saw_unresolved = false;
    for (index, ancestor) in requester.workload.ancestry.iter().enumerate() {
        match grant.holder.compare_ancestor(ancestor) {
            IdentityComparison::Same => {
                holder_index = Some(index);
                break;
            }
            IdentityComparison::Different => {}
            IdentityComparison::Indeterminate => {
                saw_unresolved = true;
            }
        }
    }
    let holder_index = if let Some(index) = holder_index {
        index
    } else {
        if saw_unresolved {
            return indeterminate(
                "requester ancestry contained unresolvable evidence and no confirmed link to the grant holder",
            );
        }
        exceeded.insert(ExceededBound::AncestryLinkage);
        // No confirmed span to scan for trust-transition markers below —
        // treat the whole (unlinked) ancestry as the span, so a marker
        // anywhere in it still surfaces, though `AncestryLinkage` alone
        // already fails this admission.
        requester.workload.ancestry.len()
    };

    // 3. Owner uid — fail closed on missing/unsupported/self-asserted.
    match &requester.workload.uid {
        Evidence::Present {
            value,
            source: EvidenceSource::SelfAsserted,
        } => {
            let _ = value;
            return indeterminate("requester uid evidence was self-asserted");
        }
        Evidence::Present { value, .. } => {
            if *value != grant.owner_uid {
                exceeded.insert(ExceededBound::OwnerUid);
            }
        }
        Evidence::Missing { .. } | Evidence::Unsupported => {
            return indeterminate("requester uid evidence is unavailable");
        }
    }

    // 4. Trust-transition scan over ancestry[0..holder_index] only —
    // strictly between the requester and the holder, exclusive of the
    // holder itself. Evidence unusable *within* this span fails closed;
    // evidence at or above `holder_index` is never inspected at all.
    for ancestor in &requester.workload.ancestry[..holder_index] {
        match &ancestor.executable_path {
            Evidence::Present {
                value,
                source: EvidenceSource::SelfAsserted,
            } => {
                let _ = value;
                return indeterminate(
                    "an ancestor's executable path evidence was self-asserted within the trust-transition span",
                );
            }
            Evidence::Present { value, .. } => {
                if bounds.transition_markers.contains(value) {
                    exceeded.insert(ExceededBound::TrustTransition);
                }
            }
            Evidence::Missing { .. } | Evidence::Unsupported => {
                return indeterminate(
                    "an ancestor's executable path evidence is unavailable within the trust-transition span",
                );
            }
        }
    }

    // 5. Session key, only when required.
    if bounds.require_same_session {
        match requester_session_key {
            Evidence::Present {
                value,
                source: EvidenceSource::SelfAsserted,
            } => {
                let _ = value;
                return indeterminate("requester session-key evidence was self-asserted");
            }
            Evidence::Present { value, .. } => {
                if grant.session_key != Some(*value) {
                    exceeded.insert(ExceededBound::SessionKey);
                }
            }
            Evidence::Missing { .. } | Evidence::Unsupported => {
                return indeterminate("requester session-key evidence is unavailable");
            }
        }
    }

    // 6. Cgroup path, only when required. `Unsupported` (expected on
    // macOS) fails closed to `Indeterminate` — never silently satisfied.
    if bounds.require_same_cgroup {
        match &requester.cgroup_path {
            Evidence::Present {
                value,
                source: EvidenceSource::SelfAsserted,
            } => {
                let _ = value;
                return indeterminate("requester cgroup-path evidence was self-asserted");
            }
            Evidence::Present { value, .. } => {
                if grant.cgroup_path.as_deref() != Some(value.as_str()) {
                    exceeded.insert(ExceededBound::CgroupPath);
                }
            }
            Evidence::Missing { .. } | Evidence::Unsupported => {
                return indeterminate("requester cgroup-path evidence is unavailable");
            }
        }
    }

    // 7. Resource/action scope.
    if !grant.scope.resources.contains(&request.resource) {
        exceeded.insert(ExceededBound::Resource);
    }
    if !grant.scope.actions.contains(&request.action) {
        exceeded.insert(ExceededBound::Action);
    }

    // 8. Depth.
    if grant.depth.saturating_add(1) > bounds.max_depth {
        exceeded.insert(ExceededBound::Depth);
    }

    // 9. Duration — a near-expired parent is reported here, as `Duration`,
    // never left to surface later as a misattributed `ExpiryOverflow`
    // when the caller's own clock composes `narrow_expiry`'s result
    // against `now` again after this call returns.
    if grant.not_after.saturating_duration_since(now) < bounds.min_remaining {
        exceeded.insert(ExceededBound::Duration);
    }

    if !exceeded.is_empty() {
        return DelegationVerdict::NotAdmitted { exceeded };
    }

    let capped_not_after = match now.checked_add(bounds.max_child_ttl) {
        Some(ttl_bound) => grant.not_after.min(ttl_bound),
        None => grant.not_after,
    };

    DelegationVerdict::Admitted {
        depth: grant.depth.saturating_add(1),
        not_after: capped_not_after,
        parent_lease: grant.lease_id.clone(),
    }
}
