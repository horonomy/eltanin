//! Remembered-authorization admission gate (F-M2-002, HORO-792):
//! agent-side configuration plus the pure helper that turns an already-
//! observed [`ExecutionContext`] into an [`ApprovalBinding`]. Lives
//! under `authz/` alongside the existing policy/lease/session
//! integration — see `tests/agent_architecture_guard.rs`'s `authz`-
//! anchored exemption, which this module relies on unchanged exactly
//! like `authz::session` already does.
//!
//! # No re-collection — reuses the peer's already-observed context
//!
//! Unlike `authz::session`, this module introduces no new platform
//! collector call. `PeerContext::authorizable()` already hands
//! `handle_request_lease` a freshly-observed [`ExecutionContext`] for
//! every request (the same one `provenance_for` binds the eventual
//! lease to) — [`binding_from_observed`] derives an [`ApprovalBinding`]
//! from *that* context, not a second, independently-timed collection.
//! This closes what would otherwise be a TOCTOU window between "the
//! context the approval gate checked" and "the context the lease is
//! actually bound to": there is only ever one observation per request.

use eltanin_core::approval::{ApprovalBinding, ExecutableDigest};
use eltanin_core::identity::{Evidence, EvidenceSource, ExecutionContext};
use eltanin_core::policy::PolicyProvenance;
use eltanin_core::resource::ResourceCapabilities;

/// Agent deployment configuration: whether `RequestLease` requires a
/// matching remembered approval before policy is ever consulted. This
/// is deployment config, not a new `Condition`/policy-DSL variant —
/// `eltanin_core::policy::PolicySet::evaluate` is completely untouched
/// by this ticket, exactly like `authz::session::SessionRequirement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApprovalRequirement {
    Required,
    #[default]
    NotRequired,
}

/// Derive the [`ApprovalBinding`] fields this ticket can honestly
/// observe from `observed`/`capabilities`/`policy`. `launcher_digest`/
/// `cgroup_path` are `None` when the corresponding evidence is not
/// [`Evidence::Present`] with a non-`SelfAsserted` source — an approval
/// recorded with no digest/cgroup expectation simply skips that
/// dimension at `recall` time (see `eltanin_core::approval`'s module
/// docs), rather than this function inventing a placeholder value.
#[must_use]
pub(crate) fn binding_from_observed(
    observed: &ExecutionContext,
    capabilities: ResourceCapabilities,
    policy: PolicyProvenance,
) -> Option<ApprovalBinding> {
    let owner_uid = match &observed.workload.uid {
        Evidence::Present { value, source } if *source != EvidenceSource::SelfAsserted => *value,
        _ => return None,
    };
    let launcher_path = match &observed.workload.executable_path {
        Evidence::Present { value, source } if *source != EvidenceSource::SelfAsserted => {
            value.clone()
        }
        _ => return None,
    };
    let launcher_digest = match &observed.workload.executable_hash {
        Evidence::Present { value, source } if *source != EvidenceSource::SelfAsserted => {
            Some(ExecutableDigest::new(value.clone()))
        }
        _ => None,
    };
    let cgroup_path = match &observed.cgroup_path {
        Evidence::Present { value, source } if *source != EvidenceSource::SelfAsserted => {
            Some(value.clone())
        }
        _ => None,
    };

    Some(ApprovalBinding {
        owner_uid,
        launcher_path,
        launcher_digest,
        cgroup_path,
        capabilities,
        policy,
    })
}
