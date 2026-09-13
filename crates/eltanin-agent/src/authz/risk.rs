//! Risk-based step-up admission glue (F-M2-004, HORO-794). Lives under
//! `authz/` alongside the existing policy/lease/session/approval/
//! delegation integration — see `tests/agent_architecture_guard.rs`'s
//! `authz`-anchored exemption, which this module relies on unchanged
//! exactly like `authz::approval`/`authz::delegation` already do.
//!
//! # Glue only — no independent security decision here
//!
//! This module owns two small, pure translations between this crate's
//! raw gate state and [`eltanin_core::risk`]'s pure classification
//! function — it introduces no new evidence collection and makes no
//! admission decision of its own. See [`eltanin_core::risk`]'s module
//! docs for the actual security argument.

use std::collections::BTreeSet;

use eltanin_core::approval::RecallVerdict;
use eltanin_core::delegation::{DelegationVerdict, ExceededBound};
use eltanin_core::identity::ExecutionContext;
use eltanin_core::risk::{assess, GateVerdicts, StepUpPolicy, StepUpVerdict};
use eltanin_core::session::MembershipVerdict;

/// The bug-fix predicate (see `AuthorizationHandler::delegation_admission`'s
/// own doc comment on `DelegationAdmission::Refused`): a grant's
/// `exceeded` set counts as "genuinely about this requester" only when
/// it contains neither `ExceededBound::AncestryLinkage` nor
/// `ExceededBound::HolderLiveness` — those two mean the candidate grant
/// simply is not this requester's (a lookup miss on
/// `DelegationState::candidates`'s unfiltered list), not a scope-
/// expansion attempt by a real linked descendant.
#[must_use]
pub(crate) fn is_linked_grant_failure(exceeded: &BTreeSet<ExceededBound>) -> bool {
    !exceeded.contains(&ExceededBound::AncestryLinkage)
        && !exceeded.contains(&ExceededBound::HolderLiveness)
}

/// Classify an already-produced refusal into a [`StepUpVerdict`].
/// `delegation` is `None` when delegation is not configured for this
/// deployment; when `Some`, it must already reflect the caller's own
/// linked-grant-only narrowing (see [`is_linked_grant_failure`]) — never
/// the raw, unfiltered union — so `eltanin_core::risk::RiskSignal::
/// DelegationScopeExpanded` is never fired by an unrelated stored grant.
#[must_use]
pub(crate) fn assess_refusal(
    membership: &MembershipVerdict,
    recall: &[RecallVerdict],
    delegation: Option<&DelegationVerdict>,
    observed: &ExecutionContext,
    policy: &StepUpPolicy,
) -> StepUpVerdict {
    let verdicts = GateVerdicts {
        membership,
        recall,
        delegation,
    };
    assess(&verdicts, observed, policy)
}
