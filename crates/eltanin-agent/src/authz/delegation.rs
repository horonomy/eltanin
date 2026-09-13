//! Bounded compute delegation admission gate: agent-side configuration
//! plus the pure helper that turns an already-observed peer into
//! [`eltanin_core::delegation::DelegationGrant`]'s non-lease fields
//! (F-M2-003, HORO-793). Lives under `authz/` alongside the existing
//! policy/lease/session/approval integration — see
//! `tests/agent_architecture_guard.rs`'s `authz`-anchored exemption,
//! which this module relies on unchanged exactly like `authz::approval`
//! already does.
//!
//! # No re-collection — reuses the peer's already-observed context
//!
//! Same discipline as `authz::approval::binding_from_observed`: this
//! module introduces no new platform collector call. The caller passes
//! in the `ExecutionContext` and [`SessionKey`] evidence it already
//! collected earlier in the same request (`PeerContext::authorizable()`'s
//! observation, and `AuthorizationHandler::membership_for_peer`'s own
//! session-key collection) — never a second, independently-timed
//! observation of the same peer. This closes the same TOCTOU window
//! HORO-792 already closed for its own gate.

use eltanin_core::identity::{Evidence, EvidenceSource, ExecutionContext};
use eltanin_core::session::SessionKey;

/// The non-lease [`eltanin_core::delegation::DelegationGrant::mint`]
/// fields this ticket can honestly derive from an already-observed peer.
/// `owner_uid` is required — minting fails entirely without it (see
/// [`grant_binding_from_observed`]'s doc). `session_key`/`cgroup_path`
/// are `None` when the corresponding evidence is not
/// [`Evidence::Present`] with a non-`SelfAsserted` source — a grant
/// minted with no session/cgroup expectation simply skips that dimension
/// at [`eltanin_core::delegation::delegated_admission`] time when the
/// deployment does not set `require_same_session`/`require_same_cgroup`,
/// mirroring `ApprovalBinding`'s identical "skip, don't invent" contract.
pub(crate) struct GrantBinding {
    pub(crate) owner_uid: u32,
    pub(crate) session_key: Option<SessionKey>,
    pub(crate) cgroup_path: Option<String>,
}

/// Derive [`GrantBinding`] from `observed`/`peer_session_key` — both
/// already collected by the caller for this same request. Returns `None`
/// only when `owner_uid` itself is unavailable (missing, unsupported, or
/// self-asserted evidence) — a grant minted with no honest owner binding
/// would make [`eltanin_core::delegation::delegated_admission`]'s owner-uid
/// check meaningless, so minting must not proceed at all in that case
/// (mirrors `authz::approval::binding_from_observed`'s identical
/// all-or-nothing treatment of its own required `owner_uid` field).
#[must_use]
pub(crate) fn grant_binding_from_observed(
    observed: &ExecutionContext,
    peer_session_key: &Evidence<SessionKey>,
) -> Option<GrantBinding> {
    let owner_uid = match &observed.workload.uid {
        Evidence::Present { value, source } if *source != EvidenceSource::SelfAsserted => *value,
        _ => return None,
    };
    let session_key = match peer_session_key {
        Evidence::Present { value, source } if *source != EvidenceSource::SelfAsserted => {
            Some(*value)
        }
        _ => None,
    };
    let cgroup_path = match &observed.cgroup_path {
        Evidence::Present { value, source } if *source != EvidenceSource::SelfAsserted => {
            Some(value.clone())
        }
        _ => None,
    };
    Some(GrantBinding {
        owner_uid,
        session_key,
        cgroup_path,
    })
}
