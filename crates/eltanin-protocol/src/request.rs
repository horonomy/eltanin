//! Wire request types.
//!
//! Deliberately absent from every type in this module: any identity or
//! evidence field. See the crate-level docs for the full rationale — in
//! short, `eltanin-protocol` contains no producer of
//! [`eltanin_core::identity::Evidence`],
//! [`eltanin_core::identity::WorkloadIdentity`], or
//! [`eltanin_core::identity::ExecutionContext`], so nothing decoded from
//! the wire can ever become one.

use eltanin_core::identity::ExecutionContext;
use eltanin_core::lease::LeaseId;
use eltanin_core::provenance::ProvenanceRecord;
use eltanin_core::resource::{Action, ComputeRequest, ResourceIdentity};
use serde::{Deserialize, Serialize};

/// A client-chosen correlation id, echoed back on the matching response.
/// Carries no authority — see the crate docs' derived-vs-client table.
/// A bounded integer rather than a `String` so a request id cannot
/// itself be used to inflate a frame within the size bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(pub u64);

/// Request a [`eltanin_core::lease::ComputeLease`] for `resource` and
/// `action`. This is a request *parameter*, not an authority claim —
/// default-deny policy means naming a resource/action can only narrow
/// what the agent's derived context is already permitted to do, never
/// grant it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequest {
    pub resource: ResourceIdentity,
    pub action: Action,
}

/// Ask the agent to release a previously issued lease.
///
/// `lease_id` is a lookup key, not a capability — see
/// [`eltanin_core::lease::LeaseId`]'s own docs: it carries no entropy and
/// was never meant to imply "is authorized." **Known limitation, a named
/// obligation on HORO-840**: `LeaseIssuer::revoke` alone only checks
/// issuer identity and sequence range, so a client that names another
/// workload's `lease_id` could otherwise revoke it. HORO-840's release
/// handler must additionally compare the stored lease's
/// `origin.context.workload` against freshly-derived peer identity
/// (`compare_process` and `compare_executable`, both reporting `Same`)
/// before calling `revoke`; every other outcome must be reported as
/// [`crate::response::ReleaseOutcome::Refused`], never as a distinction
/// the client can use to enumerate other clients' leases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRequest {
    pub lease_id: LeaseId,
}

/// The operation a client is asking the agent to perform.
///
/// Deliberately has **no** `#[serde(other)]` catch-all: an unrecognized
/// operation is a decode error ([`crate::response::ErrorCode::UnknownOperation`]),
/// never a silently-tolerated variant. This is the opposite choice from
/// [`eltanin_core::resource::Action::Unknown`], which exists so an
/// unrecognized *action inside an otherwise-valid request* still
/// round-trips for audit fidelity and simply matches no policy rule —
/// harmless because default-deny already handles it. An unrecognized
/// top-level *operation* has no such fallback shape to decode into, so
/// it must fail the whole request instead.
///
/// `ValidateLease` is deliberately not a variant here for MVP 1.0: no
/// caller in the `eltanin run` flow needs to independently validate a
/// lease it already holds, and enforcement of a lease is agent-side
/// (F-M1-007), not something a client-driven validate call gates. Adding
/// it later is additive and version-visible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "op")]
pub enum ClientRequest {
    RequestLease(LeaseRequest),
    ReleaseLease(ReleaseRequest),
    AgentStatus,
}

/// One versioned, correlated request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestBody {
    pub request_id: RequestId,
    pub body: ClientRequest,
}

/// A full wire request: [`RequestBody`] wrapped in
/// [`eltanin_core::envelope::Versioned`]. MVP 1.0 deliberately reuses the
/// domain schema version rather than minting a separate IPC protocol
/// version — see the crate docs for why a second version number would be
/// an unearned compatibility promise this codebase doesn't keep yet.
pub type Request = eltanin_core::envelope::Versioned<RequestBody>;

/// The only path from a decoded wire request to a
/// [`ProvenanceRecord`]. `derived` must come from the agent's own
/// collector, keyed on the transport-derived peer process id — **never**
/// from anything in `request`. This function's signature is the
/// enforcement: `eltanin-protocol` contains no function that returns an
/// [`ExecutionContext`], so `derived` can only have come from outside
/// this crate.
#[must_use]
pub fn provenance_for(request: &LeaseRequest, derived: ExecutionContext) -> ProvenanceRecord {
    ProvenanceRecord::new(
        derived,
        ComputeRequest {
            resource: request.resource.clone(),
            action: request.action,
        },
    )
}
