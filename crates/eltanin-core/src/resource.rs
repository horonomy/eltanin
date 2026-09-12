//! Protected resource domain: `ResourceIdentity`, `ResourceCapabilities`,
//! `ProtectedResource`, and the `ComputeRequest`/`Action`/
//! `EnforcementResult` seams later Features (policy, lease, agent, audit)
//! build on.
//!
//! Nothing here may name NVIDIA, CUDA, a Linux device node, or a cgroup —
//! see `docs/product/PRODUCT_CONSTITUTION.md`'s vendor-neutral-core rule.
//! `ResourceVendor`/`ResourceKind` are opaque string-backed tags rather
//! than closed enums: the set of real-world vendors/kinds is owned by
//! whichever adapter crate defines a concrete one (e.g. `eltanin-nvidia`),
//! never by this crate, and an arbitrary/unrecognized tag round-trips
//! through serialization without being collapsed into a lossy `Unknown`
//! placeholder — a real requirement for audit evidence (F-M1-009) to
//! actually preserve what was observed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How well a backend supports a given [`Capability`] for a resource.
///
/// This is what lets the system distinguish *functional compatibility*
/// from *device-level protection*: a backend can be `Supported` on
/// `ControlledLaunch` while remaining `Unsupported` on `DeviceEnforce` —
/// see `docs/adr/0006-cross-accelerator-capability-and-memory-model.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportState {
    /// The capability is fully implemented and proven for this resource.
    Supported,
    /// The capability works in some but not all cases (e.g. a subset of
    /// requests, or with reduced guarantees).
    Partial,
    /// The backend has determined this capability does not work for this
    /// resource.
    Unsupported,
    /// No determination has been made yet. This is also the implicit
    /// state of any capability not present in a
    /// [`ResourceCapabilities`]'s map — absence means "not evaluated,"
    /// never "supported."
    NotEvaluated,
}

impl SupportState {
    /// True only for [`SupportState::Supported`] — the sole state in
    /// which a caller may rely on the capability actually working.
    #[must_use]
    pub fn is_proven(self) -> bool {
        matches!(self, Self::Supported)
    }
}

/// The vendor that owns a protected resource, as an opaque tag. This
/// crate never matches on a specific vendor's value — see the module
/// docs above for why it isn't a closed enum naming real vendors.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceVendor(String);

impl ResourceVendor {
    pub fn new(tag: impl Into<String>) -> Self {
        Self(tag.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Tag used by the deterministic Fake Compute Backend (HORO-827).
    #[must_use]
    pub fn fake() -> Self {
        Self("fake".to_string())
    }
}

/// The class of protected resource, as an opaque tag. MVP 1.0 only ever
/// produces [`ResourceKind::gpu`]; see [`ResourceVendor`] for why this is
/// a string tag rather than a closed enum.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceKind(String);

impl ResourceKind {
    pub fn new(tag: impl Into<String>) -> Self {
        Self(tag.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn gpu() -> Self {
        Self("gpu".to_string())
    }
}

/// Stable identity for one protected resource instance.
///
/// `local_id` is whatever stable local identifier the vendor backend
/// assigns (e.g. a GPU index or UUID string) — it is opaque to this
/// crate, which never parses or interprets it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ResourceIdentity {
    pub vendor: ResourceVendor,
    pub kind: ResourceKind,
    pub local_id: String,
}

/// A capability a backend may support for a given resource.
///
/// Nine independently-evaluated semantic dimensions, per the MVP 1.0
/// Apple Silicon scope amendment (HORO-1011) — the original HORO-784
/// set (DISCOVER/OBSERVE/ATTRIBUTE/AUTHORIZE/ENFORCE/REVOKE/ATTEST)
/// conflated "the backend can launch/observe a workload" with "the
/// backend can enforce/revoke device-level access to it," which no
/// longer holds once a backend (e.g. an Apple Silicon adapter) can be
/// `Supported` on the former while remaining `Unsupported` on the
/// latter. `ControlledLaunch` supported must never be read as implying
/// `DeviceEnforce`/`DeviceRevoke` supported — see
/// `docs/adr/0006-cross-accelerator-capability-and-memory-model.md`.
///
/// Declaration order is load-bearing: [`ResourceCapabilities`] stores
/// these as `BTreeMap` keys, so this order fixes serialized key order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Can the backend enumerate this resource exists at all.
    DiscoverResource,
    /// Can the backend observe this resource's own state (e.g. utilization).
    ObserveResource,
    /// Can the backend observe a workload running against this resource.
    ObserveWorkload,
    /// Can the backend attribute an observed workload to a requester.
    AttributeWorkload,
    /// Can the backend evaluate an authorization decision for this resource.
    Authorize,
    /// Can the backend launch a workload under a controlled/observed
    /// context. Functional capability only — never implies device-level
    /// enforcement or revoke.
    ControlledLaunch,
    /// Can the backend deny/kill access at the device level.
    DeviceEnforce,
    /// Can the backend revoke already-granted device-level access.
    DeviceRevoke,
    /// Can the backend produce a verifiable attestation of the above.
    Attest,
}

/// The support state a backend actually reports for each capability of a
/// resource.
///
/// Deliberately a value type, not a trait — "does this backend support
/// X, and how well" must be checkable data (so a caller can explicitly
/// detect and report a capability downgrade), never an assumption baked
/// into control flow.
///
/// The internal map deliberately has no `#[serde(default)]`: an older
/// `{"supported": [...]}` document (the pre-HORO-1011 shape) must fail
/// to decode loudly, not silently become an empty map — which would
/// read as "every capability `NotEvaluated`" and erase the old
/// document's claims. See
/// `docs/adr/0006-cross-accelerator-capability-and-memory-model.md`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCapabilities {
    support: BTreeMap<Capability, SupportState>,
}

impl ResourceCapabilities {
    /// Every listed capability is [`SupportState::Supported`]; anything
    /// not listed is [`SupportState::NotEvaluated`], never `Supported`.
    /// For a backend that knows about partial/unsupported states, use
    /// [`Self::from_states`] instead.
    pub fn new(supported: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            support: supported
                .into_iter()
                .map(|capability| (capability, SupportState::Supported))
                .collect(),
        }
    }

    /// Explicit per-capability support states, for a backend that can
    /// distinguish `Partial`/`Unsupported` from "not evaluated."
    pub fn from_states(states: impl IntoIterator<Item = (Capability, SupportState)>) -> Self {
        Self {
            support: states.into_iter().collect(),
        }
    }

    /// A capability absent from the map is [`SupportState::NotEvaluated`]
    /// — absence never means "supported."
    #[must_use]
    pub fn state_of(&self, capability: Capability) -> SupportState {
        self.support
            .get(&capability)
            .copied()
            .unwrap_or(SupportState::NotEvaluated)
    }

    /// True iff `capability`'s state is exactly [`SupportState::Supported`].
    /// `Partial`, `Unsupported`, and an absent entry all return `false` —
    /// this is the fail-closed guarantee that partial or unproven support
    /// can never be read as full protection.
    #[must_use]
    pub fn supports(&self, capability: Capability) -> bool {
        self.state_of(capability).is_proven()
    }

    pub fn iter(&self) -> impl Iterator<Item = (Capability, SupportState)> + '_ {
        self.support.iter().map(|(&c, &s)| (c, s))
    }
}

/// An accelerator's memory topology, reported truthfully rather than
/// assumed. `Unified` deliberately carries no byte count — a
/// shared-memory backend (e.g. Apple Silicon) is never required to
/// report a fictitious dedicated-VRAM size. A shared memory pool is not,
/// by itself, an isolation boundary against the host process — see
/// `docs/adr/0006-cross-accelerator-capability-and-memory-model.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "model")]
pub enum AcceleratorMemory {
    /// Memory the accelerator owns exclusively, with a known size.
    Dedicated { total_bytes: u64 },
    /// Memory shared with the host; no byte count is required.
    Unified,
    /// The backend cannot honestly report a memory model.
    #[default]
    NotReportable,
}

/// A protected resource: its identity, what a backend actually supports
/// for it right now, and its memory topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResource {
    pub identity: ResourceIdentity,
    pub capabilities: ResourceCapabilities,
    /// Added by HORO-1011. Additive on decode: absent from older-shaped
    /// JSON decodes as [`AcceleratorMemory::NotReportable`], never a
    /// hard failure.
    #[serde(default)]
    pub memory: AcceleratorMemory,
}

/// What a workload is asking to do. MVP 1.0 has exactly one meaningful
/// action; `Unknown` exists so a future action is additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Compute,
    #[serde(other)]
    Unknown,
}

/// A request to perform `action` against a specific protected resource.
/// This is the seam F-M1-004 (policy) and F-M1-005 (lease) evaluate
/// against — it carries no identity/provenance of *who* is asking; that
/// is `WorkloadIdentity`/`ExecutionContext` (F-M1-003), composed
/// alongside this type by its callers, not folded into it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeRequest {
    pub resource: ResourceIdentity,
    pub action: Action,
}

/// The outcome of attempting to enforce an authorization decision at the
/// device/backend layer. `Unsupported` is a distinct, first-class
/// variant — see the module doc and HORO-784's AC: a backend that lacks
/// `Capability::DeviceEnforce` must report `Unsupported`, never silently
/// report `Allowed` as if enforcement had actually happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum EnforcementResult {
    Allowed,
    Denied { reason: String },
    Unsupported { capability: Capability },
    Error { message: String },
}
