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

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

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

/// A capability a backend may support for a given resource. Mirrors the
/// backend capability set named in HORO-784 (DISCOVER/OBSERVE/ATTRIBUTE/
/// AUTHORIZE/ENFORCE/REVOKE/ATTEST).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Discover,
    Observe,
    Attribute,
    Authorize,
    Enforce,
    Revoke,
    Attest,
}

/// The set of capabilities a backend actually supports for a resource.
///
/// Deliberately a value type, not a trait — "does this backend support
/// X" must be checkable data (so a caller can explicitly detect and
/// report a capability downgrade), never an assumption baked into
/// control flow.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCapabilities {
    supported: BTreeSet<Capability>,
}

impl ResourceCapabilities {
    pub fn new(supported: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            supported: supported.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn supports(&self, capability: Capability) -> bool {
        self.supported.contains(&capability)
    }

    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.supported.iter().copied()
    }
}

/// A protected resource: its identity plus what a backend actually
/// supports for it right now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResource {
    pub identity: ResourceIdentity,
    pub capabilities: ResourceCapabilities,
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
/// `Capability::Enforce` must report `Unsupported`, never silently
/// report `Allowed` as if enforcement had actually happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum EnforcementResult {
    Allowed,
    Denied { reason: String },
    Unsupported { capability: Capability },
    Error { message: String },
}
