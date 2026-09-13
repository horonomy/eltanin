//! Remembered authorization intent (F-M2-002, HORO-792).
//!
//! Core principle: **remember authorization intent, never remember
//! possession of privilege.** An [`Approval`] records that a user, once,
//! approved a stable launcher/context to ask for a specific
//! `(resource, action)` — it is never itself a grant. It is a second,
//! independent pre-policy admission gate, placed structurally like
//! HORO-791's [`crate::session`] gate: it decides whether a request may
//! even reach [`crate::policy::PolicySet::evaluate`], never what that
//! evaluation returns. See ADR 0010 for the full design record,
//! rejected alternatives, and the honest disclosure of what this
//! mechanism does *not* protect against.
//!
//! # `Serialize`-only validated type, `Deserialize`-safe raw document
//!
//! Unlike [`crate::session::TrustedSession`] and
//! [`crate::lease::ComputeLease`] — which must never be reconstructed
//! from bytes at all, because they *are* the bearer authority a session
//! or lease grants — [`Approval`] is deliberately reconstructible from
//! an on-disk document, because a durable approval must survive an
//! agent restart. This is safe for the same reason
//! [`crate::policy::PolicySet::from_document`] safely turns untrusted
//! policy bytes into something evaluable: the raw on-disk shape
//! ([`ApprovalEntry`]/[`ApprovalDocument`]) is a plain,
//! `Deserialize`-safe row, and [`ApprovalSet::from_document`] is the
//! *only* path from that row to a validated [`Approval`] — mirroring
//! `PolicySet`'s own document/validated-set split exactly.
//!
//! The security argument this rests on (spelled out fully in ADR 0010):
//! even a forged on-disk entry only buys the right to *reach*
//! `PolicySet::evaluate` — policy must still independently allow, and
//! every [`ApprovalBinding`] dimension is re-observed fresh from the
//! kernel at [`recall`] time, which a static file cannot supply or
//! fake. The bytes are evidence to re-validate, never bare authority.
//!
//! # `recall` is the one security-critical entry point
//!
//! [`recall`] is deliberately a single combined signature — evidence
//! freshness and every material-change dimension are checked together,
//! never as a lookup step followed by a separate check — mirroring
//! [`crate::session::membership`]'s own discipline and for the same
//! reason: splitting it would let a caller look an approval up once and
//! reuse that lookup's result without ever re-confirming the launcher
//! context still matches.
//!
//! Candidate lookup (which stored [`Approval`] even applies) is keyed on
//! `(resource, action)` only — see [`ApprovalSet::candidates`]. Every
//! other dimension is a *compared* dimension inside [`recall`], not a
//! lookup key, so a uid or digest change surfaces as a named
//! [`ChangedDimension`] for audit rather than a silent lookup miss.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::envelope::{UnsupportedVersion, Versioned};
use crate::identity::{Evidence, EvidenceSource, ExecutionContext};
use crate::policy::{PolicyId, PolicyProvenance};
use crate::resource::{Action, ComputeRequest, ResourceCapabilities, ResourceIdentity};

/// A content-derived digest of one executable's bytes, as computed by a
/// platform adapter (`eltanin-linux`/`eltanin-macos`) — never hashed
/// here. Opaque like [`crate::identity::ProcessStartToken`]: this crate
/// never inspects its bytes, only compares it for equality.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecutableDigest(String);

impl ExecutableDigest {
    pub fn new(digest: impl Into<String>) -> Self {
        Self(digest.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What `eltanin approve` recorded. `Once` lives entirely in agent
/// memory with a short TTL and is consumed on first successful
/// [`RecallVerdict::Matched`] use; `Remember`/`Deny` are durable. See
/// the crate-level docs' "Do NOT build in this ticket" section — there
/// is no TTL on `Remember`/`Deny` here: durable approvals are
/// invalidated by material-change detection or explicit `forget`, never
/// by expiry, because this crate never reads a wall clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDisposition {
    Once,
    Remember,
    Deny,
}

/// A correlation identifier for one [`Approval`]. Deliberately **not**
/// shaped like [`crate::lease::LeaseId`]/[`crate::session::SessionId`]
/// (both embed an [`crate::lease::IssuerInstanceId`] and are
/// restart-scoped) — an `ApprovalId` is a deterministic digest of the
/// binding it names, so the same launcher/context/request always
/// produces the same id across an agent restart. Carries no entropy and
/// is not a capability.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApprovalId(String);

impl ApprovalId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Wrap a raw string as an `ApprovalId` for a lookup — e.g. what
    /// `eltanin approve forget <id>` parses from argv (the id a prior
    /// `eltanin approve`/`approve list` printed back). Carries no
    /// entropy and is not a capability: constructing one this way
    /// grants nothing by itself, it is only useful if it happens to
    /// match a stored approval's own `ApprovalId::compute`-derived
    /// value.
    #[must_use]
    pub fn from_raw(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// Deterministically derive an id from the identity-anchoring
    /// dimensions of `binding` plus `resource`/`action`. Deliberately
    /// **excludes** `binding.capabilities`/`binding.policy`: those are
    /// dynamic, *compared* dimensions at [`recall`] time, not identity —
    /// including them here would mint a new, unrelated id every time
    /// capacity or policy revision drifted, fragmenting what is really
    /// one launcher's one remembered approval into many.
    fn compute(
        owner_uid: u32,
        launcher_path: &str,
        launcher_digest: Option<&ExecutableDigest>,
        cgroup_path: Option<&str>,
        resource: &ResourceIdentity,
        action: Action,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(owner_uid.to_le_bytes());
        hasher.update(b"\0");
        hasher.update(launcher_path.as_bytes());
        hasher.update(b"\0");
        hasher.update(
            launcher_digest
                .map_or("", ExecutableDigest::as_str)
                .as_bytes(),
        );
        hasher.update(b"\0");
        hasher.update(cgroup_path.unwrap_or("").as_bytes());
        hasher.update(b"\0");
        hasher.update(resource.vendor.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(resource.kind.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(resource.local_id.as_bytes());
        hasher.update(b"\0");
        hasher.update([u8::from(matches!(action, Action::Compute))]);
        Self(format!("{:x}", hasher.finalize()))
    }
}

/// The kernel-observed launcher context an [`Approval`] is bound to.
/// [`recall`] re-observes every one of these dimensions fresh and never
/// trusts this struct's own fields as current truth — it is the
/// baseline they are compared against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalBinding {
    pub owner_uid: u32,
    pub launcher_path: String,
    /// `None` when no executable digest was available at approval time
    /// (e.g. the launcher exceeded the collector's size cap, or
    /// hashing failed) — see `eltanin-linux`/`eltanin-macos`'s
    /// `executable_hash`. A binding with no recorded digest simply
    /// never compares this dimension at [`recall`] time, exactly like
    /// `cgroup_path: None` means "no cgroup expected."
    pub launcher_digest: Option<ExecutableDigest>,
    pub cgroup_path: Option<String>,
    pub capabilities: ResourceCapabilities,
    pub policy: PolicyProvenance,
}

/// One remembered (or denied) authorization intent. Private fields, no
/// public constructor outside [`ApprovalSet::from_document`] — see the
/// module docs' "`Serialize`-only validated type" section for why this
/// is safe despite being reconstructible from disk via that one path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Approval {
    id: ApprovalId,
    binding: ApprovalBinding,
    resource: ResourceIdentity,
    action: Action,
    disposition: ApprovalDisposition,
}

impl Approval {
    #[must_use]
    pub fn id(&self) -> &ApprovalId {
        &self.id
    }

    #[must_use]
    pub fn binding(&self) -> &ApprovalBinding {
        &self.binding
    }

    #[must_use]
    pub fn resource(&self) -> &ResourceIdentity {
        &self.resource
    }

    #[must_use]
    pub fn action(&self) -> Action {
        self.action
    }

    #[must_use]
    pub fn disposition(&self) -> ApprovalDisposition {
        self.disposition
    }

    /// Construct a fresh, unvalidated [`Approval`] directly from
    /// already-observed evidence — used by the agent's `eltanin approve`
    /// handler, which derives every [`ApprovalBinding`] field itself
    /// from the peer's own freshly-observed kernel state (mirroring
    /// exactly how `CreateSessionRequest` handling already works, per
    /// ADR 0010). This is *not* the on-disk validation path — that is
    /// [`ApprovalSet::from_document`], for bytes coming back off disk.
    #[must_use]
    pub fn new(
        binding: ApprovalBinding,
        resource: ResourceIdentity,
        action: Action,
        disposition: ApprovalDisposition,
    ) -> Self {
        let id = ApprovalId::compute(
            binding.owner_uid,
            &binding.launcher_path,
            binding.launcher_digest.as_ref(),
            binding.cgroup_path.as_deref(),
            &resource,
            action,
        );
        Self {
            id,
            binding,
            resource,
            action,
            disposition,
        }
    }
}

/// Named material-change dimensions [`recall`] can report inside
/// [`RecallVerdict::NotMatched`]. Six dimensions, matching the ADR 0010
/// table exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangedDimension {
    OwnerUid,
    LauncherPath,
    LauncherDigest,
    CgroupPath,
    ResourceCapabilityState,
    PolicyRevision,
}

/// The result of [`recall`]. A rich enum, not a `bool` — same
/// established pattern as [`crate::session::MembershipVerdict`]/
/// [`crate::identity::IdentityComparison`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "verdict")]
pub enum RecallVerdict {
    Matched {
        id: ApprovalId,
    },
    NotMatched {
        changed: BTreeSet<ChangedDimension>,
    },
    /// The evidence needed to decide at least one dimension could not be
    /// confirmed (missing/unsupported/self-asserted where the binding
    /// expected a real value). Callers must treat this identically to
    /// [`RecallVerdict::NotMatched`] — never as `Matched` — fail-closed,
    /// same discipline as
    /// [`crate::session::MembershipVerdict::Indeterminate`].
    Indeterminate {
        reason: String,
    },
}

/// Determine whether `observed`/`observed_capabilities`/`current_policy`
/// together prove `request` still matches `approval`'s remembered
/// [`ApprovalBinding`]. The **one** combined signature — see the module
/// docs for why this must never be split into a lookup step and a
/// separate check.
///
/// Every dimension where `approval.binding()` recorded an expectation is
/// re-observed fresh from `observed`/`observed_capabilities`/
/// `current_policy` and compared; anything the binding did not record
/// (`launcher_digest: None`, `cgroup_path: None`) is skipped for that
/// dimension rather than treated as a mismatch. A `resource`/`action`
/// mismatch against `approval` itself (a caller bug — candidate lookup
/// should already have filtered on these) is reported as
/// [`RecallVerdict::Indeterminate`] rather than panicking.
#[must_use]
pub fn recall(
    approval: &Approval,
    observed: &ExecutionContext,
    observed_capabilities: &ResourceCapabilities,
    current_policy: &PolicyProvenance,
    request: &ComputeRequest,
) -> RecallVerdict {
    if request.resource != approval.resource || request.action != approval.action {
        return RecallVerdict::Indeterminate {
            reason: "recall() called with a request that does not match this approval's \
                      (resource, action)"
                .to_string(),
        };
    }

    let binding = &approval.binding;
    let mut changed = BTreeSet::new();

    // 1. Owner uid.
    match &observed.workload.uid {
        Evidence::Present {
            value,
            source: EvidenceSource::SelfAsserted,
        } => {
            let _ = value;
            return indeterminate("owner uid evidence was self-asserted");
        }
        Evidence::Present { value, .. } => {
            if *value != binding.owner_uid {
                changed.insert(ChangedDimension::OwnerUid);
            }
        }
        Evidence::Missing { .. } | Evidence::Unsupported => {
            return indeterminate("owner uid evidence is unavailable");
        }
    }

    // 2. Launcher path.
    match &observed.workload.executable_path {
        Evidence::Present {
            value,
            source: EvidenceSource::SelfAsserted,
        } => {
            let _ = value;
            return indeterminate("launcher path evidence was self-asserted");
        }
        Evidence::Present { value, .. } => {
            if *value != binding.launcher_path {
                changed.insert(ChangedDimension::LauncherPath);
            }
        }
        Evidence::Missing { .. } | Evidence::Unsupported => {
            return indeterminate("launcher path evidence is unavailable");
        }
    }

    // 3. Launcher digest — only compared when the binding recorded one.
    if let Some(expected_digest) = &binding.launcher_digest {
        match &observed.workload.executable_hash {
            Evidence::Present {
                value,
                source: EvidenceSource::SelfAsserted,
            } => {
                let _ = value;
                return indeterminate("launcher digest evidence was self-asserted");
            }
            Evidence::Present { value, .. } => {
                if value != expected_digest.as_str() {
                    changed.insert(ChangedDimension::LauncherDigest);
                }
            }
            Evidence::Missing { .. } | Evidence::Unsupported => {
                return indeterminate("launcher digest evidence is unavailable");
            }
        }
    }

    // 4. Cgroup/container path.
    match (&binding.cgroup_path, &observed.cgroup_path) {
        (None, Evidence::Missing { .. } | Evidence::Unsupported) => {}
        (None, Evidence::Present { .. }) => {
            changed.insert(ChangedDimension::CgroupPath);
        }
        (
            Some(_),
            Evidence::Present {
                source: EvidenceSource::SelfAsserted,
                ..
            },
        ) => {
            return indeterminate("cgroup path evidence was self-asserted");
        }
        (Some(expected), Evidence::Present { value, .. }) => {
            if value != expected {
                changed.insert(ChangedDimension::CgroupPath);
            }
        }
        (Some(_), Evidence::Missing { .. } | Evidence::Unsupported) => {
            return indeterminate("cgroup path evidence is unavailable but was expected");
        }
    }

    // 5. Resource capability state.
    if *observed_capabilities != binding.capabilities {
        changed.insert(ChangedDimension::ResourceCapabilityState);
    }

    // 6. Security posture (policy identity/revision/schema).
    if current_policy != &binding.policy {
        changed.insert(ChangedDimension::PolicyRevision);
    }

    if changed.is_empty() {
        RecallVerdict::Matched {
            id: approval.id.clone(),
        }
    } else {
        RecallVerdict::NotMatched { changed }
    }
}

fn indeterminate(reason: &str) -> RecallVerdict {
    RecallVerdict::Indeterminate {
        reason: reason.to_string(),
    }
}

/// The on-disk row shape for one [`Approval`] — plain, `Deserialize`-safe
/// fields only, deliberately separate from the validated [`Approval`]
/// type. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalEntry {
    pub owner_uid: u32,
    pub launcher_path: String,
    pub launcher_digest: Option<String>,
    pub cgroup_path: Option<String>,
    pub capabilities: ResourceCapabilities,
    pub policy_id: String,
    pub policy_revision: u32,
    pub schema_version: u16,
    pub resource: ResourceIdentity,
    pub action: Action,
    pub disposition: ApprovalDisposition,
}

/// The on-disk document wrapping every stored [`ApprovalEntry`] for one
/// agent instance's durable approval store. Wrapped in
/// [`Versioned`] like every other on-disk domain document in this crate
/// (e.g. [`crate::policy::PolicyDocument`]).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ApprovalDocument {
    pub entries: Vec<ApprovalEntry>,
}

/// Why [`ApprovalSet::from_document`] rejected an [`ApprovalDocument`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalError {
    #[error("approval launcher_path must not be empty")]
    EmptyLauncherPath,
    #[error("approval policy_id must not be empty")]
    EmptyPolicyId,
    #[error(transparent)]
    UnsupportedVersion(#[from] UnsupportedVersion),
}

/// A validated collection of [`Approval`]s. The only way to obtain one
/// from untrusted bytes is [`ApprovalSet::from_document`]/
/// [`ApprovalSet::from_versioned`] — mirroring
/// [`crate::policy::PolicySet`]'s own document/validated-set split
/// exactly.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApprovalSet {
    approvals: Vec<Approval>,
}

impl ApprovalSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate `document` and, if valid, wrap it as a usable
    /// [`ApprovalSet`].
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::EmptyLauncherPath`] or
    /// [`ApprovalError::EmptyPolicyId`] if any entry names an empty
    /// value for either field.
    pub fn from_document(document: ApprovalDocument) -> Result<Self, ApprovalError> {
        let mut approvals = Vec::with_capacity(document.entries.len());
        for entry in document.entries {
            if entry.launcher_path.is_empty() {
                return Err(ApprovalError::EmptyLauncherPath);
            }
            if entry.policy_id.is_empty() {
                return Err(ApprovalError::EmptyPolicyId);
            }
            let binding = ApprovalBinding {
                owner_uid: entry.owner_uid,
                launcher_path: entry.launcher_path,
                launcher_digest: entry.launcher_digest.map(ExecutableDigest::new),
                cgroup_path: entry.cgroup_path,
                capabilities: entry.capabilities,
                policy: PolicyProvenance {
                    policy_id: PolicyId::new(entry.policy_id),
                    policy_revision: entry.policy_revision,
                    schema_version: entry.schema_version,
                },
            };
            approvals.push(Approval::new(
                binding,
                entry.resource,
                entry.action,
                entry.disposition,
            ));
        }
        Ok(Self { approvals })
    }

    /// Unwrap `envelope`'s schema version, then validate its payload the
    /// same way [`ApprovalSet::from_document`] does.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::UnsupportedVersion`] if the envelope's
    /// schema version is not [`crate::envelope::DOMAIN_SCHEMA_VERSION`],
    /// or any [`ApprovalSet::from_document`] error otherwise.
    pub fn from_versioned(envelope: Versioned<ApprovalDocument>) -> Result<Self, ApprovalError> {
        let document = envelope.into_current()?;
        Self::from_document(document)
    }

    /// Project this set back to its on-disk document shape, for
    /// persistence.
    #[must_use]
    pub fn to_document(&self) -> ApprovalDocument {
        ApprovalDocument {
            entries: self
                .approvals
                .iter()
                .map(|approval| ApprovalEntry {
                    owner_uid: approval.binding.owner_uid,
                    launcher_path: approval.binding.launcher_path.clone(),
                    launcher_digest: approval
                        .binding
                        .launcher_digest
                        .as_ref()
                        .map(|d| d.as_str().to_string()),
                    cgroup_path: approval.binding.cgroup_path.clone(),
                    capabilities: approval.binding.capabilities.clone(),
                    policy_id: approval.binding.policy.policy_id.as_str().to_string(),
                    policy_revision: approval.binding.policy.policy_revision,
                    schema_version: approval.binding.policy.schema_version,
                    resource: approval.resource.clone(),
                    action: approval.action,
                    disposition: approval.disposition,
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn approvals(&self) -> &[Approval] {
        &self.approvals
    }

    /// Every stored [`Approval`] naming exactly `resource`/`action` —
    /// the **only** lookup key; see the module docs for why every other
    /// dimension is compared inside [`recall`] instead. `Deny`
    /// dispositions are ordered first so a caller folding this iterator
    /// left-to-right naturally implements deny-overrides.
    pub fn candidates(
        &self,
        resource: &ResourceIdentity,
        action: Action,
    ) -> impl Iterator<Item = &Approval> {
        let mut matching: Vec<&Approval> = self
            .approvals
            .iter()
            .filter(move |a| &a.resource == resource && a.action == action)
            .collect();
        matching.sort_by_key(|a| !matches!(a.disposition, ApprovalDisposition::Deny));
        matching.into_iter()
    }

    /// Insert `approval`, replacing any existing entry with the same
    /// [`ApprovalId`] (the same launcher/context/request re-approved).
    pub fn insert(&mut self, approval: Approval) {
        self.approvals.retain(|existing| existing.id != approval.id);
        self.approvals.push(approval);
    }

    /// Remove the approval identified by `id`, if any. Returns `true` if
    /// an entry was removed.
    pub fn remove(&mut self, id: &ApprovalId) -> bool {
        let before = self.approvals.len();
        self.approvals.retain(|approval| &approval.id != id);
        self.approvals.len() != before
    }

    #[must_use]
    pub fn get(&self, id: &ApprovalId) -> Option<&Approval> {
        self.approvals.iter().find(|approval| &approval.id == id)
    }

    /// Every approval owned by `uid` — used by `eltanin approve list`
    /// (agent side), which must only ever return the calling peer's own
    /// approvals.
    pub fn owned_by(&self, uid: u32) -> impl Iterator<Item = &Approval> {
        self.approvals
            .iter()
            .filter(move |approval| approval.binding.owner_uid == uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{ProcessAncestor, ProcessStartToken, WorkloadIdentity};
    use crate::resource::{Capability, ResourceKind, ResourceVendor};

    fn present<T>(value: T) -> Evidence<T> {
        Evidence::Present {
            value,
            source: EvidenceSource::KernelObserved,
        }
    }

    fn resource() -> ResourceIdentity {
        ResourceIdentity {
            vendor: ResourceVendor::new("fake"),
            kind: ResourceKind::gpu(),
            local_id: "0".to_string(),
        }
    }

    fn capabilities() -> ResourceCapabilities {
        ResourceCapabilities::new([Capability::ControlledLaunch])
    }

    fn policy() -> PolicyProvenance {
        PolicyProvenance {
            policy_id: PolicyId::new("p1"),
            policy_revision: 1,
            schema_version: crate::envelope::DOMAIN_SCHEMA_VERSION,
        }
    }

    fn binding() -> ApprovalBinding {
        ApprovalBinding {
            owner_uid: 1000,
            launcher_path: "/usr/bin/trusted".to_string(),
            launcher_digest: Some(ExecutableDigest::new("sha256:abc")),
            cgroup_path: None,
            capabilities: capabilities(),
            policy: policy(),
        }
    }

    fn approval() -> Approval {
        Approval::new(
            binding(),
            resource(),
            Action::Compute,
            ApprovalDisposition::Remember,
        )
    }

    fn workload() -> WorkloadIdentity {
        WorkloadIdentity {
            pid: 100,
            process_start: present(ProcessStartToken(1)),
            uid: present(1000u32),
            gid: present(1000u32),
            executable_path: present("/usr/bin/trusted".to_string()),
            executable_hash: present("sha256:abc".to_string()),
            ancestry: Vec::<ProcessAncestor>::new(),
        }
    }

    fn context() -> ExecutionContext {
        ExecutionContext {
            workload: workload(),
            cgroup_path: Evidence::Unsupported,
            namespace_hint: Evidence::Unsupported,
            container_hint: Evidence::Unsupported,
            session_origin: Evidence::Unsupported,
        }
    }

    fn request() -> ComputeRequest {
        ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        }
    }

    #[test]
    fn same_id_for_same_binding_and_request() {
        let a = approval();
        let b = approval();
        assert_eq!(a.id(), b.id());
    }

    #[test]
    fn recall_matches_unchanged_context() {
        let approval = approval();
        let verdict = recall(
            &approval,
            &context(),
            &capabilities(),
            &policy(),
            &request(),
        );
        assert_eq!(
            verdict,
            RecallVerdict::Matched {
                id: approval.id().clone()
            }
        );
    }

    #[test]
    fn recall_reports_changed_owner_uid() {
        let approval = approval();
        let mut ctx = context();
        ctx.workload.uid = present(2000u32);
        let verdict = recall(&approval, &ctx, &capabilities(), &policy(), &request());
        assert_eq!(
            verdict,
            RecallVerdict::NotMatched {
                changed: BTreeSet::from([ChangedDimension::OwnerUid])
            }
        );
    }

    #[test]
    fn recall_reports_changed_launcher_digest_on_replacement() {
        let approval = approval();
        let mut ctx = context();
        ctx.workload.executable_hash = present("sha256:different".to_string());
        let verdict = recall(&approval, &ctx, &capabilities(), &policy(), &request());
        assert_eq!(
            verdict,
            RecallVerdict::NotMatched {
                changed: BTreeSet::from([ChangedDimension::LauncherDigest])
            }
        );
    }

    #[test]
    fn recall_accepts_best_effort_digest_evidence() {
        let approval = approval();
        let mut ctx = context();
        ctx.workload.executable_hash = Evidence::Present {
            value: "sha256:abc".to_string(),
            source: EvidenceSource::BestEffort,
        };
        let verdict = recall(&approval, &ctx, &capabilities(), &policy(), &request());
        assert!(matches!(verdict, RecallVerdict::Matched { .. }));
    }

    #[test]
    fn recall_rejects_self_asserted_digest_evidence() {
        let approval = approval();
        let mut ctx = context();
        ctx.workload.executable_hash = Evidence::Present {
            value: "sha256:abc".to_string(),
            source: EvidenceSource::SelfAsserted,
        };
        let verdict = recall(&approval, &ctx, &capabilities(), &policy(), &request());
        assert!(matches!(verdict, RecallVerdict::Indeterminate { .. }));
    }

    #[test]
    fn recall_missing_uid_evidence_is_indeterminate_not_not_matched() {
        let approval = approval();
        let mut ctx = context();
        ctx.workload.uid = Evidence::Missing {
            reason: "no uid".to_string(),
        };
        let verdict = recall(&approval, &ctx, &capabilities(), &policy(), &request());
        assert!(matches!(verdict, RecallVerdict::Indeterminate { .. }));
    }

    #[test]
    fn recall_reports_changed_capabilities() {
        let approval = approval();
        let other_caps = ResourceCapabilities::new([Capability::DeviceEnforce]);
        let verdict = recall(&approval, &context(), &other_caps, &policy(), &request());
        assert_eq!(
            verdict,
            RecallVerdict::NotMatched {
                changed: BTreeSet::from([ChangedDimension::ResourceCapabilityState])
            }
        );
    }

    #[test]
    fn recall_reports_changed_policy_revision() {
        let approval = approval();
        let mut other_policy = policy();
        other_policy.policy_revision = 2;
        let verdict = recall(
            &approval,
            &context(),
            &capabilities(),
            &other_policy,
            &request(),
        );
        assert_eq!(
            verdict,
            RecallVerdict::NotMatched {
                changed: BTreeSet::from([ChangedDimension::PolicyRevision])
            }
        );
    }

    #[test]
    fn recall_ignores_cgroup_when_binding_recorded_none() {
        let approval = approval();
        let mut ctx = context();
        ctx.cgroup_path = present("/sys/fs/cgroup/foo".to_string());
        let verdict = recall(&approval, &ctx, &capabilities(), &policy(), &request());
        // Binding recorded no cgroup expectation, but the observed
        // context now has one — that is itself a material change (a
        // previously bare-process launcher is now containerized).
        assert_eq!(
            verdict,
            RecallVerdict::NotMatched {
                changed: BTreeSet::from([ChangedDimension::CgroupPath])
            }
        );
    }

    #[test]
    fn recall_skips_digest_dimension_when_binding_has_none() {
        let mut binding = binding();
        binding.launcher_digest = None;
        let approval = Approval::new(
            binding,
            resource(),
            Action::Compute,
            ApprovalDisposition::Remember,
        );
        let mut ctx = context();
        ctx.workload.executable_hash = present("sha256:whatever-different".to_string());
        let verdict = recall(&approval, &ctx, &capabilities(), &policy(), &request());
        assert!(matches!(verdict, RecallVerdict::Matched { .. }));
    }

    #[test]
    fn empty_launcher_path_is_rejected_by_from_document() {
        let mut entry_binding = binding();
        entry_binding.launcher_path = String::new();
        let document = ApprovalDocument {
            entries: vec![ApprovalEntry {
                owner_uid: entry_binding.owner_uid,
                launcher_path: entry_binding.launcher_path,
                launcher_digest: entry_binding
                    .launcher_digest
                    .map(|d| d.as_str().to_string()),
                cgroup_path: entry_binding.cgroup_path,
                capabilities: entry_binding.capabilities,
                policy_id: entry_binding.policy.policy_id.as_str().to_string(),
                policy_revision: entry_binding.policy.policy_revision,
                schema_version: entry_binding.policy.schema_version,
                resource: resource(),
                action: Action::Compute,
                disposition: ApprovalDisposition::Remember,
            }],
        };
        assert_eq!(
            ApprovalSet::from_document(document),
            Err(ApprovalError::EmptyLauncherPath)
        );
    }

    #[test]
    fn document_round_trip_preserves_content() {
        let mut set = ApprovalSet::new();
        set.insert(approval());
        let document = set.to_document();
        let restored = ApprovalSet::from_document(document).unwrap();
        assert_eq!(restored.approvals().len(), 1);
        assert_eq!(restored.approvals()[0].id(), approval().id());
    }

    #[test]
    fn candidates_orders_deny_first() {
        let mut set = ApprovalSet::new();
        let mut deny_binding = binding();
        deny_binding.owner_uid = 4242;
        let deny = Approval::new(
            deny_binding,
            resource(),
            Action::Compute,
            ApprovalDisposition::Deny,
        );
        set.insert(approval());
        set.insert(deny.clone());
        let ordered: Vec<&Approval> = set.candidates(&resource(), Action::Compute).collect();
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].disposition(), ApprovalDisposition::Deny);
    }

    #[test]
    fn insert_replaces_existing_entry_with_same_id() {
        let mut set = ApprovalSet::new();
        set.insert(approval());
        let mut denied_binding = binding();
        // Same identity dimensions as `approval()`, so this produces the
        // same `ApprovalId` — re-approving from the same launcher
        // replaces the old disposition rather than creating a second
        // entry.
        denied_binding.capabilities = capabilities();
        let denied = Approval::new(
            denied_binding,
            resource(),
            Action::Compute,
            ApprovalDisposition::Deny,
        );
        set.insert(denied);
        assert_eq!(set.approvals().len(), 1);
        assert_eq!(set.approvals()[0].disposition(), ApprovalDisposition::Deny);
    }
}
