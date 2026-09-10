//! Authorization policy decision (F-M1-004, HORO-834).
//!
//! A [`PolicySet`] is built by validating a [`PolicyDocument`] — an
//! invalid document never becomes a [`PolicySet`] at all, so it cannot
//! deny or allow anything. [`PolicySet::evaluate`] is a pure function of
//! `(&PolicySet, &ExecutionContext, &ComputeRequest)`: it takes no
//! caller-supplied identity/override parameter, so "caller-supplied
//! identity fields must not override observed context" (North Star
//! invariant, HORO-787) is not expressible, not merely disallowed.
//!
//! # Default deny is structural
//!
//! [`Effect::Allow`] is reachable from [`PolicySet::evaluate`] only via
//! [`DecisionReason::ExplicitAllow`], which requires a non-empty set of
//! matching allow rules. There is no default-effect parameter, no
//! `Default` impl for [`PolicyDecision`], and no public constructor for
//! it outside `evaluate` — an empty policy (zero rules) is a valid
//! [`PolicySet`] and denies every request, which is the load-bearing
//! "absence is not permissive" case.
//!
//! # Deny-overrides, order-independent
//!
//! Every rule is always evaluated; there is no first-match short
//! circuit. If any deny rule matches, the decision is `Deny` regardless
//! of how many allow rules also matched. This makes the decision a pure
//! function of the matched *set*, not of authoring order — replaying the
//! same policy and request always produces byte-identical explanations.
//!
//! # Evidence trust floor
//!
//! A [`Condition`] matches only [`Evidence::Present`] whose `source`
//! clears the condition's [`TrustFloor`]. [`EvidenceSource::SelfAsserted`]
//! never clears any floor — a rule that trusts a workload's own claim
//! about itself is unrepresentable, not merely rejected at runtime (see
//! [`TrustFloor::admits`]). `Evidence::Missing`/`Evidence::Unsupported`
//! never match; there is deliberately no "field is missing" matcher —
//! default-deny already covers absence, and an allow-on-missing matcher
//! would be a pure footgun ("allow when we couldn't see who you are").
//!
//! Deliberately unmatchable fields: `pid` (a raw PID is the canonical
//! contextual-signal-as-authority mistake), `ancestry` (HORO-787: parent
//! process alone cannot imply ALLOW — excluding it structurally means
//! this can't be written), and `namespace_hint`/`container_hint`/
//! `session_origin` (never populated by any collector today).
//!
//! # Scope
//!
//! No general-purpose DSL: conditions are AND-only (no OR/NOT/grouping),
//! matching is exact-equality only (no wildcards/globs/regex/prefix),
//! and there is no rule priority/weight or time/quota/rate condition.
//! Lease issuance (F-M1-005), audit emission (F-M1-009), and loading a
//! policy from disk are all out of scope here — this module only
//! computes a [`PolicyDecision`] in memory.
//!
//! # Known limitation: replay is only partially guaranteed
//!
//! [`PolicyProvenance`] names a policy by `policy_id` + `revision`, but
//! nothing enforces that a given `(id, revision)` pair's content is
//! immutable — an author could edit a policy without bumping `revision`,
//! and a later replay would then evaluate different rules under the same
//! provenance. Closing this needs a content digest (a new hashing
//! dependency), out of scope for this ticket. Carried forward honestly
//! rather than overclaimed, following the same pattern as the
//! ancestry-truncation gap documented for `eltanin-linux` (HORO-832).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::envelope::{UnsupportedVersion, Versioned, DOMAIN_SCHEMA_VERSION};
use crate::identity::{Evidence, EvidenceSource, ExecutionContext};
use crate::resource::{Action, ComputeRequest, ResourceIdentity};

/// Identity of one [`PolicyDocument`], opaque like
/// [`crate::resource::ResourceVendor`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyId(String);

impl PolicyId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Identity of one [`Rule`] within a [`PolicyDocument`], unique within
/// that document (enforced by [`PolicySet::from_document`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuleId(String);

impl RuleId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a matching [`Rule`] does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

/// The minimum trust a piece of [`Evidence`] must carry for a
/// [`Condition`] to match it. Deliberately two variants only —
/// [`EvidenceSource::SelfAsserted`] is not representable as a floor at
/// all, so a rule that would trust a workload's own claim about itself
/// cannot be authored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustFloor {
    KernelObserved,
    BestEffort,
}

impl TrustFloor {
    /// Whether evidence observed via `source` clears this floor.
    /// `SelfAsserted` never clears any floor.
    #[must_use]
    pub fn admits(self, source: EvidenceSource) -> bool {
        match (self, source) {
            (TrustFloor::KernelObserved, EvidenceSource::KernelObserved)
            | (
                TrustFloor::BestEffort,
                EvidenceSource::KernelObserved | EvidenceSource::BestEffort,
            ) => true,
            (_, EvidenceSource::SelfAsserted)
            | (TrustFloor::KernelObserved, EvidenceSource::BestEffort) => false,
        }
    }
}

/// One evidence-backed equality check: `expected` must equal the
/// observed value, and the observed [`EvidenceSource`] must clear
/// `min_trust`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceMatch<T> {
    pub expected: T,
    pub min_trust: TrustFloor,
}

impl<T: PartialEq> EvidenceMatch<T> {
    /// Whether `evidence` satisfies this match: `Present` with an equal
    /// value and a source that clears `min_trust`. `Missing` and
    /// `Unsupported` never match.
    #[must_use]
    pub fn matches(&self, evidence: &Evidence<T>) -> bool {
        matches!(
            evidence,
            Evidence::Present { value, source }
                if *value == self.expected && self.min_trust.admits(*source)
        )
    }
}

/// A single evidence-backed condition a [`Rule`] requires. Only
/// [`ExecutionContext`]/`WorkloadIdentity` fields that carry real
/// evidence are representable — see the module docs for what is
/// deliberately excluded and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "field")]
pub enum Condition {
    Uid(EvidenceMatch<u32>),
    Gid(EvidenceMatch<u32>),
    ExecutablePath(EvidenceMatch<String>),
    ExecutableHash(EvidenceMatch<String>),
    CgroupPath(EvidenceMatch<String>),
}

/// Which [`Condition`] variant a value carries, for validation's
/// duplicate-condition-kind check. Not part of the wire schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ConditionKind {
    Uid,
    Gid,
    ExecutablePath,
    ExecutableHash,
    CgroupPath,
}

impl Condition {
    const fn kind(&self) -> ConditionKind {
        match self {
            Condition::Uid(_) => ConditionKind::Uid,
            Condition::Gid(_) => ConditionKind::Gid,
            Condition::ExecutablePath(_) => ConditionKind::ExecutablePath,
            Condition::ExecutableHash(_) => ConditionKind::ExecutableHash,
            Condition::CgroupPath(_) => ConditionKind::CgroupPath,
        }
    }

    /// Whether `context` satisfies this condition.
    fn matches(&self, context: &ExecutionContext) -> bool {
        match self {
            Condition::Uid(m) => m.matches(&context.workload.uid),
            Condition::Gid(m) => m.matches(&context.workload.gid),
            Condition::ExecutablePath(m) => m.matches(&context.workload.executable_path),
            Condition::ExecutableHash(m) => m.matches(&context.workload.executable_hash),
            Condition::CgroupPath(m) => m.matches(&context.cgroup_path),
        }
    }
}

/// One authored rule: on an exact `resource`/`action` match, if every
/// condition in `conditions` also matches, this rule contributes
/// `effect` to the decision. `conditions` must be non-empty and contain
/// at most one condition per field (validated by
/// [`PolicySet::from_document`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    pub effect: Effect,
    pub resource: ResourceIdentity,
    pub action: Action,
    pub conditions: Vec<Condition>,
}

impl Rule {
    /// Whether this rule matches `request` observed under `context`.
    fn matches(&self, context: &ExecutionContext, request: &ComputeRequest) -> bool {
        self.resource == request.resource
            && self.action == request.action
            && self.conditions.iter().all(|c| c.matches(context))
    }
}

/// The authored, not-yet-validated policy document. Deserializable, but
/// never directly evaluable — only [`PolicySet::from_document`] (or
/// [`PolicySet::from_versioned`]) can turn one into something
/// [`PolicySet::evaluate`] can use, and that conversion can fail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub id: PolicyId,
    /// Author-declared content revision — distinct from the schema
    /// version carried by [`Versioned<T>`]. See the module docs' "Known
    /// limitation" section for what this does and does not guarantee.
    pub revision: u32,
    pub rules: Vec<Rule>,
}

/// Why [`PolicySet::from_document`] rejected a [`PolicyDocument`]. There
/// is no "validate and continue anyway" path: any of these makes the
/// document unusable as a policy, full stop.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("policy id must not be empty")]
    EmptyPolicyId,
    #[error("rule id must not be empty")]
    EmptyRuleId,
    #[error("duplicate rule id: {rule:?}")]
    DuplicateRuleId { rule: RuleId },
    #[error("rule {rule:?} has no conditions")]
    RuleWithoutConditions { rule: RuleId },
    #[error("rule {rule:?} has more than one condition on the same field")]
    DuplicateConditionKind { rule: RuleId },
    #[error("rule {rule:?} names an unrecognized action")]
    UnknownActionInRule { rule: RuleId },
    #[error(transparent)]
    UnsupportedVersion(#[from] UnsupportedVersion),
}

/// Provenance of one [`PolicyDecision`]: which policy, which revision of
/// it, and under which domain schema version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyProvenance {
    pub policy_id: PolicyId,
    pub policy_revision: u32,
    pub schema_version: u16,
}

/// Why a [`PolicyDecision`] came out the way it did. `matched_rules` and
/// `overridden_allow_rules` are [`BTreeSet`]s so the explanation is
/// canonical regardless of the authoring order of rules in the document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum DecisionReason {
    NoMatchingRule,
    ExplicitAllow {
        matched_rules: BTreeSet<RuleId>,
    },
    ExplicitDeny {
        matched_rules: BTreeSet<RuleId>,
        overridden_allow_rules: BTreeSet<RuleId>,
    },
}

/// The outcome of evaluating a [`PolicySet`] against one request. Fields
/// are private and there is no public constructor outside
/// [`PolicySet::evaluate`] — `effect` can never be set to
/// [`Effect::Allow`] except via [`DecisionReason::ExplicitAllow`], which
/// itself requires a non-empty matched-allow set. Serializable (for
/// audit consumers to record), deliberately not `Deserialize` — nothing
/// should reconstruct an authority-bearing decision from bytes by
/// default; a future audit-side record type can own that if needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyDecision {
    effect: Effect,
    reason: DecisionReason,
    policy: PolicyProvenance,
}

impl PolicyDecision {
    #[must_use]
    pub fn effect(&self) -> Effect {
        self.effect
    }

    #[must_use]
    pub fn reason(&self) -> &DecisionReason {
        &self.reason
    }

    #[must_use]
    pub fn policy(&self) -> &PolicyProvenance {
        &self.policy
    }
}

/// A validated, evaluable policy. The only way to obtain one is through
/// [`PolicySet::from_document`]/[`PolicySet::from_versioned`] — both can
/// fail, and a failed validation never produces a `PolicySet`, so an
/// invalid or malformed document can never deny or allow anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySet {
    document: PolicyDocument,
}

impl PolicySet {
    /// Validate `document` and, if valid, wrap it as an evaluable
    /// [`PolicySet`].
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] if `document.id` is empty, any rule id is
    /// empty or duplicated, any rule has zero conditions, any rule has
    /// more than one condition on the same field, or any rule names
    /// [`Action::Unknown`].
    pub fn from_document(document: PolicyDocument) -> Result<Self, PolicyError> {
        if document.id.as_str().is_empty() {
            return Err(PolicyError::EmptyPolicyId);
        }
        let mut seen_rule_ids = BTreeSet::new();
        for rule in &document.rules {
            if rule.id.as_str().is_empty() {
                return Err(PolicyError::EmptyRuleId);
            }
            if !seen_rule_ids.insert(rule.id.clone()) {
                return Err(PolicyError::DuplicateRuleId {
                    rule: rule.id.clone(),
                });
            }
            if rule.conditions.is_empty() {
                return Err(PolicyError::RuleWithoutConditions {
                    rule: rule.id.clone(),
                });
            }
            let mut seen_kinds = BTreeSet::new();
            for condition in &rule.conditions {
                if !seen_kinds.insert(condition.kind()) {
                    return Err(PolicyError::DuplicateConditionKind {
                        rule: rule.id.clone(),
                    });
                }
            }
            if matches!(rule.action, Action::Unknown) {
                return Err(PolicyError::UnknownActionInRule {
                    rule: rule.id.clone(),
                });
            }
        }
        Ok(Self { document })
    }

    /// Unwrap `envelope`'s schema version, then validate its payload the
    /// same way [`PolicySet::from_document`] does.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::UnsupportedVersion`] if the envelope's
    /// schema version is not [`DOMAIN_SCHEMA_VERSION`], or any
    /// [`PolicySet::from_document`] error otherwise.
    pub fn from_versioned(envelope: Versioned<PolicyDocument>) -> Result<Self, PolicyError> {
        let document = envelope.into_current()?;
        Self::from_document(document)
    }

    #[must_use]
    pub fn provenance(&self) -> PolicyProvenance {
        PolicyProvenance {
            policy_id: self.document.id.clone(),
            policy_revision: self.document.revision,
            schema_version: DOMAIN_SCHEMA_VERSION,
        }
    }

    /// Evaluate this policy against an observed `context` and `request`.
    ///
    /// Every rule is always evaluated (no first-match short circuit).
    /// Deny-overrides: if any deny rule matches, the decision is
    /// [`Effect::Deny`] regardless of how many allow rules also matched.
    /// [`Effect::Allow`] requires a non-empty matched-allow set and zero
    /// matched deny rules. No match at all denies.
    ///
    /// This function takes no caller-supplied identity/override
    /// parameter — only what is actually observed in `context` can
    /// affect the outcome.
    #[must_use]
    pub fn evaluate(&self, context: &ExecutionContext, request: &ComputeRequest) -> PolicyDecision {
        let mut allow_hits = BTreeSet::new();
        let mut deny_hits = BTreeSet::new();
        for rule in &self.document.rules {
            if rule.matches(context, request) {
                match rule.effect {
                    Effect::Allow => {
                        allow_hits.insert(rule.id.clone());
                    }
                    Effect::Deny => {
                        deny_hits.insert(rule.id.clone());
                    }
                }
            }
        }

        let (effect, reason) = if !deny_hits.is_empty() {
            (
                Effect::Deny,
                DecisionReason::ExplicitDeny {
                    matched_rules: deny_hits,
                    overridden_allow_rules: allow_hits,
                },
            )
        } else if !allow_hits.is_empty() {
            (
                Effect::Allow,
                DecisionReason::ExplicitAllow {
                    matched_rules: allow_hits,
                },
            )
        } else {
            (Effect::Deny, DecisionReason::NoMatchingRule)
        };

        PolicyDecision {
            effect,
            reason,
            policy: self.provenance(),
        }
    }
}
