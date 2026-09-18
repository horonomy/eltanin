//! Operator-facing configuration file loader for the bounded compute
//! delegation gate (F-M2-003, HORO-793, ADR 0011) and the risk-based
//! step-up gate (F-M2-004, HORO-794, ADR 0012) — HORO-1278 closes the
//! gap those two Features shipped with: fully implemented and
//! Track-A-tested, but reachable only by a caller embedding
//! `eltanin-agent` as a library
//! ([`super::AuthorizationConfig::with_delegation`]/
//! [`super::AuthorizationConfig::with_step_up`]), with no way for
//! `eltanin-agentd` itself to enable either. `ELTANIN_AGENT_GATE_CONFIG`
//! names the JSON file [`load_gate_config`] reads.
//!
//! Mirrors [`super::load_policy`]'s exact `Io`/`Json` error shape and
//! its [`Versioned`] JSON envelope discipline — this loader reads a
//! `Versioned<GateConfigDocument>` the same way `load_policy` reads a
//! `Versioned<PolicyDocument>`.
//!
//! # No re-implemented validation
//!
//! Every actual validation rule (the collector-verifiable max-depth
//! bound, non-zero durations, `Action::Unknown` rejection,
//! `PathSignalCannotDeny`) is enforced by
//! [`DelegationBounds::new`]/[`StepUpPolicy::new`] themselves — this
//! module only deserializes a document and forwards its fields to those
//! constructors unchanged. A misconfigured document surfaces exactly
//! the same [`DelegationBoundsError`]/[`StepUpPolicyError`] a direct
//! library caller would see.
//!
//! # Deliberate divergences from [`super::load_policy`]
//!
//! - **`#[serde(deny_unknown_fields)]` on every DTO here** —
//!   [`eltanin_core::policy::PolicyDocument`] carries no such attribute.
//!   This loader adds it because a typo'd field name in a
//!   security-relevant gate configuration (e.g. `"max_dpeth"`) must be a
//!   loud startup error, never a silently-ignored no-op.
//! - **A missing file is a hard [`GateConfigLoadError::Io`]**, not
//!   treated as "nothing configured." This is the opposite convention
//!   from a loader that treats a missing durable store as fresh empty
//!   state — a deployment that names a gate-config file via
//!   `ELTANIN_AGENT_GATE_CONFIG` and gets the path wrong has made a
//!   configuration mistake, not opted out of the feature.
//! - **No path-safety/permission checks** — mirrors `load_policy`'s own
//!   lack of them, for consistency: the policy file is at least as
//!   security-relevant as this one and does not get one either, so
//!   giving this loader alone a check would be an inconsistent, not
//!   extra-safe, choice.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use eltanin_core::delegation::{DelegationBounds, DelegationBoundsError};
use eltanin_core::envelope::{UnsupportedVersion, Versioned};
use eltanin_core::resource::Action;
use eltanin_core::risk::{RiskSignal, SignalDisposition, StepUpPolicy, StepUpPolicyError};
use serde::{Deserialize, Serialize};

/// Raw deserialized shape of a `DelegationBounds` configuration —
/// field-for-field, [`DelegationBounds::new`]'s exact parameter list.
/// Every field is required (no `#[serde(default)]` on any of them): a
/// security-relevant choice should never silently default. Durations
/// are named `*_secs` and converted to [`Duration`] by
/// [`load_gate_config`] — there is no natural JSON duration type, and a
/// bare integer is the least ambiguous encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationBoundsDocument {
    pub max_depth: u8,
    pub max_child_ttl_secs: u64,
    pub min_remaining_secs: u64,
    pub delegable_actions: BTreeSet<Action>,
    pub transition_markers: BTreeSet<String>,
    pub require_same_session: bool,
    pub require_same_cgroup: bool,
}

/// Raw deserialized shape of a `StepUpPolicy` configuration —
/// field-for-field, [`StepUpPolicy::new`]'s exact parameter list. Every
/// field is required, mirroring [`DelegationBoundsDocument`]'s identical
/// "no security-relevant default" discipline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepUpPolicyDocument {
    pub dispositions: BTreeMap<RiskSignal, SignalDisposition>,
    pub untrusted_path_prefixes: BTreeSet<String>,
}

/// Raw deserialized payload of `ELTANIN_AGENT_GATE_CONFIG`'s JSON file,
/// wrapped in [`Versioned`] exactly like [`super::load_policy`]'s
/// `Versioned<PolicyDocument>`. `delegation`/`step_up` are independently
/// optional — a deployment may enable either one alone or both — but
/// [`load_gate_config`] refuses a document naming neither (see
/// [`GateConfigLoadError::Empty`]). The `#[serde(default)]` on these two
/// fields governs section *presence* only, not any leaf value inside
/// either section — it does not weaken the "no default on a
/// security-relevant leaf" discipline stated on
/// [`DelegationBoundsDocument`]/[`StepUpPolicyDocument`] above.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateConfigDocument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<DelegationBoundsDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up: Option<StepUpPolicyDocument>,
}

/// The validated output of [`load_gate_config`] — already-constructed
/// real domain types, ready to hand to
/// [`super::AuthorizationConfig::with_delegation`]/
/// [`super::AuthorizationConfig::with_step_up`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GateConfig {
    pub delegation: Option<DelegationBounds>,
    pub step_up: Option<StepUpPolicy>,
}

/// Why [`load_gate_config`] could not produce a [`GateConfig`].
#[derive(Debug, thiserror::Error)]
pub enum GateConfigLoadError {
    #[error("failed to read gate config file: {reason}")]
    Io { reason: String },
    #[error("failed to parse gate config file as JSON: {reason}")]
    Json { reason: String },
    #[error(transparent)]
    UnsupportedVersion(#[from] UnsupportedVersion),
    #[error("invalid delegation bounds: {0}")]
    Delegation(#[from] DelegationBoundsError),
    #[error("invalid step-up policy: {0}")]
    StepUp(#[from] StepUpPolicyError),
    /// A document naming neither `delegation` nor `step_up` is almost
    /// certainly a mistake — an operator who sets
    /// `ELTANIN_AGENT_GATE_CONFIG` at all clearly intends to configure
    /// something, so an empty document fails loudly rather than being
    /// silently treated as "nothing configured."
    #[error(
        "gate config file names neither \"delegation\" nor \"step_up\" — set at least one, or \
         leave ELTANIN_AGENT_GATE_CONFIG unset entirely"
    )]
    Empty,
}

/// Load and validate a `Versioned<GateConfigDocument>` JSON file from
/// `path`, constructing the real [`DelegationBounds`]/[`StepUpPolicy`]
/// domain values named by whichever section(s) are present.
///
/// # Errors
///
/// Returns [`GateConfigLoadError::Io`] if `path` cannot be read (this
/// includes a path that does not exist — a named-but-absent gate-config
/// file is a misconfiguration, not "nothing configured"),
/// [`GateConfigLoadError::Json`] if its contents are not a well-formed
/// `Versioned<GateConfigDocument>`,
/// [`GateConfigLoadError::UnsupportedVersion`] if the envelope's schema
/// version is not [`eltanin_core::envelope::DOMAIN_SCHEMA_VERSION`],
/// [`GateConfigLoadError::Delegation`]/[`GateConfigLoadError::StepUp`] if
/// the named section fails its own constructor's validation, or
/// [`GateConfigLoadError::Empty`] if neither section is present.
pub fn load_gate_config(path: &Path) -> Result<GateConfig, GateConfigLoadError> {
    let contents = std::fs::read_to_string(path).map_err(|e| GateConfigLoadError::Io {
        reason: e.to_string(),
    })?;
    let envelope: Versioned<GateConfigDocument> =
        serde_json::from_str(&contents).map_err(|e| GateConfigLoadError::Json {
            reason: e.to_string(),
        })?;
    let document = envelope.into_current()?;

    if document.delegation.is_none() && document.step_up.is_none() {
        return Err(GateConfigLoadError::Empty);
    }

    let delegation = document
        .delegation
        .map(|d| {
            DelegationBounds::new(
                d.max_depth,
                Duration::from_secs(d.max_child_ttl_secs),
                Duration::from_secs(d.min_remaining_secs),
                d.delegable_actions,
                d.transition_markers,
                d.require_same_session,
                d.require_same_cgroup,
            )
        })
        .transpose()?;

    let step_up = document
        .step_up
        .map(|s| StepUpPolicy::new(s.dispositions, s.untrusted_path_prefixes))
        .transpose()?;

    Ok(GateConfig {
        delegation,
        step_up,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_document() -> GateConfigDocument {
        GateConfigDocument {
            delegation: Some(DelegationBoundsDocument {
                max_depth: 4,
                max_child_ttl_secs: 300,
                min_remaining_secs: 30,
                delegable_actions: BTreeSet::from([Action::Compute]),
                transition_markers: BTreeSet::from(["python".to_string()]),
                require_same_session: true,
                require_same_cgroup: false,
            }),
            step_up: Some(StepUpPolicyDocument {
                dispositions: BTreeMap::from([
                    (RiskSignal::UnknownLauncher, SignalDisposition::StepUp),
                    (
                        RiskSignal::PrivilegeEscalationToRoot,
                        SignalDisposition::Deny,
                    ),
                ]),
                untrusted_path_prefixes: BTreeSet::from(["/tmp/".to_string()]),
            }),
        }
    }

    #[test]
    fn gate_config_document_round_trips_through_json() {
        let original = sample_document();
        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: GateConfigDocument = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, decoded);
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let json = r#"{
            "delegation": null,
            "step_up": null,
            "not_a_real_field": true
        }"#;
        let err = serde_json::from_str::<GateConfigDocument>(json).unwrap_err();
        assert!(
            err.to_string().contains("not_a_real_field"),
            "expected the unknown-field name in the error, got: {err}"
        );
    }

    #[test]
    fn unknown_signal_name_key_is_rejected() {
        let json = r#"{
            "dispositions": {"totally_made_up_signal": "deny"},
            "untrusted_path_prefixes": []
        }"#;
        let err = serde_json::from_str::<StepUpPolicyDocument>(json).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("unknown variant")
                || err.to_string().contains("totally_made_up_signal"),
            "expected an unknown-variant error, got: {err}"
        );
    }

    #[test]
    fn load_gate_config_rejects_missing_file() {
        let missing = Path::new("/nonexistent/does/not/exist/gate-config.json");
        let err = load_gate_config(missing).expect_err("missing file must be a hard error");
        assert!(matches!(err, GateConfigLoadError::Io { .. }));
    }

    #[test]
    fn load_gate_config_rejects_empty_document() {
        let dir = std::env::temp_dir().join(format!(
            "eltanin-gate-config-empty-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("gate-config.json");
        std::fs::write(
            &path,
            r#"{"version": 6, "payload": {"delegation": null, "step_up": null}}"#,
        )
        .expect("write fixture");
        let err = load_gate_config(&path).expect_err("empty document must be rejected");
        assert!(matches!(err, GateConfigLoadError::Empty));
    }

    #[test]
    fn load_gate_config_forwards_path_signal_cannot_deny() {
        let dir = std::env::temp_dir().join(format!(
            "eltanin-gate-config-pathdeny-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("gate-config.json");
        let document = GateConfigDocument {
            delegation: None,
            step_up: Some(StepUpPolicyDocument {
                dispositions: BTreeMap::from([(
                    RiskSignal::UntrustedExecutionPath,
                    SignalDisposition::Deny,
                )]),
                untrusted_path_prefixes: BTreeSet::new(),
            }),
        };
        std::fs::write(
            &path,
            serde_json::to_string(&Versioned::current(document)).expect("serialize envelope"),
        )
        .expect("write fixture");
        let err = load_gate_config(&path).expect_err("PathSignalCannotDeny must not be bypassable");
        assert!(matches!(err, GateConfigLoadError::StepUp(_)));
    }
}
