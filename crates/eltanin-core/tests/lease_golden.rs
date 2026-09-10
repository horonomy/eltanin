//! `ComputeLease` serialization and "no bearer-token shortcut" coverage
//! (F-M1-005, HORO-836).

use std::time::Duration;

use eltanin_core::identity::{
    Evidence, EvidenceSource, ExecutionContext, ProcessStartToken, WorkloadIdentity,
};
use eltanin_core::lease::{IssuerInstanceId, LeaseIssuer, MonotonicTime};
use eltanin_core::policy::{
    Condition, Effect, EvidenceMatch, PolicyDocument, PolicyId, PolicySet, Rule, RuleId, TrustFloor,
};
use eltanin_core::provenance::ProvenanceRecord;
use eltanin_core::resource::{
    Action, ComputeRequest, ResourceIdentity, ResourceKind, ResourceVendor,
};

fn resource() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-0".into(),
    }
}

fn context() -> ExecutionContext {
    ExecutionContext {
        workload: WorkloadIdentity {
            pid: 42,
            process_start: Evidence::Present {
                value: ProcessStartToken(100),
                source: EvidenceSource::KernelObserved,
            },
            uid: Evidence::Present {
                value: 1000,
                source: EvidenceSource::KernelObserved,
            },
            gid: Evidence::Present {
                value: 1000,
                source: EvidenceSource::KernelObserved,
            },
            executable_path: Evidence::Present {
                value: "/usr/bin/tool".into(),
                source: EvidenceSource::KernelObserved,
            },
            executable_hash: Evidence::Missing {
                reason: "hashing not implemented".into(),
            },
            ancestry: Vec::new(),
        },
        cgroup_path: Evidence::Unsupported,
        namespace_hint: Evidence::Unsupported,
        container_hint: Evidence::Unsupported,
        session_origin: Evidence::Unsupported,
    }
}

fn allow_all_policy() -> PolicySet {
    PolicySet::from_document(PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 1,
        rules: vec![Rule {
            id: RuleId::new("allow-1000"),
            effect: Effect::Allow,
            resource: resource(),
            action: Action::Compute,
            conditions: vec![Condition::Uid(EvidenceMatch {
                expected: 1000,
                min_trust: TrustFloor::KernelObserved,
            })],
        }],
    })
    .unwrap()
}

#[test]
fn lease_serializes_to_the_expected_shape() {
    let mut issuer = LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(60));
    let policy = allow_all_policy();
    let origin = ProvenanceRecord::new(
        context(),
        ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
    );
    let lease = issuer
        .issue(
            &policy,
            origin,
            MonotonicTime::from_nanos(0),
            Duration::from_secs(30),
        )
        .unwrap();

    let json = serde_json::to_string(&lease).expect("ComputeLease must serialize");
    // Spot-check the shape rather than a full golden string (the nested
    // ExecutionContext/ComputeRequest payload is already golden-tested
    // elsewhere) — the point of this test is that serialization exists
    // and includes the fields that matter for an audit trail.
    assert!(json.contains("\"sequence\":0"));
    assert!(json.contains("\"issuer\":\"issuer-a\""));
    assert!(json.contains("\"issued_at\":0"));
    assert!(json.contains("\"expires_at\":30000000000"));
}

/// HORO-836 AC / module docs: "No reusable plaintext bearer-token
/// shortcut." `ComputeLease` must never gain a `Deserialize` impl — a
/// lexical guard, following the same pattern
/// `architecture_no_vendor_leak.rs` uses for its forbidden-term scan,
/// since a negative trait bound ("`ComputeLease` does not implement
/// `Deserialize`") is not otherwise expressible without an additional
/// compile-fail-testing dependency.
///
/// Deliberately checks *every* `#[derive(...)]` attribute stacked
/// directly above the struct, not just the nearest one — Rust allows
/// stacking multiple derive attributes on one item, all of which apply,
/// so a check that only inspected the single nearest line could be
/// defeated by splitting `Deserialize` into a second `#[derive(...)]`
/// line (found by independent review). Also guards against a
/// hand-written `impl Deserialize for ComputeLease` that bypasses derive
/// entirely.
#[test]
fn compute_lease_source_never_derives_deserialize() {
    let source = include_str!("../src/lease.rs");
    let struct_offset = source
        .find("pub struct ComputeLease")
        .expect("ComputeLease struct definition must exist in lease.rs");

    let mut derives_above = Vec::new();
    for line in source[..struct_offset].lines().rev() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[derive(") {
            derives_above.push(trimmed);
        } else if trimmed.starts_with('#') || trimmed.starts_with("//") || trimmed.is_empty() {
            // Other attributes, doc comments, or blank lines between the
            // previous item and this one — keep walking up.
        } else {
            break; // reached the previous item's code
        }
    }
    assert!(
        !derives_above.is_empty(),
        "ComputeLease must have at least one #[derive(...)] attribute above it"
    );
    for derive in &derives_above {
        assert!(
            !derive.contains("Deserialize"),
            "ComputeLease must never derive Deserialize — see lease.rs module docs \
             on 'No reusable plaintext bearer-token shortcut'. Found: {derive:?}"
        );
    }

    for forbidden in [
        "Deserialize for ComputeLease",
        "Deserialize<'de> for ComputeLease",
        "de::Deserialize for ComputeLease",
        "de::Deserialize<'de> for ComputeLease",
    ] {
        assert!(
            !source.contains(forbidden),
            "found a hand-written Deserialize impl for ComputeLease bypassing derive: {forbidden:?}"
        );
    }
}
