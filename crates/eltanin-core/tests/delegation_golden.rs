//! `DelegationGrant` serialization coverage (F-M2-003, HORO-793).
//! Mirrors `lease_golden.rs`'s shape-spot-check style.

use std::time::Duration;

use eltanin_core::delegation::{DelegationBounds, DelegationGrant};
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

fn holder() -> WorkloadIdentity {
    WorkloadIdentity {
        pid: 100,
        process_start: Evidence::Present {
            value: ProcessStartToken(10),
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
            value: "/usr/bin/eltanin-run".into(),
            source: EvidenceSource::KernelObserved,
        },
        executable_hash: Evidence::Missing {
            reason: "hashing not implemented".into(),
        },
        ancestry: Vec::new(),
    }
}

fn context() -> ExecutionContext {
    ExecutionContext {
        workload: holder(),
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
fn delegation_grant_serializes_to_the_expected_shape() {
    let mut issuer = LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(300));
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
            Duration::from_secs(60),
        )
        .unwrap();
    let bounds = DelegationBounds::new(
        4,
        Duration::from_secs(300),
        Duration::from_secs(1),
        [Action::Compute],
        std::collections::BTreeSet::new(),
        false,
        false,
    )
    .unwrap();

    let grant = DelegationGrant::mint(&lease, &bounds, holder(), 1000, None, None, 0, None)
        .expect("Action::Compute is delegable under these bounds");

    let json = serde_json::to_string(&grant).expect("DelegationGrant must serialize");
    assert!(json.contains("\"owner_uid\":1000"));
    assert!(json.contains("\"depth\":0"));
    assert!(json.contains("\"not_after\":60000000000"));
    assert!(json.contains("\"sequence\":0"));
    assert!(json.contains("\"issuer\":\"issuer-a\""));
    // Scope carries exactly the parent lease's own resource/action, never
    // an independently invented value.
    assert!(json.contains("\"local_id\":\"gpu-0\""));
    assert!(json.contains("\"actions\":[\"compute\"]"));
}

/// HORO-793's own "ephemeral, in-memory only" contract: `DelegationGrant`
/// must never gain a `Deserialize` impl. Same lexical-guard technique
/// `lease_golden.rs::compute_lease_source_never_derives_deserialize` uses
/// for `ComputeLease`.
#[test]
fn delegation_grant_source_never_derives_deserialize() {
    let source = include_str!("../src/delegation.rs");
    let struct_offset = source
        .find("pub struct DelegationGrant")
        .expect("DelegationGrant struct definition must exist in delegation.rs");
    let preceding = &source[..struct_offset];
    let mut derive_lines = Vec::new();
    for line in preceding.lines().rev() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[derive(") {
            derive_lines.push(trimmed);
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("///") {
            continue;
        }
        break;
    }
    assert!(
        !derive_lines.is_empty(),
        "expected at least one #[derive(...)] directly above DelegationGrant"
    );
    for line in derive_lines {
        assert!(
            !line.contains("Deserialize"),
            "DelegationGrant must never derive Deserialize: {line}"
        );
    }
    assert!(
        !source.contains("impl Deserialize for DelegationGrant")
            && !source.contains("impl<'de> Deserialize<'de> for DelegationGrant"),
        "DelegationGrant must never hand-implement Deserialize"
    );
}
