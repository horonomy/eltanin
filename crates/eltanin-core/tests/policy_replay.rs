//! Policy replay and malformed-policy regression coverage (F-M1-004,
//! HORO-835). Complements HORO-834's own test suites — this file adds
//! the remaining "replay a serialized document" and "reject malformed
//! wire content" scenarios HORO-835's AC calls for.

use eltanin_core::envelope::Versioned;
use eltanin_core::identity::{
    Evidence, EvidenceSource, ExecutionContext, ProcessStartToken, WorkloadIdentity,
};
use eltanin_core::policy::{
    Condition, Effect, EvidenceMatch, PolicyDocument, PolicyId, PolicySet, Rule, RuleId, TrustFloor,
};
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

fn request() -> ComputeRequest {
    ComputeRequest {
        resource: resource(),
        action: Action::Compute,
    }
}

fn context(uid: u32) -> ExecutionContext {
    ExecutionContext {
        workload: WorkloadIdentity {
            pid: 42,
            process_start: Evidence::Present {
                value: ProcessStartToken(100),
                source: EvidenceSource::KernelObserved,
            },
            uid: Evidence::Present {
                value: uid,
                source: EvidenceSource::KernelObserved,
            },
            gid: Evidence::Present {
                value: uid,
                source: EvidenceSource::KernelObserved,
            },
            executable_path: Evidence::Present {
                value: "/usr/bin/tool".into(),
                source: EvidenceSource::BestEffort,
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

fn sample_document() -> PolicyDocument {
    PolicyDocument {
        id: PolicyId::new("replay-fixture"),
        revision: 3,
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
    }
}

#[test]
fn a_policy_document_serialized_then_deserialized_produces_the_same_decision() {
    // "Replayable" (HORO-834 AC) means: take a policy off the wire,
    // evaluate it, and get the same decision the original in-memory
    // document would have produced — not just that PolicyDecision
    // itself round-trips.
    let original = PolicySet::from_document(sample_document()).unwrap();
    let original_decision = original.evaluate(&context(1000), &request());

    let wire = serde_json::to_string(&Versioned::current(sample_document())).unwrap();
    let replayed_envelope: Versioned<PolicyDocument> = serde_json::from_str(&wire).unwrap();
    let replayed = PolicySet::from_versioned(replayed_envelope).unwrap();
    let replayed_decision = replayed.evaluate(&context(1000), &request());

    assert_eq!(original_decision, replayed_decision);
}

#[test]
fn replaying_the_same_document_against_a_different_context_still_denies_correctly() {
    let policy = PolicySet::from_document(sample_document()).unwrap();
    let wire = serde_json::to_string(&Versioned::current(sample_document())).unwrap();
    let replayed_envelope: Versioned<PolicyDocument> = serde_json::from_str(&wire).unwrap();
    let replayed = PolicySet::from_versioned(replayed_envelope).unwrap();

    let non_matching_context = context(2000);
    assert_eq!(
        policy.evaluate(&non_matching_context, &request()),
        replayed.evaluate(&non_matching_context, &request())
    );
    assert_eq!(
        replayed
            .evaluate(&non_matching_context, &request())
            .effect(),
        Effect::Deny
    );
}

#[test]
fn malformed_condition_with_unknown_field_tag_fails_to_deserialize() {
    // Condition is internally tagged on "field"; an unrecognized tag
    // value must be a hard deserialization error, never silently
    // ignored or defaulted to some permissive condition.
    let malformed = r#"{"field":"not_a_real_field","expected":1000,"min_trust":"kernel_observed"}"#;
    let result: Result<Condition, _> = serde_json::from_str(malformed);
    assert!(result.is_err());
}

#[test]
fn malformed_policy_document_missing_required_field_fails_to_deserialize() {
    // Missing `revision` must be a hard error, not defaulted to 0 (which
    // would let a malformed document silently masquerade as revision 0
    // of some legitimate policy).
    let malformed = r#"{"id":"p1","rules":[]}"#;
    let result: Result<PolicyDocument, _> = serde_json::from_str(malformed);
    assert!(result.is_err());
}

#[test]
fn malformed_effect_value_fails_to_deserialize_rather_than_defaulting_to_deny() {
    let malformed = r#"{
        "id":"r1",
        "effect":"maybe",
        "resource":{"vendor":"fake","kind":"gpu","local_id":"gpu-0"},
        "action":"compute",
        "conditions":[{"field":"uid","expected":1000,"min_trust":"kernel_observed"}]
    }"#;
    let result: Result<Rule, _> = serde_json::from_str(malformed);
    assert!(result.is_err());
}

#[test]
fn document_with_unsupported_schema_version_is_never_evaluable_even_with_valid_rules() {
    let envelope = Versioned {
        version: eltanin_core::envelope::DOMAIN_SCHEMA_VERSION + 1,
        payload: sample_document(),
    };
    let wire = serde_json::to_string(&envelope).unwrap();
    let decoded: Versioned<PolicyDocument> = serde_json::from_str(&wire).unwrap();
    let result = PolicySet::from_versioned(decoded);
    assert!(result.is_err());
}

/// HORO-835 AC: "User examples are validated against the same fixtures
/// where practical." Loads the committed fixture
/// (`fixtures/example_policy.json`) — the same JSON published verbatim
/// in `docs/product/POLICY_EXAMPLES.md` — and validates it end to end:
/// it deserializes, validates, and produces the documented ALLOW/DENY
/// outcomes for the two scenarios the doc describes.
#[test]
fn example_policy_from_the_docs_matches_the_committed_fixture() {
    let wire = include_str!("fixtures/example_policy.json");
    let envelope: Versioned<PolicyDocument> =
        serde_json::from_str(wire).expect("docs example must be valid JSON matching the schema");
    let policy = PolicySet::from_document(envelope.payload.clone())
        .expect("docs example must be a valid policy");

    let example_resource = ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-0".into(),
    };
    let example_request = ComputeRequest {
        resource: example_resource,
        action: Action::Compute,
    };

    // Alice (uid 1000) running the trusted tool, both KernelObserved:
    // ALLOW, per the doc.
    let mut alice_context = context(1000);
    alice_context.workload.executable_path = Evidence::Present {
        value: "/usr/bin/trusted-tool".to_string(),
        source: EvidenceSource::KernelObserved,
    };
    assert_eq!(
        policy.evaluate(&alice_context, &example_request).effect(),
        Effect::Allow
    );

    // root (uid 0): DENY, per the doc, regardless of executable path.
    let mut root_context = context(0);
    root_context.workload.executable_path = Evidence::Present {
        value: "/usr/bin/trusted-tool".to_string(),
        source: EvidenceSource::KernelObserved,
    };
    assert_eq!(
        policy.evaluate(&root_context, &example_request).effect(),
        Effect::Deny
    );

    // An unrelated uid running an unrelated tool: DENY (default deny).
    let stranger_context = {
        let mut ctx = context(9999);
        ctx.workload.executable_path = Evidence::Present {
            value: "/usr/bin/other".to_string(),
            source: EvidenceSource::KernelObserved,
        };
        ctx
    };
    assert_eq!(
        policy
            .evaluate(&stranger_context, &example_request)
            .effect(),
        Effect::Deny
    );
}
