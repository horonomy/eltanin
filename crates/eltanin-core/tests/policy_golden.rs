//! Golden JSON coverage for `PolicyDecision`'s wire shape (F-M1-004,
//! HORO-834). `PolicyDecision` is `Serialize`-only (see its module
//! docs), so a round-trip test cannot pin its shape — only an explicit
//! golden string can. This is what actually satisfies "`DecisionReason`
//! is stable" (HORO-834 AC).

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
            executable_path: Evidence::Missing {
                reason: "not needed for this fixture".into(),
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

#[test]
fn no_matching_rule_decision_golden_json() {
    let policy = PolicySet::from_document(PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 1,
        rules: Vec::new(),
    })
    .unwrap();
    let decision = policy.evaluate(
        &context(1000),
        &ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
    );
    let json = serde_json::to_string_pretty(&decision).unwrap();
    let expected = r#"{
  "effect": "deny",
  "reason": {
    "reason": "no_matching_rule"
  },
  "policy": {
    "policy_id": "p1",
    "policy_revision": 1,
    "schema_version": 2
  }
}"#;
    assert_eq!(json, expected);
}

#[test]
fn explicit_allow_decision_golden_json() {
    let policy = PolicySet::from_document(PolicyDocument {
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
    .unwrap();
    let decision = policy.evaluate(
        &context(1000),
        &ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
    );
    let json = serde_json::to_string_pretty(&decision).unwrap();
    let expected = r#"{
  "effect": "allow",
  "reason": {
    "reason": "explicit_allow",
    "matched_rules": [
      "allow-1000"
    ]
  },
  "policy": {
    "policy_id": "p1",
    "policy_revision": 1,
    "schema_version": 2
  }
}"#;
    assert_eq!(json, expected);
}

#[test]
fn explicit_deny_overriding_allow_decision_golden_json() {
    let policy = PolicySet::from_document(PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 1,
        rules: vec![
            Rule {
                id: RuleId::new("allow-1000"),
                effect: Effect::Allow,
                resource: resource(),
                action: Action::Compute,
                conditions: vec![Condition::Uid(EvidenceMatch {
                    expected: 1000,
                    min_trust: TrustFloor::KernelObserved,
                })],
            },
            Rule {
                id: RuleId::new("deny-1000"),
                effect: Effect::Deny,
                resource: resource(),
                action: Action::Compute,
                conditions: vec![Condition::Gid(EvidenceMatch {
                    expected: 1000,
                    min_trust: TrustFloor::KernelObserved,
                })],
            },
        ],
    })
    .unwrap();
    let decision = policy.evaluate(
        &context(1000),
        &ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
    );
    let json = serde_json::to_string_pretty(&decision).unwrap();
    let expected = r#"{
  "effect": "deny",
  "reason": {
    "reason": "explicit_deny",
    "matched_rules": [
      "deny-1000"
    ],
    "overridden_allow_rules": [
      "allow-1000"
    ]
  },
  "policy": {
    "policy_id": "p1",
    "policy_revision": 1,
    "schema_version": 2
  }
}"#;
    assert_eq!(json, expected);
}

#[test]
fn indeterminate_evidence_decision_golden_json() {
    let policy = PolicySet::from_document(PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 1,
        rules: vec![Rule {
            id: RuleId::new("deny-root"),
            effect: Effect::Deny,
            resource: resource(),
            action: Action::Compute,
            conditions: vec![Condition::Uid(EvidenceMatch {
                expected: 0,
                min_trust: TrustFloor::KernelObserved,
            })],
        }],
    })
    .unwrap();
    let mut ctx = context(1000);
    ctx.workload.uid = Evidence::Missing {
        reason: "permission denied".into(),
    };
    let decision = policy.evaluate(
        &ctx,
        &ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
    );
    let json = serde_json::to_string_pretty(&decision).unwrap();
    let expected = r#"{
  "effect": "deny",
  "reason": {
    "reason": "indeterminate_evidence",
    "rules": [
      "deny-root"
    ]
  },
  "policy": {
    "policy_id": "p1",
    "policy_revision": 1,
    "schema_version": 2
  }
}"#;
    assert_eq!(json, expected);
}
