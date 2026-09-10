//! `PolicySet::evaluate` decision-semantics coverage (F-M1-004, HORO-834).

use std::collections::BTreeSet;

use eltanin_core::identity::{
    Evidence, EvidenceSource, ExecutionContext, ProcessStartToken, WorkloadIdentity,
};
use eltanin_core::policy::{
    Condition, DecisionReason, Effect, EvidenceMatch, PolicyDocument, PolicyId, PolicySet, Rule,
    RuleId, TrustFloor,
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

fn context_with_uid_source(uid: u32, source: EvidenceSource) -> ExecutionContext {
    ExecutionContext {
        workload: WorkloadIdentity {
            pid: 42,
            process_start: Evidence::Present {
                value: ProcessStartToken(100),
                source: EvidenceSource::KernelObserved,
            },
            uid: Evidence::Present { value: uid, source },
            gid: Evidence::Present { value: uid, source },
            executable_path: Evidence::Present {
                value: "/usr/bin/tool".into(),
                source: EvidenceSource::BestEffort,
            },
            executable_hash: Evidence::Missing {
                reason: "hashing not implemented".into(),
            },
            ancestry: Vec::new(),
        },
        cgroup_path: Evidence::Present {
            value: "/sys/fs/cgroup/user.slice".into(),
            source: EvidenceSource::KernelObserved,
        },
        namespace_hint: Evidence::Unsupported,
        container_hint: Evidence::Unsupported,
        session_origin: Evidence::Unsupported,
    }
}

fn uid_rule(id: &str, effect: Effect, uid: u32) -> Rule {
    Rule {
        id: RuleId::new(id),
        effect,
        resource: resource(),
        action: Action::Compute,
        conditions: vec![Condition::Uid(EvidenceMatch {
            expected: uid,
            min_trust: TrustFloor::KernelObserved,
        })],
    }
}

fn policy(rules: Vec<Rule>) -> PolicySet {
    PolicySet::from_document(PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 1,
        rules,
    })
    .expect("fixture policy must validate")
}

#[test]
fn empty_policy_denies_every_request() {
    let policy = policy(Vec::new());
    let context = context_with_uid_source(1000, EvidenceSource::KernelObserved);
    let decision = policy.evaluate(&context, &request());
    assert_eq!(decision.effect(), Effect::Deny);
    assert_eq!(decision.reason(), &DecisionReason::NoMatchingRule);
}

#[test]
fn no_matching_rule_denies() {
    let policy = policy(vec![uid_rule("r1", Effect::Allow, 2000)]);
    let context = context_with_uid_source(1000, EvidenceSource::KernelObserved);
    let decision = policy.evaluate(&context, &request());
    assert_eq!(decision.effect(), Effect::Deny);
    assert_eq!(decision.reason(), &DecisionReason::NoMatchingRule);
}

#[test]
fn single_matching_allow_rule_allows() {
    let policy = policy(vec![uid_rule("r1", Effect::Allow, 1000)]);
    let context = context_with_uid_source(1000, EvidenceSource::KernelObserved);
    let decision = policy.evaluate(&context, &request());
    assert_eq!(decision.effect(), Effect::Allow);
    assert_eq!(
        decision.reason(),
        &DecisionReason::ExplicitAllow {
            matched_rules: BTreeSet::from([RuleId::new("r1")])
        }
    );
}

#[test]
fn deny_rule_overrides_a_matching_allow_rule() {
    let policy = policy(vec![
        uid_rule("allow-r", Effect::Allow, 1000),
        uid_rule("deny-r", Effect::Deny, 1000),
    ]);
    let context = context_with_uid_source(1000, EvidenceSource::KernelObserved);
    let decision = policy.evaluate(&context, &request());
    assert_eq!(decision.effect(), Effect::Deny);
    assert_eq!(
        decision.reason(),
        &DecisionReason::ExplicitDeny {
            matched_rules: BTreeSet::from([RuleId::new("deny-r")]),
            overridden_allow_rules: BTreeSet::from([RuleId::new("allow-r")]),
        }
    );
}

#[test]
fn rule_authoring_order_does_not_change_the_decision() {
    let forward = policy(vec![
        uid_rule("allow-r", Effect::Allow, 1000),
        uid_rule("deny-r", Effect::Deny, 1000),
    ]);
    let backward = policy(vec![
        uid_rule("deny-r", Effect::Deny, 1000),
        uid_rule("allow-r", Effect::Allow, 1000),
    ]);
    let context = context_with_uid_source(1000, EvidenceSource::KernelObserved);
    assert_eq!(
        forward.evaluate(&context, &request()),
        backward.evaluate(&context, &request())
    );
}

#[test]
fn request_with_unknown_action_never_matches_any_rule() {
    let policy = policy(vec![uid_rule("r1", Effect::Allow, 1000)]);
    let context = context_with_uid_source(1000, EvidenceSource::KernelObserved);
    let mismatched_action = ComputeRequest {
        resource: resource(),
        action: Action::Unknown,
    };
    let decision = policy.evaluate(&context, &mismatched_action);
    assert_eq!(decision.effect(), Effect::Deny);
}

#[test]
fn self_asserted_only_context_cannot_produce_an_allow() {
    let policy = policy(vec![uid_rule("r1", Effect::Allow, 1000)]);
    let context = context_with_uid_source(1000, EvidenceSource::SelfAsserted);
    let decision = policy.evaluate(&context, &request());
    assert_eq!(decision.effect(), Effect::Deny);
    assert_eq!(decision.reason(), &DecisionReason::NoMatchingRule);
}

#[test]
fn best_effort_source_matches_a_best_effort_floor_condition() {
    let mut rule = uid_rule("r1", Effect::Allow, 1000);
    rule.conditions = vec![Condition::ExecutablePath(EvidenceMatch {
        expected: "/usr/bin/tool".to_string(),
        min_trust: TrustFloor::BestEffort,
    })];
    let policy = policy(vec![rule]);
    let context = context_with_uid_source(1000, EvidenceSource::KernelObserved);
    let decision = policy.evaluate(&context, &request());
    assert_eq!(decision.effect(), Effect::Allow);
}

#[test]
fn repeated_evaluation_of_the_same_inputs_is_byte_identical() {
    let policy = policy(vec![uid_rule("r1", Effect::Allow, 1000)]);
    let context = context_with_uid_source(1000, EvidenceSource::KernelObserved);
    let first = policy.evaluate(&context, &request());
    let second = policy.evaluate(&context, &request());
    assert_eq!(first, second);
    let first_json = serde_json::to_string(&first).unwrap();
    let second_json = serde_json::to_string(&second).unwrap();
    assert_eq!(first_json, second_json);
}

#[test]
fn decision_carries_policy_provenance() {
    let policy = PolicySet::from_document(PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 7,
        rules: Vec::new(),
    })
    .unwrap();
    let context = context_with_uid_source(1000, EvidenceSource::KernelObserved);
    let decision = policy.evaluate(&context, &request());
    assert_eq!(decision.policy().policy_id, PolicyId::new("p1"));
    assert_eq!(decision.policy().policy_revision, 7);
    assert_eq!(
        decision.policy().schema_version,
        eltanin_core::envelope::DOMAIN_SCHEMA_VERSION
    );
}
