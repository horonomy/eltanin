//! `PolicySet::from_document` validation coverage (F-M1-004, HORO-834).

use eltanin_core::policy::{
    Condition, EvidenceMatch, PolicyDocument, PolicyError, PolicyId, PolicySet, Rule, RuleId,
    TrustFloor,
};
use eltanin_core::resource::{Action, ResourceIdentity, ResourceKind, ResourceVendor};

fn sample_resource() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-0".into(),
    }
}

fn uid_condition(uid: u32) -> Condition {
    Condition::Uid(EvidenceMatch {
        expected: uid,
        min_trust: TrustFloor::KernelObserved,
    })
}

fn sample_rule(id: &str) -> Rule {
    Rule {
        id: RuleId::new(id),
        effect: eltanin_core::policy::Effect::Allow,
        resource: sample_resource(),
        action: Action::Compute,
        conditions: vec![uid_condition(1000)],
    }
}

#[test]
fn empty_policy_document_with_no_rules_is_valid() {
    // The load-bearing "absence is not permissive" case: zero rules is
    // not an error, it is a valid policy that denies everything.
    let document = PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 1,
        rules: Vec::new(),
    };
    assert!(PolicySet::from_document(document).is_ok());
}

#[test]
fn empty_policy_id_is_rejected() {
    let document = PolicyDocument {
        id: PolicyId::new(""),
        revision: 1,
        rules: Vec::new(),
    };
    assert_eq!(
        PolicySet::from_document(document),
        Err(PolicyError::EmptyPolicyId)
    );
}

#[test]
fn empty_rule_id_is_rejected() {
    let mut rule = sample_rule("");
    rule.id = RuleId::new("");
    let document = PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 1,
        rules: vec![rule],
    };
    assert_eq!(
        PolicySet::from_document(document),
        Err(PolicyError::EmptyRuleId)
    );
}

#[test]
fn duplicate_rule_id_is_rejected() {
    let document = PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 1,
        rules: vec![sample_rule("r1"), sample_rule("r1")],
    };
    assert_eq!(
        PolicySet::from_document(document),
        Err(PolicyError::DuplicateRuleId {
            rule: RuleId::new("r1")
        })
    );
}

#[test]
fn rule_without_conditions_is_rejected() {
    let mut rule = sample_rule("r1");
    rule.conditions = Vec::new();
    let document = PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 1,
        rules: vec![rule],
    };
    assert_eq!(
        PolicySet::from_document(document),
        Err(PolicyError::RuleWithoutConditions {
            rule: RuleId::new("r1")
        })
    );
}

#[test]
fn rule_with_duplicate_condition_kind_is_rejected() {
    let mut rule = sample_rule("r1");
    rule.conditions = vec![uid_condition(1000), uid_condition(1001)];
    let document = PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 1,
        rules: vec![rule],
    };
    assert_eq!(
        PolicySet::from_document(document),
        Err(PolicyError::DuplicateConditionKind {
            rule: RuleId::new("r1")
        })
    );
}

#[test]
fn rule_naming_unknown_action_is_rejected() {
    let mut rule = sample_rule("r1");
    rule.action = Action::Unknown;
    let document = PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 1,
        rules: vec![rule],
    };
    assert_eq!(
        PolicySet::from_document(document),
        Err(PolicyError::UnknownActionInRule {
            rule: RuleId::new("r1")
        })
    );
}

#[test]
fn distinct_condition_kinds_on_one_rule_are_accepted() {
    let mut rule = sample_rule("r1");
    rule.conditions = vec![
        uid_condition(1000),
        Condition::ExecutablePath(EvidenceMatch {
            expected: "/usr/bin/tool".to_string(),
            min_trust: TrustFloor::BestEffort,
        }),
    ];
    let document = PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 1,
        rules: vec![rule],
    };
    assert!(PolicySet::from_document(document).is_ok());
}

#[test]
fn versioned_envelope_with_unsupported_version_is_rejected() {
    use eltanin_core::envelope::Versioned;

    let document = PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 1,
        rules: Vec::new(),
    };
    let envelope = Versioned {
        version: 9999,
        payload: document,
    };
    let result = PolicySet::from_versioned(envelope);
    assert!(matches!(result, Err(PolicyError::UnsupportedVersion(_))));
}

#[test]
fn versioned_envelope_at_the_current_version_is_accepted() {
    use eltanin_core::envelope::Versioned;

    let document = PolicyDocument {
        id: PolicyId::new("p1"),
        revision: 1,
        rules: Vec::new(),
    };
    let envelope = Versioned::current(document);
    assert!(PolicySet::from_versioned(envelope).is_ok());
}
