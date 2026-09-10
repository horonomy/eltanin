//! Multi-vector spoof-signal regression coverage (F-M1-004, HORO-835).
//! HORO-834's own tests cover single-vector spoofing (one field
//! self-asserted). This file composes multiple simultaneously-spoofed
//! fields against a realistic multi-condition policy, per HORO-835's
//! AC: "Spoof-prone signals cannot independently grant ALLOW."

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

/// A realistic policy requiring a trusted uid AND a trusted executable
/// path together — the kind of multi-signal rule an operator would
/// actually author to reduce single-signal spoofing risk.
fn strict_policy() -> PolicySet {
    PolicySet::from_document(PolicyDocument {
        id: PolicyId::new("strict"),
        revision: 1,
        rules: vec![Rule {
            id: RuleId::new("allow-trusted-tool"),
            effect: Effect::Allow,
            resource: resource(),
            action: Action::Compute,
            conditions: vec![
                Condition::Uid(EvidenceMatch {
                    expected: 1000,
                    min_trust: TrustFloor::KernelObserved,
                }),
                Condition::ExecutablePath(EvidenceMatch {
                    expected: "/usr/bin/trusted-tool".to_string(),
                    min_trust: TrustFloor::KernelObserved,
                }),
            ],
        }],
    })
    .unwrap()
}

fn context_with(
    uid_value: u32,
    uid_source: EvidenceSource,
    path_value: &str,
    path_source: EvidenceSource,
) -> ExecutionContext {
    ExecutionContext {
        workload: WorkloadIdentity {
            pid: 42,
            process_start: Evidence::Present {
                value: ProcessStartToken(100),
                source: EvidenceSource::KernelObserved,
            },
            uid: Evidence::Present {
                value: uid_value,
                source: uid_source,
            },
            gid: Evidence::Present {
                value: uid_value,
                source: uid_source,
            },
            executable_path: Evidence::Present {
                value: path_value.to_string(),
                source: path_source,
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
fn both_signals_self_asserted_never_grants_allow_even_with_correct_values() {
    // An attacker who can fully forge both the claimed uid and path
    // (both SelfAsserted) still cannot obtain Allow, because the
    // TrustFloor on both conditions requires KernelObserved.
    let context = context_with(
        1000,
        EvidenceSource::SelfAsserted,
        "/usr/bin/trusted-tool",
        EvidenceSource::SelfAsserted,
    );
    let decision = strict_policy().evaluate(&context, &request());
    assert_eq!(decision.effect(), Effect::Deny);
    assert_eq!(decision.reason(), &DecisionReason::NoMatchingRule);
}

#[test]
fn one_trusted_signal_and_one_spoofed_signal_never_grants_allow() {
    // A partially-compromised evidence chain (real uid, forged path, or
    // vice versa) must not be treated as "close enough" — every
    // condition on the rule must independently clear its trust floor.
    let uid_trusted_path_spoofed = context_with(
        1000,
        EvidenceSource::KernelObserved,
        "/usr/bin/trusted-tool",
        EvidenceSource::SelfAsserted,
    );
    assert_eq!(
        strict_policy()
            .evaluate(&uid_trusted_path_spoofed, &request())
            .effect(),
        Effect::Deny
    );

    let path_trusted_uid_spoofed = context_with(
        1000,
        EvidenceSource::SelfAsserted,
        "/usr/bin/trusted-tool",
        EvidenceSource::KernelObserved,
    );
    assert_eq!(
        strict_policy()
            .evaluate(&path_trusted_uid_spoofed, &request())
            .effect(),
        Effect::Deny
    );
}

#[test]
fn both_signals_trusted_and_correct_grants_allow() {
    // Sanity check that the strict policy is satisfiable at all — proves
    // the deny results above are because of spoofing, not because the
    // policy is unconditionally unsatisfiable.
    let context = context_with(
        1000,
        EvidenceSource::KernelObserved,
        "/usr/bin/trusted-tool",
        EvidenceSource::KernelObserved,
    );
    let decision = strict_policy().evaluate(&context, &request());
    assert_eq!(decision.effect(), Effect::Allow);
}

#[test]
fn both_signals_trusted_but_wrong_values_denies() {
    // Correct trust level, wrong content — a different real user
    // running a different real binary must not satisfy this rule.
    let context = context_with(
        2000,
        EvidenceSource::KernelObserved,
        "/usr/bin/other-tool",
        EvidenceSource::KernelObserved,
    );
    let decision = strict_policy().evaluate(&context, &request());
    assert_eq!(decision.effect(), Effect::Deny);
}

#[test]
fn spoofed_uid_matching_a_deny_rule_still_denies_via_no_matching_rule_not_by_luck() {
    // A self-asserted claim of a dangerous value (uid 0) must not
    // accidentally grant safety just because it's untrusted. The
    // deny-on-uid-0 rule requires KernelObserved, so a SelfAsserted
    // uid=0 claim is Present-but-below-floor evidence — definitively
    // ConditionOutcome::NotMatched, not Indeterminate (Indeterminate is
    // reserved for genuinely Missing/Unsupported evidence — see
    // policy.rs's ConditionOutcome). That distinction is what this test
    // actually pins: asserting only effect() == Deny here would pass
    // even if the implementation were broken in a way that still
    // produced Deny for an unrelated reason (the original version of
    // this test, flagged by independent review, did exactly that — the
    // policy had zero allow rules, so it could only ever produce Deny
    // regardless of whether any matching logic ran at all). Adding an
    // unrelated allow rule and asserting the specific reason closes
    // that gap.
    let policy = PolicySet::from_document(PolicyDocument {
        id: PolicyId::new("with-deny"),
        revision: 1,
        rules: vec![
            Rule {
                id: RuleId::new("deny-root"),
                effect: Effect::Deny,
                resource: resource(),
                action: Action::Compute,
                conditions: vec![Condition::Uid(EvidenceMatch {
                    expected: 0,
                    min_trust: TrustFloor::KernelObserved,
                })],
            },
            Rule {
                id: RuleId::new("allow-unrelated-uid"),
                effect: Effect::Allow,
                resource: resource(),
                action: Action::Compute,
                conditions: vec![Condition::Uid(EvidenceMatch {
                    expected: 5000,
                    min_trust: TrustFloor::KernelObserved,
                })],
            },
        ],
    })
    .unwrap();

    let context = context_with(
        0,
        EvidenceSource::SelfAsserted,
        "/usr/bin/trusted-tool",
        EvidenceSource::KernelObserved,
    );
    let decision = policy.evaluate(&context, &request());
    assert_eq!(decision.effect(), Effect::Deny);
    // Neither rule matches: deny-root's uid condition is definitively
    // NotMatched (Present, below floor — not unobserved), and
    // allow-unrelated-uid's condition doesn't match either. The result
    // must be plain NoMatchingRule, not IndeterminateEvidence — proving
    // the untrusted claim was correctly treated as "doesn't satisfy
    // this condition," not "we don't know."
    assert_eq!(decision.reason(), &DecisionReason::NoMatchingRule);
}
