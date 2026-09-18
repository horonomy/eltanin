//! Signal-composition, precedence, and validation coverage for
//! `eltanin_core::risk` (F-M2-004, HORO-794).

use std::collections::{BTreeMap, BTreeSet};

use eltanin_core::approval::{ApprovalId, ChangedDimension, RecallVerdict};
use eltanin_core::delegation::{DelegationVerdict, ExceededBound};
use eltanin_core::identity::{
    Evidence, EvidenceSource, ExecutionContext, ProcessStartToken, WorkloadIdentity,
};
use eltanin_core::risk::{
    assess, GateVerdicts, RiskSignal, SignalDisposition, StepUpPolicy, StepUpPolicyError,
    StepUpVerdict,
};
use eltanin_core::session::MembershipVerdict;

fn context(uid: u32, executable_path: &str) -> ExecutionContext {
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
                value: executable_path.to_string(),
                source: EvidenceSource::KernelObserved,
            },
            executable_hash: Evidence::Missing {
                reason: "not needed for this fixture".into(),
            },
            ancestry: Vec::new(),
        },
        cgroup_path: Evidence::Unsupported,
        namespace_hint: Evidence::Unsupported,
        container_hint: Evidence::Unsupported,
        session_origin: Evidence::Unsupported,
    }
}

fn member() -> MembershipVerdict {
    MembershipVerdict::Member
}

fn empty_policy() -> StepUpPolicy {
    StepUpPolicy::new(BTreeMap::new(), BTreeSet::new()).unwrap()
}

fn policy_with(
    dispositions: &[(RiskSignal, SignalDisposition)],
    untrusted_prefixes: &[&str],
) -> StepUpPolicy {
    StepUpPolicy::new(
        dispositions.iter().copied().collect(),
        untrusted_prefixes.iter().map(ToString::to_string).collect(),
    )
    .unwrap()
}

fn no_signals(verdict: &StepUpVerdict) -> &BTreeSet<RiskSignal> {
    match verdict {
        StepUpVerdict::NoStepUp { signals }
        | StepUpVerdict::StepUpRequired { signals }
        | StepUpVerdict::RiskDenied { signals } => signals,
    }
}

#[test]
fn zero_approval_candidates_fires_unknown_launcher() {
    let ctx = context(1000, "/usr/bin/tool");
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &[],
        delegation: None,
    };
    let verdict = assess(&verdicts, &ctx, &empty_policy());
    assert!(no_signals(&verdict).contains(&RiskSignal::UnknownLauncher));
    assert!(matches!(verdict, StepUpVerdict::NoStepUp { .. }));
}

#[test]
fn launcher_path_changed_fires_unknown_launcher() {
    let ctx = context(1000, "/usr/bin/tool");
    let changed = [RecallVerdict::NotMatched {
        changed: BTreeSet::from([ChangedDimension::LauncherPath]),
    }];
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &changed,
        delegation: None,
    };
    let verdict = assess(&verdicts, &ctx, &empty_policy());
    assert!(no_signals(&verdict).contains(&RiskSignal::UnknownLauncher));
}

#[test]
fn untrusted_execution_path_fires_from_configured_prefix() {
    let ctx = context(1000, "/tmp/payload");
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &[],
        delegation: None,
    };
    let policy = policy_with(&[], &["/tmp/"]);
    let verdict = assess(&verdicts, &ctx, &policy);
    assert!(no_signals(&verdict).contains(&RiskSignal::UntrustedExecutionPath));
}

#[test]
fn trusted_execution_path_does_not_fire() {
    let ctx = context(1000, "/usr/bin/tool");
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &[],
        delegation: None,
    };
    let policy = policy_with(&[], &["/tmp/"]);
    let verdict = assess(&verdicts, &ctx, &policy);
    assert!(!no_signals(&verdict).contains(&RiskSignal::UntrustedExecutionPath));
}

#[test]
fn launcher_digest_changed_fires_launcher_identity_changed() {
    let ctx = context(1000, "/usr/bin/tool");
    let changed = [RecallVerdict::NotMatched {
        changed: BTreeSet::from([ChangedDimension::LauncherDigest]),
    }];
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &changed,
        delegation: None,
    };
    let verdict = assess(&verdicts, &ctx, &empty_policy());
    assert!(no_signals(&verdict).contains(&RiskSignal::LauncherIdentityChanged));
}

#[test]
fn owner_uid_changed_via_recall_fires_privilege_transition() {
    let ctx = context(1000, "/usr/bin/tool");
    let changed = [RecallVerdict::NotMatched {
        changed: BTreeSet::from([ChangedDimension::OwnerUid]),
    }];
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &changed,
        delegation: None,
    };
    let verdict = assess(&verdicts, &ctx, &empty_policy());
    assert!(no_signals(&verdict).contains(&RiskSignal::PrivilegeTransition));
    assert!(!no_signals(&verdict).contains(&RiskSignal::PrivilegeEscalationToRoot));
}

#[test]
fn owner_uid_changed_via_delegation_fires_privilege_transition() {
    let ctx = context(1000, "/usr/bin/tool");
    let delegation = DelegationVerdict::NotAdmitted {
        exceeded: BTreeSet::from([ExceededBound::OwnerUid]),
    };
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &[],
        delegation: Some(&delegation),
    };
    let verdict = assess(&verdicts, &ctx, &empty_policy());
    assert!(no_signals(&verdict).contains(&RiskSignal::PrivilegeTransition));
}

#[test]
fn privilege_escalation_to_root_requires_both_transition_and_observed_root() {
    let changed = [RecallVerdict::NotMatched {
        changed: BTreeSet::from([ChangedDimension::OwnerUid]),
    }];

    // Transition fired, but observed uid is not root: no escalation signal.
    let ctx_non_root = context(1000, "/usr/bin/tool");
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &changed,
        delegation: None,
    };
    let verdict = assess(&verdicts, &ctx_non_root, &empty_policy());
    assert!(!no_signals(&verdict).contains(&RiskSignal::PrivilegeEscalationToRoot));

    // Observed uid is root, but no transition fired: no escalation signal.
    let ctx_root = context(0, "/usr/bin/tool");
    let verdicts_no_transition = GateVerdicts {
        membership: &member(),
        recall: &[],
        delegation: None,
    };
    let verdict = assess(&verdicts_no_transition, &ctx_root, &empty_policy());
    assert!(!no_signals(&verdict).contains(&RiskSignal::PrivilegeEscalationToRoot));

    // Both fire together: escalation signal fires.
    let verdicts_both = GateVerdicts {
        membership: &member(),
        recall: &changed,
        delegation: None,
    };
    let verdict = assess(&verdicts_both, &ctx_root, &empty_policy());
    assert!(no_signals(&verdict).contains(&RiskSignal::PrivilegeEscalationToRoot));
}

#[test]
fn not_member_fires_detached_execution() {
    let ctx = context(1000, "/usr/bin/tool");
    let verdict_membership = MembershipVerdict::NotMember {
        reason: eltanin_core::session::NotMemberReason::KeyMismatch,
    };
    let verdicts = GateVerdicts {
        membership: &verdict_membership,
        recall: &[],
        delegation: None,
    };
    let verdict = assess(&verdicts, &ctx, &empty_policy());
    assert!(no_signals(&verdict).contains(&RiskSignal::DetachedExecution));
}

#[test]
fn indeterminate_membership_fires_detached_execution_and_evidence_indeterminate() {
    let ctx = context(1000, "/usr/bin/tool");
    let verdict_membership = MembershipVerdict::Indeterminate {
        reason: "test".into(),
    };
    let verdicts = GateVerdicts {
        membership: &verdict_membership,
        recall: &[],
        delegation: None,
    };
    let verdict = assess(&verdicts, &ctx, &empty_policy());
    assert!(no_signals(&verdict).contains(&RiskSignal::DetachedExecution));
    assert!(no_signals(&verdict).contains(&RiskSignal::EvidenceIndeterminate));
}

#[test]
fn delegation_scope_expanded_fires_on_resource_action_depth_duration() {
    for bound in [
        ExceededBound::Resource,
        ExceededBound::Action,
        ExceededBound::Depth,
        ExceededBound::Duration,
    ] {
        let ctx = context(1000, "/usr/bin/tool");
        let delegation = DelegationVerdict::NotAdmitted {
            exceeded: BTreeSet::from([bound]),
        };
        let verdicts = GateVerdicts {
            membership: &member(),
            recall: &[],
            delegation: Some(&delegation),
        };
        let verdict = assess(&verdicts, &ctx, &empty_policy());
        assert!(
            no_signals(&verdict).contains(&RiskSignal::DelegationScopeExpanded),
            "bound {bound:?} should fire DelegationScopeExpanded"
        );
    }
}

#[test]
fn ancestry_linkage_and_holder_liveness_never_fire_delegation_scope_expanded() {
    // These two bounds are excluded from the narrowed exceeded set by
    // the caller (see eltanin-agent's `linked_exceeded`) before it ever
    // reaches `assess` — but even if one leaked through, it must not be
    // classified as scope expansion.
    for bound in [
        ExceededBound::AncestryLinkage,
        ExceededBound::HolderLiveness,
    ] {
        let ctx = context(1000, "/usr/bin/tool");
        let delegation = DelegationVerdict::NotAdmitted {
            exceeded: BTreeSet::from([bound]),
        };
        let verdicts = GateVerdicts {
            membership: &member(),
            recall: &[],
            delegation: Some(&delegation),
        };
        let verdict = assess(&verdicts, &ctx, &empty_policy());
        assert!(!no_signals(&verdict).contains(&RiskSignal::DelegationScopeExpanded));
    }
}

#[test]
fn security_posture_changed_fires_on_capability_or_policy_drift() {
    for dimension in [
        ChangedDimension::ResourceCapabilityState,
        ChangedDimension::PolicyRevision,
    ] {
        let ctx = context(1000, "/usr/bin/tool");
        let changed = [RecallVerdict::NotMatched {
            changed: BTreeSet::from([dimension]),
        }];
        let verdicts = GateVerdicts {
            membership: &member(),
            recall: &changed,
            delegation: None,
        };
        let verdict = assess(&verdicts, &ctx, &empty_policy());
        assert!(no_signals(&verdict).contains(&RiskSignal::SecurityPostureChanged));
    }
}

#[test]
fn context_boundary_changed_fires_on_cgroup_or_session_key() {
    let ctx = context(1000, "/usr/bin/tool");
    let changed = [RecallVerdict::NotMatched {
        changed: BTreeSet::from([ChangedDimension::CgroupPath]),
    }];
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &changed,
        delegation: None,
    };
    let verdict = assess(&verdicts, &ctx, &empty_policy());
    assert!(no_signals(&verdict).contains(&RiskSignal::ContextBoundaryChanged));

    for bound in [ExceededBound::CgroupPath, ExceededBound::SessionKey] {
        let delegation = DelegationVerdict::NotAdmitted {
            exceeded: BTreeSet::from([bound]),
        };
        let verdicts = GateVerdicts {
            membership: &member(),
            recall: &[],
            delegation: Some(&delegation),
        };
        let verdict = assess(&verdicts, &ctx, &empty_policy());
        assert!(no_signals(&verdict).contains(&RiskSignal::ContextBoundaryChanged));
    }
}

#[test]
fn trust_transition_fires_from_delegation_bound() {
    let ctx = context(1000, "/usr/bin/tool");
    let delegation = DelegationVerdict::NotAdmitted {
        exceeded: BTreeSet::from([ExceededBound::TrustTransition]),
    };
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &[],
        delegation: Some(&delegation),
    };
    let verdict = assess(&verdicts, &ctx, &empty_policy());
    assert!(no_signals(&verdict).contains(&RiskSignal::TrustTransition));
}

#[test]
fn recall_indeterminate_fires_evidence_indeterminate() {
    let ctx = context(1000, "/usr/bin/tool");
    let indeterminate = [RecallVerdict::Indeterminate {
        reason: "test".into(),
    }];
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &indeterminate,
        delegation: None,
    };
    let verdict = assess(&verdicts, &ctx, &empty_policy());
    assert!(no_signals(&verdict).contains(&RiskSignal::EvidenceIndeterminate));
}

#[test]
fn delegation_indeterminate_fires_evidence_indeterminate() {
    let ctx = context(1000, "/usr/bin/tool");
    let delegation = DelegationVerdict::Indeterminate {
        reason: "test".into(),
    };
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &[],
        delegation: Some(&delegation),
    };
    let verdict = assess(&verdicts, &ctx, &empty_policy());
    assert!(no_signals(&verdict).contains(&RiskSignal::EvidenceIndeterminate));
}

#[test]
fn informational_only_config_yields_no_step_up() {
    let ctx = context(1000, "/usr/bin/tool");
    let changed = [RecallVerdict::NotMatched {
        changed: BTreeSet::from([ChangedDimension::LauncherDigest]),
    }];
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &changed,
        delegation: None,
    };
    let policy = policy_with(
        &[(
            RiskSignal::LauncherIdentityChanged,
            SignalDisposition::Informational,
        )],
        &[],
    );
    let verdict = assess(&verdicts, &ctx, &policy);
    assert!(matches!(verdict, StepUpVerdict::NoStepUp { .. }));
    assert!(no_signals(&verdict).contains(&RiskSignal::LauncherIdentityChanged));
}

#[test]
fn unnamed_signal_defaults_to_informational() {
    let ctx = context(1000, "/usr/bin/tool");
    let changed = [RecallVerdict::NotMatched {
        changed: BTreeSet::from([ChangedDimension::LauncherDigest]),
    }];
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &changed,
        delegation: None,
    };
    // Policy names no dispositions at all.
    let verdict = assess(&verdicts, &ctx, &empty_policy());
    assert!(matches!(verdict, StepUpVerdict::NoStepUp { .. }));
}

#[test]
fn step_up_disposition_elevates_to_step_up_required() {
    let ctx = context(1000, "/usr/bin/tool");
    let changed = [RecallVerdict::NotMatched {
        changed: BTreeSet::from([ChangedDimension::LauncherDigest]),
    }];
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &changed,
        delegation: None,
    };
    let policy = policy_with(
        &[(
            RiskSignal::LauncherIdentityChanged,
            SignalDisposition::StepUp,
        )],
        &[],
    );
    let verdict = assess(&verdicts, &ctx, &policy);
    assert!(matches!(verdict, StepUpVerdict::StepUpRequired { .. }));
}

#[test]
fn deny_overrides_step_up_regardless_of_order() {
    let ctx = context(1000, "/usr/bin/tool");
    let changed = [RecallVerdict::NotMatched {
        changed: BTreeSet::from([ChangedDimension::LauncherDigest, ChangedDimension::OwnerUid]),
    }];
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &changed,
        delegation: None,
    };
    // LauncherIdentityChanged -> StepUp, PrivilegeTransition -> Deny.
    // Deny must win regardless of BTreeSet iteration order.
    let policy = policy_with(
        &[
            (
                RiskSignal::LauncherIdentityChanged,
                SignalDisposition::StepUp,
            ),
            (RiskSignal::PrivilegeTransition, SignalDisposition::Deny),
        ],
        &[],
    );
    let verdict = assess(&verdicts, &ctx, &policy);
    assert!(matches!(verdict, StepUpVerdict::RiskDenied { .. }));
}

#[test]
fn path_signal_cannot_deny() {
    let mut dispositions = BTreeMap::new();
    dispositions.insert(RiskSignal::UntrustedExecutionPath, SignalDisposition::Deny);
    let result = StepUpPolicy::new(dispositions, BTreeSet::new());
    assert_eq!(result.unwrap_err(), StepUpPolicyError::PathSignalCannotDeny);
}

#[test]
fn path_signal_can_step_up() {
    let mut dispositions = BTreeMap::new();
    dispositions.insert(
        RiskSignal::UntrustedExecutionPath,
        SignalDisposition::StepUp,
    );
    assert!(StepUpPolicy::new(dispositions, BTreeSet::new()).is_ok());
}

#[test]
fn recommended_disposition_table_is_exhaustive_over_all_signals() {
    // A deployment that wants to name a disposition for every signal
    // must be able to do so without RiskSignal::ALL drifting from the
    // enum's real variant set. Path can never map to Deny.
    let mut dispositions: BTreeMap<RiskSignal, SignalDisposition> = RiskSignal::ALL
        .iter()
        .map(|signal| (*signal, SignalDisposition::StepUp))
        .collect();
    dispositions.insert(
        RiskSignal::UntrustedExecutionPath,
        SignalDisposition::StepUp,
    );
    assert_eq!(dispositions.len(), RiskSignal::ALL.len());
    assert!(StepUpPolicy::new(dispositions, BTreeSet::new()).is_ok());
}

#[test]
fn matched_recall_verdicts_are_never_passed_in_by_a_well_behaved_caller() {
    // Documented invariant: assess() is reachable only from a refusal
    // arm, so `recall` must never contain `Matched`. This test pins the
    // *documented* contract by demonstrating assess() does not special-
    // case Matched at all — a Matched verdict simply contributes no
    // signal, it is never treated as a step-up trigger. A well-behaved
    // caller (the agent's approval gate) never constructs this input.
    let ctx = context(1000, "/usr/bin/tool");
    let matched = [RecallVerdict::Matched {
        id: ApprovalId::from_raw("test"),
    }];
    let verdicts = GateVerdicts {
        membership: &member(),
        recall: &matched,
        delegation: None,
    };
    let verdict = assess(&verdicts, &ctx, &empty_policy());
    assert!(matches!(verdict, StepUpVerdict::NoStepUp { .. }));
    assert!(no_signals(&verdict).is_empty());
}
