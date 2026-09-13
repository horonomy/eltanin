//! Bound and linkage coverage for `delegation::delegated_admission`
//! (F-M2-003, HORO-793). Hand-constructs `WorkloadIdentity`/
//! `ProcessAncestor`/`ExecutionContext` values the same way
//! `session.rs`'s/`approval.rs`'s own existing tests do — fully
//! deterministic, no platform collector involved.

use std::collections::BTreeSet;
use std::time::Duration;

use eltanin_core::delegation::{
    delegated_admission, DelegationBounds, DelegationBoundsError, DelegationGrant,
    DelegationVerdict, ExceededBound,
};
use eltanin_core::identity::{
    Evidence, EvidenceSource, ExecutionContext, ProcessAncestor, ProcessStartToken,
    WorkloadIdentity,
};
use eltanin_core::lease::{IssuerInstanceId, LeaseIssuer, MonotonicTime};
use eltanin_core::policy::{
    Condition, Effect, EvidenceMatch, PolicyDocument, PolicyId, PolicySet, Rule, RuleId, TrustFloor,
};
use eltanin_core::provenance::ProvenanceRecord;
use eltanin_core::resource::{
    Action, ComputeRequest, ResourceIdentity, ResourceKind, ResourceVendor,
};
use eltanin_core::session::SessionKey;

fn resource() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-0".into(),
    }
}

fn other_resource() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-1".into(),
    }
}

fn present_start(value: u64) -> Evidence<ProcessStartToken> {
    Evidence::Present {
        value: ProcessStartToken(value),
        source: EvidenceSource::KernelObserved,
    }
}

fn workload(pid: u32, start: Evidence<ProcessStartToken>, uid: u32) -> WorkloadIdentity {
    WorkloadIdentity {
        pid,
        process_start: start,
        uid: Evidence::Present {
            value: uid,
            source: EvidenceSource::KernelObserved,
        },
        gid: Evidence::Present {
            value: uid,
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

fn ancestor(
    pid: u32,
    start: Evidence<ProcessStartToken>,
    executable_path: Evidence<String>,
) -> ProcessAncestor {
    ProcessAncestor {
        pid,
        start,
        executable_path,
    }
}

fn kernel_path(value: &str) -> Evidence<String> {
    Evidence::Present {
        value: value.to_string(),
        source: EvidenceSource::KernelObserved,
    }
}

fn context_with_ancestry(child_uid: u32, ancestry: Vec<ProcessAncestor>) -> ExecutionContext {
    ExecutionContext {
        workload: WorkloadIdentity {
            ancestry,
            ..workload(9000, present_start(1), child_uid)
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

fn holder_execution_context(holder: &WorkloadIdentity) -> ExecutionContext {
    ExecutionContext {
        workload: holder.clone(),
        cgroup_path: Evidence::Unsupported,
        namespace_hint: Evidence::Unsupported,
        container_hint: Evidence::Unsupported,
        session_origin: Evidence::Unsupported,
    }
}

/// Issue a real lease bound to `holder`, for `resource()`/`Action::Compute`,
/// with `ttl` remaining from time zero.
fn issue_lease(holder: &WorkloadIdentity, ttl: Duration) -> eltanin_core::lease::ComputeLease {
    let mut issuer = LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(3600));
    let policy = allow_all_policy();
    let origin = ProvenanceRecord::new(
        holder_execution_context(holder),
        ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
    );
    issuer
        .issue(&policy, origin, MonotonicTime::from_nanos(0), ttl)
        .unwrap()
}

fn default_bounds() -> DelegationBounds {
    DelegationBounds::new(
        4,
        Duration::from_secs(300),
        Duration::from_secs(1),
        [Action::Compute],
        BTreeSet::new(),
        false,
        false,
    )
    .unwrap()
}

fn mint_grant(
    lease: &eltanin_core::lease::ComputeLease,
    bounds: &DelegationBounds,
    holder: &WorkloadIdentity,
    owner_uid: u32,
    depth: u8,
) -> DelegationGrant {
    DelegationGrant::mint(
        lease,
        bounds,
        holder.clone(),
        owner_uid,
        None,
        None,
        depth,
        None,
    )
    .expect("Action::Compute must be delegable under default_bounds")
}

fn absent_session_key() -> Evidence<SessionKey> {
    Evidence::Unsupported
}

#[test]
fn child_resource_outside_parent_scope_is_not_admitted() {
    let holder = workload(100, present_start(10), 1000);
    let lease = issue_lease(&holder, Duration::from_secs(60));
    let bounds = default_bounds();
    let grant = mint_grant(&lease, &bounds, &holder, 1000, 0);

    let requester = context_with_ancestry(
        1000,
        vec![ancestor(
            100,
            present_start(10),
            kernel_path("/usr/bin/eltanin-run"),
        )],
    );
    let verdict = delegated_admission(
        &grant,
        &bounds,
        &requester,
        &absent_session_key(),
        &holder,
        &ComputeRequest {
            resource: other_resource(),
            action: Action::Compute,
        },
        MonotonicTime::from_nanos(1),
    );
    match verdict {
        DelegationVerdict::NotAdmitted { exceeded } => {
            assert!(exceeded.contains(&ExceededBound::Resource));
        }
        other => panic!("expected NotAdmitted{{Resource}}, got {other:?}"),
    }
}

#[test]
fn child_action_outside_parent_scope_is_not_admitted() {
    let holder = workload(100, present_start(10), 1000);
    let lease = issue_lease(&holder, Duration::from_secs(60));
    let bounds = default_bounds();
    let grant = mint_grant(&lease, &bounds, &holder, 1000, 0);

    let requester = context_with_ancestry(
        1000,
        vec![ancestor(
            100,
            present_start(10),
            kernel_path("/usr/bin/eltanin-run"),
        )],
    );
    let verdict = delegated_admission(
        &grant,
        &bounds,
        &requester,
        &absent_session_key(),
        &holder,
        &ComputeRequest {
            resource: resource(),
            action: Action::Unknown,
        },
        MonotonicTime::from_nanos(1),
    );
    match verdict {
        DelegationVerdict::NotAdmitted { exceeded } => {
            assert!(exceeded.contains(&ExceededBound::Action));
        }
        other => panic!("expected NotAdmitted{{Action}}, got {other:?}"),
    }
}

#[test]
fn admitted_child_ttl_is_capped_by_narrow_expiry() {
    let holder = workload(100, present_start(10), 1000);
    // Parent lease has 60s remaining from time zero.
    let lease = issue_lease(&holder, Duration::from_secs(60));
    let parent_not_after = lease.expires_at();
    // max_child_ttl is much smaller than the parent's remaining time.
    let bounds = DelegationBounds::new(
        4,
        Duration::from_secs(10),
        Duration::from_secs(1),
        [Action::Compute],
        BTreeSet::new(),
        false,
        false,
    )
    .unwrap();
    let grant = mint_grant(&lease, &bounds, &holder, 1000, 0);
    assert_eq!(grant.not_after(), parent_not_after);

    let requester = context_with_ancestry(
        1000,
        vec![ancestor(
            100,
            present_start(10),
            kernel_path("/usr/bin/eltanin-run"),
        )],
    );
    let now = MonotonicTime::from_nanos(1);
    let verdict = delegated_admission(
        &grant,
        &bounds,
        &requester,
        &absent_session_key(),
        &holder,
        &ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
        now,
    );
    let DelegationVerdict::Admitted { not_after, .. } = verdict else {
        panic!("expected Admitted, got {verdict:?}");
    };
    // Capped to now + max_child_ttl, strictly less than the parent's own
    // (much longer) expiry.
    assert_eq!(not_after, now.checked_add(Duration::from_secs(10)).unwrap());
    assert!(not_after < parent_not_after);
}

#[test]
fn parent_within_min_remaining_is_not_admitted_for_duration_not_expiry_overflow() {
    let holder = workload(100, present_start(10), 1000);
    // Parent lease has only 500ms remaining.
    let lease = issue_lease(&holder, Duration::from_millis(500));
    let bounds = DelegationBounds::new(
        4,
        Duration::from_secs(300),
        Duration::from_secs(1), // min_remaining exceeds what's left
        [Action::Compute],
        BTreeSet::new(),
        false,
        false,
    )
    .unwrap();
    let grant = mint_grant(&lease, &bounds, &holder, 1000, 0);

    let requester = context_with_ancestry(
        1000,
        vec![ancestor(
            100,
            present_start(10),
            kernel_path("/usr/bin/eltanin-run"),
        )],
    );
    let verdict = delegated_admission(
        &grant,
        &bounds,
        &requester,
        &absent_session_key(),
        &holder,
        &ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
        MonotonicTime::from_nanos(1),
    );
    match verdict {
        DelegationVerdict::NotAdmitted { exceeded } => {
            assert_eq!(exceeded, BTreeSet::from([ExceededBound::Duration]));
        }
        other => panic!("expected NotAdmitted{{Duration}}, not {other:?} (never ExpiryOverflow)"),
    }
}

#[test]
fn depth_equal_to_max_depth_admits_and_depth_plus_one_is_refused() {
    let holder = workload(100, present_start(10), 1000);
    let lease = issue_lease(&holder, Duration::from_secs(60));
    let bounds = DelegationBounds::new(
        2,
        Duration::from_secs(300),
        Duration::from_secs(1),
        [Action::Compute],
        BTreeSet::new(),
        false,
        false,
    )
    .unwrap();
    let requester = context_with_ancestry(
        1000,
        vec![ancestor(
            100,
            present_start(10),
            kernel_path("/usr/bin/eltanin-run"),
        )],
    );
    let request = ComputeRequest {
        resource: resource(),
        action: Action::Compute,
    };

    // depth 1 -> child depth 2, exactly max_depth: admitted.
    let grant_at_1 = mint_grant(&lease, &bounds, &holder, 1000, 1);
    let verdict = delegated_admission(
        &grant_at_1,
        &bounds,
        &requester,
        &absent_session_key(),
        &holder,
        &request,
        MonotonicTime::from_nanos(1),
    );
    assert!(matches!(
        verdict,
        DelegationVerdict::Admitted { depth: 2, .. }
    ));

    // depth 2 -> child depth 3, exceeds max_depth: refused.
    let grant_at_2 = mint_grant(&lease, &bounds, &holder, 1000, 2);
    let verdict = delegated_admission(
        &grant_at_2,
        &bounds,
        &requester,
        &absent_session_key(),
        &holder,
        &request,
        MonotonicTime::from_nanos(1),
    );
    match verdict {
        DelegationVerdict::NotAdmitted { exceeded } => {
            assert!(exceeded.contains(&ExceededBound::Depth));
        }
        other => panic!("expected NotAdmitted{{Depth}}, got {other:?}"),
    }
}

#[test]
fn holder_pid_reused_by_unrelated_process_is_not_admitted() {
    let holder = workload(100, present_start(10), 1000);
    let lease = issue_lease(&holder, Duration::from_secs(60));
    let bounds = default_bounds();
    let grant = mint_grant(&lease, &bounds, &holder, 1000, 0);

    // Same pid, different start token: a different process now.
    let reused = workload(100, present_start(999), 1000);
    let requester = context_with_ancestry(
        1000,
        vec![ancestor(
            100,
            present_start(999),
            kernel_path("/usr/bin/eltanin-run"),
        )],
    );
    let verdict = delegated_admission(
        &grant,
        &bounds,
        &requester,
        &absent_session_key(),
        &reused,
        &ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
        MonotonicTime::from_nanos(1),
    );
    match verdict {
        DelegationVerdict::NotAdmitted { exceeded } => {
            assert!(exceeded.contains(&ExceededBound::HolderLiveness));
        }
        other => panic!("expected NotAdmitted{{HolderLiveness}}, got {other:?}"),
    }
}

#[test]
fn holder_absent_from_ancestry_is_not_admitted() {
    let holder = workload(100, present_start(10), 1000);
    let lease = issue_lease(&holder, Duration::from_secs(60));
    let bounds = default_bounds();
    let grant = mint_grant(&lease, &bounds, &holder, 1000, 0);

    // Ancestry names a confirmed-different process, never the holder.
    let requester = context_with_ancestry(
        1000,
        vec![ancestor(
            200,
            present_start(20),
            kernel_path("/usr/bin/other"),
        )],
    );
    let verdict = delegated_admission(
        &grant,
        &bounds,
        &requester,
        &absent_session_key(),
        &holder,
        &ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
        MonotonicTime::from_nanos(1),
    );
    match verdict {
        DelegationVerdict::NotAdmitted { exceeded } => {
            assert!(exceeded.contains(&ExceededBound::AncestryLinkage));
        }
        other => panic!("expected NotAdmitted{{AncestryLinkage}}, got {other:?}"),
    }
}

#[test]
fn ancestry_with_unresolvable_evidence_and_no_match_is_indeterminate_not_not_admitted() {
    let holder = workload(100, present_start(10), 1000);
    let lease = issue_lease(&holder, Duration::from_secs(60));
    let bounds = default_bounds();
    let grant = mint_grant(&lease, &bounds, &holder, 1000, 0);

    let requester = context_with_ancestry(
        1000,
        vec![ancestor(
            200,
            Evidence::Missing {
                reason: "permission denied".into(),
            },
            kernel_path("/usr/bin/other"),
        )],
    );
    let verdict = delegated_admission(
        &grant,
        &bounds,
        &requester,
        &absent_session_key(),
        &holder,
        &ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
        MonotonicTime::from_nanos(1),
    );
    assert!(
        matches!(verdict, DelegationVerdict::Indeterminate { .. }),
        "expected Indeterminate, got {verdict:?}"
    );
}

#[test]
fn self_asserted_uid_evidence_is_indeterminate() {
    let holder = workload(100, present_start(10), 1000);
    let lease = issue_lease(&holder, Duration::from_secs(60));
    let bounds = default_bounds();
    let grant = mint_grant(&lease, &bounds, &holder, 1000, 0);

    let mut requester = context_with_ancestry(
        1000,
        vec![ancestor(
            100,
            present_start(10),
            kernel_path("/usr/bin/eltanin-run"),
        )],
    );
    requester.workload.uid = Evidence::Present {
        value: 1000,
        source: EvidenceSource::SelfAsserted,
    };
    let verdict = delegated_admission(
        &grant,
        &bounds,
        &requester,
        &absent_session_key(),
        &holder,
        &ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
        MonotonicTime::from_nanos(1),
    );
    assert!(matches!(verdict, DelegationVerdict::Indeterminate { .. }));
}

#[test]
fn self_asserted_session_key_evidence_is_indeterminate() {
    let holder = workload(100, present_start(10), 1000);
    let lease = issue_lease(&holder, Duration::from_secs(60));
    let bounds = DelegationBounds::new(
        4,
        Duration::from_secs(300),
        Duration::from_secs(1),
        [Action::Compute],
        BTreeSet::new(),
        true, // require_same_session
        false,
    )
    .unwrap();
    let grant = DelegationGrant::mint(
        &lease,
        &bounds,
        holder.clone(),
        1000,
        Some(SessionKey(1)),
        None,
        0,
        None,
    )
    .unwrap();

    let requester = context_with_ancestry(
        1000,
        vec![ancestor(
            100,
            present_start(10),
            kernel_path("/usr/bin/eltanin-run"),
        )],
    );
    let self_asserted_key = Evidence::Present {
        value: SessionKey(1),
        source: EvidenceSource::SelfAsserted,
    };
    let verdict = delegated_admission(
        &grant,
        &bounds,
        &requester,
        &self_asserted_key,
        &holder,
        &ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
        MonotonicTime::from_nanos(1),
    );
    assert!(matches!(verdict, DelegationVerdict::Indeterminate { .. }));
}

#[test]
fn self_asserted_span_executable_path_evidence_is_indeterminate() {
    let holder = workload(100, present_start(10), 1000);
    let lease = issue_lease(&holder, Duration::from_secs(60));
    let bounds = default_bounds();
    let grant = mint_grant(&lease, &bounds, &holder, 1000, 0);

    // Span ancestor at index 0 (between requester and holder at index 1)
    // has self-asserted executable path evidence.
    let requester = context_with_ancestry(
        1000,
        vec![
            ancestor(
                50,
                present_start(5),
                Evidence::Present {
                    value: "/usr/bin/mid".into(),
                    source: EvidenceSource::SelfAsserted,
                },
            ),
            ancestor(100, present_start(10), kernel_path("/usr/bin/eltanin-run")),
        ],
    );
    let verdict = delegated_admission(
        &grant,
        &bounds,
        &requester,
        &absent_session_key(),
        &holder,
        &ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
        MonotonicTime::from_nanos(1),
    );
    assert!(matches!(verdict, DelegationVerdict::Indeterminate { .. }));
}

#[test]
fn transition_marker_present_in_span_is_not_admitted() {
    let holder = workload(100, present_start(10), 1000);
    let lease = issue_lease(&holder, Duration::from_secs(60));
    let bounds = DelegationBounds::new(
        4,
        Duration::from_secs(300),
        Duration::from_secs(1),
        [Action::Compute],
        BTreeSet::from(["/usr/bin/untrusted-plugin".to_string()]),
        false,
        false,
    )
    .unwrap();
    let grant = mint_grant(&lease, &bounds, &holder, 1000, 0);

    // Marker sits in the span between requester (implicit index -1) and
    // holder at index 1.
    let requester = context_with_ancestry(
        1000,
        vec![
            ancestor(
                50,
                present_start(5),
                kernel_path("/usr/bin/untrusted-plugin"),
            ),
            ancestor(100, present_start(10), kernel_path("/usr/bin/eltanin-run")),
        ],
    );
    let verdict = delegated_admission(
        &grant,
        &bounds,
        &requester,
        &absent_session_key(),
        &holder,
        &ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
        MonotonicTime::from_nanos(1),
    );
    match verdict {
        DelegationVerdict::NotAdmitted { exceeded } => {
            assert!(exceeded.contains(&ExceededBound::TrustTransition));
        }
        other => panic!("expected NotAdmitted{{TrustTransition}}, got {other:?}"),
    }
}

/// The scoping test most likely to be implemented wrong (per the design
/// doc): the same marker string, present *above* the holder (index > k),
/// must have zero effect — check 4 only inspects `ancestry[0..holder_index]`.
#[test]
fn transition_marker_above_holder_does_not_prevent_admission() {
    let holder = workload(100, present_start(10), 1000);
    let lease = issue_lease(&holder, Duration::from_secs(60));
    let bounds = DelegationBounds::new(
        4,
        Duration::from_secs(300),
        Duration::from_secs(1),
        [Action::Compute],
        BTreeSet::from(["/usr/bin/untrusted-plugin".to_string()]),
        false,
        false,
    )
    .unwrap();
    let grant = mint_grant(&lease, &bounds, &holder, 1000, 0);

    // Marker sits *above* the holder (index 1, holder at index 0) — must
    // never be inspected.
    let requester = context_with_ancestry(
        1000,
        vec![
            ancestor(100, present_start(10), kernel_path("/usr/bin/eltanin-run")),
            ancestor(
                1,
                present_start(1),
                kernel_path("/usr/bin/untrusted-plugin"),
            ),
        ],
    );
    let verdict = delegated_admission(
        &grant,
        &bounds,
        &requester,
        &absent_session_key(),
        &holder,
        &ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
        MonotonicTime::from_nanos(1),
    );
    assert!(
        matches!(verdict, DelegationVerdict::Admitted { .. }),
        "marker above the holder must not block admission, got {verdict:?}"
    );
}

#[test]
fn delegation_bounds_new_rejects_unknown_action() {
    let error = DelegationBounds::new(
        4,
        Duration::from_secs(300),
        Duration::from_secs(1),
        [Action::Unknown],
        BTreeSet::new(),
        false,
        false,
    )
    .unwrap_err();
    assert_eq!(error, DelegationBoundsError::ActionNotDelegable);
}

#[test]
fn delegation_bounds_new_rejects_depth_over_max_ancestry_depth() {
    let error = DelegationBounds::new(
        33,
        Duration::from_secs(300),
        Duration::from_secs(1),
        [Action::Compute],
        BTreeSet::new(),
        false,
        false,
    )
    .unwrap_err();
    assert_eq!(
        error,
        DelegationBoundsError::DepthExceedsMax {
            requested: 33,
            maximum: 32,
        }
    );
}

#[test]
fn delegation_bounds_new_rejects_zero_min_remaining() {
    let error = DelegationBounds::new(
        4,
        Duration::from_secs(300),
        Duration::ZERO,
        [Action::Compute],
        BTreeSet::new(),
        false,
        false,
    )
    .unwrap_err();
    assert_eq!(error, DelegationBoundsError::NonPositiveMinRemaining);
}
