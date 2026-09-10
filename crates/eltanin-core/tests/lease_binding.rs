//! `ComputeLease` binding and mismatch-rejection coverage (F-M1-005,
//! HORO-836).

use eltanin_core::identity::{
    Evidence, EvidenceSource, ExecutionContext, ProcessStartToken, WorkloadIdentity,
};
use eltanin_core::lease::{IssuerInstanceId, LeaseIssuer, LeaseValidity, MonotonicTime};
use eltanin_core::policy::{
    Condition, Effect, EvidenceMatch, PolicyDocument, PolicyId, PolicySet, Rule, RuleId, TrustFloor,
};
use eltanin_core::provenance::ProvenanceRecord;
use eltanin_core::resource::{
    Action, ComputeRequest, ResourceIdentity, ResourceKind, ResourceVendor,
};

fn resource(local_id: &str) -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: local_id.to_string(),
    }
}

fn context(pid: u32, start: u64, uid: u32) -> ExecutionContext {
    ExecutionContext {
        workload: WorkloadIdentity {
            pid,
            process_start: Evidence::Present {
                value: ProcessStartToken(start),
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
        id: PolicyId::new("allow-all-for-test"),
        revision: 1,
        rules: vec![Rule {
            id: RuleId::new("allow-1000-on-gpu-0"),
            effect: Effect::Allow,
            resource: resource("gpu-0"),
            action: Action::Compute,
            conditions: vec![Condition::Uid(EvidenceMatch {
                expected: 1000,
                min_trust: TrustFloor::KernelObserved,
            })],
        }],
    })
    .unwrap()
}

fn issuer() -> LeaseIssuer {
    LeaseIssuer::new(
        IssuerInstanceId::new("issuer-a"),
        std::time::Duration::from_secs(60),
    )
}

#[test]
fn lease_validates_when_presented_context_matches_exactly() {
    let mut issuer = issuer();
    let policy = allow_all_policy();
    let origin = ProvenanceRecord::new(
        context(42, 100, 1000),
        ComputeRequest {
            resource: resource("gpu-0"),
            action: Action::Compute,
        },
    );
    let now = MonotonicTime::from_nanos(1_000_000_000);
    let lease = issuer
        .issue(
            &policy,
            origin.clone(),
            now,
            std::time::Duration::from_secs(30),
        )
        .expect("policy allows this request");

    let validity = issuer.validate(&lease, &origin, now);
    assert!(validity.is_valid());
}

#[test]
fn lease_rejects_a_different_resource() {
    let mut issuer = issuer();
    let policy = allow_all_policy();
    let request = ComputeRequest {
        resource: resource("gpu-0"),
        action: Action::Compute,
    };
    let origin = ProvenanceRecord::new(context(42, 100, 1000), request);
    let now = MonotonicTime::from_nanos(0);
    let lease = issuer
        .issue(
            &policy,
            origin.clone(),
            now,
            std::time::Duration::from_secs(30),
        )
        .unwrap();

    let presented = ProvenanceRecord::new(
        origin.context.clone(),
        ComputeRequest {
            resource: resource("gpu-1"),
            action: Action::Compute,
        },
    );
    assert_eq!(
        issuer.validate(&lease, &presented, now),
        LeaseValidity::ResourceMismatch
    );
}

#[test]
fn lease_rejects_a_different_action() {
    let mut issuer = issuer();
    let policy = allow_all_policy();
    let origin = ProvenanceRecord::new(
        context(42, 100, 1000),
        ComputeRequest {
            resource: resource("gpu-0"),
            action: Action::Compute,
        },
    );
    let now = MonotonicTime::from_nanos(0);
    let lease = issuer
        .issue(
            &policy,
            origin.clone(),
            now,
            std::time::Duration::from_secs(30),
        )
        .unwrap();

    let presented = ProvenanceRecord::new(
        origin.context.clone(),
        ComputeRequest {
            resource: resource("gpu-0"),
            action: Action::Unknown,
        },
    );
    assert_eq!(
        issuer.validate(&lease, &presented, now),
        LeaseValidity::ActionMismatch
    );
}

#[test]
fn lease_rejects_a_different_workload_pid_and_start_token() {
    let mut issuer = issuer();
    let policy = allow_all_policy();
    let request = ComputeRequest {
        resource: resource("gpu-0"),
        action: Action::Compute,
    };
    let origin = ProvenanceRecord::new(context(42, 100, 1000), request.clone());
    let now = MonotonicTime::from_nanos(0);
    let lease = issuer
        .issue(&policy, origin, now, std::time::Duration::from_secs(30))
        .unwrap();

    // Different pid entirely (e.g. PID reuse by an unrelated process).
    let presented = ProvenanceRecord::new(context(999, 500, 1000), request);
    assert_eq!(
        issuer.validate(&lease, &presented, now),
        LeaseValidity::WorkloadMismatch
    );
}

#[test]
fn lease_rejects_a_different_pid_with_the_same_start_token() {
    // Isolates the pid half of compare_process's `pid == pid && a == b`
    // conjunction from the start-token half — a matching start token
    // alone must not be enough.
    let mut issuer = issuer();
    let policy = allow_all_policy();
    let request = ComputeRequest {
        resource: resource("gpu-0"),
        action: Action::Compute,
    };
    let origin = ProvenanceRecord::new(context(42, 100, 1000), request.clone());
    let now = MonotonicTime::from_nanos(0);
    let lease = issuer
        .issue(&policy, origin, now, std::time::Duration::from_secs(30))
        .unwrap();

    let presented = ProvenanceRecord::new(context(999, 100, 1000), request);
    assert_eq!(
        issuer.validate(&lease, &presented, now),
        LeaseValidity::WorkloadMismatch
    );
}

#[test]
fn lease_rejects_an_in_place_execve_into_a_different_binary() {
    // pid and process_start survive execve() unchanged — compare_process
    // alone would report Same here. compare_executable is what catches
    // this substitution.
    let mut issuer = issuer();
    let policy = allow_all_policy();
    let request = ComputeRequest {
        resource: resource("gpu-0"),
        action: Action::Compute,
    };
    let origin = ProvenanceRecord::new(context(42, 100, 1000), request.clone());
    let now = MonotonicTime::from_nanos(0);
    let lease = issuer
        .issue(&policy, origin, now, std::time::Duration::from_secs(30))
        .unwrap();

    let mut swapped = context(42, 100, 1000);
    swapped.workload.executable_path = Evidence::Present {
        value: "/usr/bin/a-different-tool".into(),
        source: EvidenceSource::KernelObserved,
    };
    let presented = ProvenanceRecord::new(swapped, request);
    assert_eq!(
        issuer.validate(&lease, &presented, now),
        LeaseValidity::ExecutableMismatch
    );
}

#[test]
fn lease_issue_fails_when_policy_denies() {
    let mut issuer = issuer();
    let policy = allow_all_policy();
    // uid 2000 doesn't match the allow-all-for-test policy's uid-1000 rule.
    let origin = ProvenanceRecord::new(
        context(42, 100, 2000),
        ComputeRequest {
            resource: resource("gpu-0"),
            action: Action::Compute,
        },
    );
    let result = issuer.issue(
        &policy,
        origin,
        MonotonicTime::from_nanos(0),
        std::time::Duration::from_secs(30),
    );
    assert!(result.is_err());
}
