//! `ComputeLease` restart/replay coverage (F-M1-005, HORO-836).

use std::time::Duration;

use eltanin_core::identity::{
    Evidence, EvidenceSource, ExecutionContext, ProcessStartToken, WorkloadIdentity,
};
use eltanin_core::lease::{
    IssuerInstanceId, LeaseIssuer, LeaseValidity, MonotonicTime, RevocationOutcome,
};
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

fn context_with(pid: u32, start: u64) -> ExecutionContext {
    ExecutionContext {
        workload: WorkloadIdentity {
            pid,
            process_start: Evidence::Present {
                value: ProcessStartToken(start),
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
        id: PolicyId::new("allow-all-for-test"),
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

fn request() -> ComputeRequest {
    ComputeRequest {
        resource: resource(),
        action: Action::Compute,
    }
}

#[test]
fn lease_from_a_prior_issuer_instance_is_rejected_as_foreign() {
    // Simulates an agent restart: a new LeaseIssuer with a new
    // IssuerInstanceId cannot validate a lease minted by the old one,
    // even though nothing about the workload/resource/action changed.
    let mut issuer_before_restart = LeaseIssuer::new(
        IssuerInstanceId::new("agent-pid-100-start-5"),
        Duration::from_secs(60),
    );
    let policy = allow_all_policy();
    let origin = ProvenanceRecord::new(context_with(42, 100), request());
    let lease = issuer_before_restart
        .issue(
            &policy,
            origin.clone(),
            MonotonicTime::from_nanos(0),
            Duration::from_secs(30),
        )
        .unwrap();

    let issuer_after_restart = LeaseIssuer::new(
        IssuerInstanceId::new("agent-pid-100-start-6"),
        Duration::from_secs(60),
    );
    assert_eq!(
        issuer_after_restart.validate(&lease, &origin, MonotonicTime::from_nanos(0)),
        LeaseValidity::ForeignIssuer {
            issued_by: IssuerInstanceId::new("agent-pid-100-start-5")
        }
    );
}

#[test]
fn workload_restart_with_a_new_process_start_token_is_a_mismatch_not_valid() {
    let mut issuer = LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(60));
    let policy = allow_all_policy();
    let original = ProvenanceRecord::new(context_with(42, 100), request());
    let lease = issuer
        .issue(
            &policy,
            original,
            MonotonicTime::from_nanos(0),
            Duration::from_secs(30),
        )
        .unwrap();

    // Same pid, but a different process_start token — the process was
    // restarted (or the pid was reused) between issue and validation.
    let restarted = ProvenanceRecord::new(context_with(42, 200), request());
    assert_eq!(
        issuer.validate(&lease, &restarted, MonotonicTime::from_nanos(0)),
        LeaseValidity::WorkloadMismatch
    );
}

#[test]
fn indeterminate_workload_evidence_is_neither_valid_nor_a_confirmed_mismatch() {
    let mut issuer = LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(60));
    let policy = allow_all_policy();
    let original = ProvenanceRecord::new(context_with(42, 100), request());
    let lease = issuer
        .issue(
            &policy,
            original,
            MonotonicTime::from_nanos(0),
            Duration::from_secs(30),
        )
        .unwrap();

    let mut presented_context = context_with(42, 100);
    presented_context.workload.process_start = Evidence::Missing {
        reason: "permission denied".into(),
    };
    let presented = ProvenanceRecord::new(presented_context, request());

    let validity = issuer.validate(&lease, &presented, MonotonicTime::from_nanos(0));
    assert_eq!(validity, LeaseValidity::WorkloadIndeterminate);
    assert!(!validity.is_valid());
}

#[test]
fn revoked_lease_is_rejected_even_when_otherwise_still_valid() {
    let mut issuer = LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(60));
    let policy = allow_all_policy();
    let origin = ProvenanceRecord::new(context_with(42, 100), request());
    let lease = issuer
        .issue(
            &policy,
            origin.clone(),
            MonotonicTime::from_nanos(0),
            Duration::from_secs(30),
        )
        .unwrap();

    assert_eq!(issuer.revoke(lease.id()), RevocationOutcome::Revoked);
    assert_eq!(
        issuer.validate(&lease, &origin, MonotonicTime::from_nanos(0)),
        LeaseValidity::Revoked
    );
}

#[test]
fn revoking_an_already_revoked_lease_reports_already_revoked() {
    let mut issuer = LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(60));
    let policy = allow_all_policy();
    let origin = ProvenanceRecord::new(context_with(42, 100), request());
    let lease = issuer
        .issue(
            &policy,
            origin,
            MonotonicTime::from_nanos(0),
            Duration::from_secs(30),
        )
        .unwrap();

    assert_eq!(issuer.revoke(lease.id()), RevocationOutcome::Revoked);
    assert_eq!(issuer.revoke(lease.id()), RevocationOutcome::AlreadyRevoked);
}

#[test]
fn revoking_a_lease_from_a_foreign_issuer_is_reported_as_foreign() {
    let mut issuer_a = LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(60));
    let issuer_b = LeaseIssuer::new(IssuerInstanceId::new("issuer-b"), Duration::from_secs(60));
    let policy = allow_all_policy();
    let origin = ProvenanceRecord::new(context_with(42, 100), request());
    let lease = issuer_a
        .issue(
            &policy,
            origin,
            MonotonicTime::from_nanos(0),
            Duration::from_secs(30),
        )
        .unwrap();

    let mut issuer_b = issuer_b;
    assert_eq!(
        issuer_b.revoke(lease.id()),
        RevocationOutcome::ForeignIssuer
    );
}

#[test]
fn revoking_a_lease_id_that_was_never_issued_is_reported_as_not_issued() {
    use eltanin_core::lease::LeaseId;

    let mut issuer = LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(60));
    let never_issued = LeaseId {
        issuer: IssuerInstanceId::new("issuer-a"),
        sequence: 999,
    };
    assert_eq!(issuer.revoke(&never_issued), RevocationOutcome::NotIssued);
}
