//! `ComputeLease` renewal-boundary coverage (F-M1-005, HORO-837).
//!
//! There is no `renew`/`extend` method anywhere on [`ComputeLease`] or
//! [`LeaseIssuer`] (see `lease.rs` module docs, "Scope narrowing is
//! structural"). "Renewal" is always a fresh [`LeaseIssuer::issue`] over
//! freshly observed context — a new authorization act, never a
//! continuation of an existing one. These tests pin the *boundary* of
//! that claim: what a caller gets back when they do the only thing this
//! module allows in place of renewal.

use std::time::Duration;

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

fn resource() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-0".into(),
    }
}

fn context() -> ExecutionContext {
    ExecutionContext {
        workload: WorkloadIdentity {
            pid: 42,
            process_start: Evidence::Present {
                value: ProcessStartToken(100),
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

fn origin() -> ProvenanceRecord {
    ProvenanceRecord::new(
        context(),
        ComputeRequest {
            resource: resource(),
            action: Action::Compute,
        },
    )
}

#[test]
fn re_issuing_after_expiry_mints_a_distinct_lease_id_not_a_continuation() {
    // "Renewal" is a fresh issue, so the "renewed" lease must carry its
    // own identity — never the expired lease's id with a pushed-out
    // expiry, which would be an extension in disguise.
    let mut issuer = LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(3600));
    let policy = allow_all_policy();

    let first = issuer
        .issue(
            &policy,
            origin(),
            MonotonicTime::from_nanos(0),
            Duration::from_secs(30),
        )
        .unwrap();
    assert_eq!(
        issuer.validate(&first, &origin(), first.expires_at()),
        LeaseValidity::Expired {
            expired_at: first.expires_at()
        }
    );

    let renewed = issuer
        .issue(
            &policy,
            origin(),
            first.expires_at(),
            Duration::from_secs(30),
        )
        .unwrap();

    assert_ne!(
        first.id(),
        renewed.id(),
        "renewal must not reuse the expired lease's id"
    );
    assert!(issuer
        .validate(&renewed, &origin(), first.expires_at())
        .is_valid());
}

#[test]
fn the_expired_lease_stays_expired_after_a_sibling_is_renewed() {
    // Issuing a fresh lease must not resurrect an earlier one that shares
    // no state with it beyond the issuer — proves renewal is additive,
    // not a mutation of prior state.
    let mut issuer = LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(3600));
    let policy = allow_all_policy();

    let first = issuer
        .issue(
            &policy,
            origin(),
            MonotonicTime::from_nanos(0),
            Duration::from_secs(30),
        )
        .unwrap();
    let now_at_expiry = first.expires_at();

    let _renewed = issuer
        .issue(&policy, origin(), now_at_expiry, Duration::from_secs(30))
        .unwrap();

    assert_eq!(
        issuer.validate(&first, &origin(), now_at_expiry),
        LeaseValidity::Expired {
            expired_at: first.expires_at()
        }
    );
}

#[test]
fn revoking_a_renewed_lease_does_not_revoke_the_lease_it_replaced() {
    // Confirms the two leases are genuinely independent identities: a
    // revocation targets one LeaseId only, never "the latest lease for
    // this workload."
    let mut issuer = LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(3600));
    let policy = allow_all_policy();

    let first = issuer
        .issue(
            &policy,
            origin(),
            MonotonicTime::from_nanos(0),
            Duration::from_secs(299),
        )
        .unwrap();
    let renewed = issuer
        .issue(
            &policy,
            origin(),
            MonotonicTime::from_nanos(1),
            Duration::from_secs(299),
        )
        .unwrap();

    issuer.revoke(renewed.id());

    assert!(issuer
        .validate(&first, &origin(), MonotonicTime::from_nanos(2))
        .is_valid());
}
