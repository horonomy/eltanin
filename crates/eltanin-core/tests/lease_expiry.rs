//! `ComputeLease` expiry and narrowing coverage (F-M1-005, HORO-836).

use std::time::Duration;

use eltanin_core::identity::{
    Evidence, EvidenceSource, ExecutionContext, ProcessStartToken, WorkloadIdentity,
};
use eltanin_core::lease::{
    IssuerInstanceId, LeaseError, LeaseIssuer, LeaseValidity, MonotonicTime,
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

fn issuer() -> LeaseIssuer {
    LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(3600))
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
fn lease_is_valid_strictly_before_expiry() {
    let mut issuer = issuer();
    let policy = allow_all_policy();
    let issued_at = MonotonicTime::from_nanos(1_000_000_000);
    let ttl = Duration::from_secs(30);
    let lease = issuer.issue(&policy, origin(), issued_at, ttl).unwrap();

    let ttl_nanos = u64::try_from(ttl.as_nanos()).unwrap();
    let just_before_expiry = MonotonicTime::from_nanos(issued_at.as_nanos() + ttl_nanos - 1);
    let validity = issuer.validate(&lease, &origin(), just_before_expiry);
    assert!(validity.is_valid(), "expected valid, got {validity:?}");
}

#[test]
fn lease_is_expired_at_the_exact_expiry_instant() {
    // Expiry is inclusive of the boundary: `now >= expires_at` is
    // Expired, not Valid — a lease's last valid instant is strictly
    // before its expiry, never including it.
    let mut issuer = issuer();
    let policy = allow_all_policy();
    let issued_at = MonotonicTime::from_nanos(0);
    let ttl = Duration::from_secs(30);
    let lease = issuer.issue(&policy, origin(), issued_at, ttl).unwrap();

    let at_expiry = lease.expires_at();
    assert_eq!(
        issuer.validate(&lease, &origin(), at_expiry),
        LeaseValidity::Expired {
            expired_at: lease.expires_at()
        }
    );
}

#[test]
fn lease_is_expired_after_expiry_even_with_identical_matching_context() {
    // The core invariant: "expired lease is invalid even if
    // workload/path/UID still looks familiar." Everything about the
    // presented context matches exactly — only time has moved past
    // expiry.
    let mut issuer = issuer();
    let policy = allow_all_policy();
    let issued_at = MonotonicTime::from_nanos(0);
    let ttl = Duration::from_secs(30);
    let lease = issuer.issue(&policy, origin(), issued_at, ttl).unwrap();

    let long_after = MonotonicTime::from_nanos(lease.expires_at().as_nanos() + 1_000_000_000);
    assert_eq!(
        issuer.validate(&lease, &origin(), long_after),
        LeaseValidity::Expired {
            expired_at: lease.expires_at()
        }
    );
}

#[test]
fn issue_rejects_zero_ttl() {
    let mut issuer = issuer();
    let policy = allow_all_policy();
    let result = issuer.issue(
        &policy,
        origin(),
        MonotonicTime::from_nanos(0),
        Duration::ZERO,
    );
    assert!(result.is_err());
}

#[test]
fn issue_rejects_ttl_exceeding_issuer_maximum() {
    let mut issuer = LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(10));
    let policy = allow_all_policy();
    let result = issuer.issue(
        &policy,
        origin(),
        MonotonicTime::from_nanos(0),
        Duration::from_secs(11),
    );
    assert!(result.is_err());
}

#[test]
fn issue_accepts_ttl_exactly_at_the_issuer_maximum() {
    // The boundary itself: issue() rejects `ttl > max_ttl`, so `ttl ==
    // max_ttl` must succeed. Pins the boundary against an off-by-one
    // (e.g. `>=` instead of `>`) that the exceeds-maximum test alone
    // cannot catch.
    let mut issuer = LeaseIssuer::new(IssuerInstanceId::new("issuer-a"), Duration::from_secs(10));
    let policy = allow_all_policy();
    let result = issuer.issue(
        &policy,
        origin(),
        MonotonicTime::from_nanos(0),
        Duration::from_secs(10),
    );
    assert!(result.is_ok());
}

#[test]
fn issue_rejects_an_expiry_that_would_overflow_monotonic_time() {
    let mut issuer = issuer();
    let policy = allow_all_policy();
    let result = issuer.issue(
        &policy,
        origin(),
        MonotonicTime::from_nanos(u64::MAX),
        Duration::from_nanos(1),
    );
    assert_eq!(result, Err(LeaseError::ExpiryOverflow));
}

#[test]
fn narrow_expiry_to_an_earlier_instant_shortens_the_lease() {
    let mut issuer = issuer();
    let policy = allow_all_policy();
    let issued_at = MonotonicTime::from_nanos(0);
    let lease = issuer
        .issue(&policy, origin(), issued_at, Duration::from_secs(60))
        .unwrap();

    let narrowed = lease.narrow_expiry(MonotonicTime::from_nanos(10));
    assert_eq!(narrowed.expires_at(), MonotonicTime::from_nanos(10));
}

#[test]
fn narrow_expiry_to_a_later_instant_is_a_no_op() {
    // Narrowing to a *later* instant must never extend the lease — this
    // is what makes "caller cannot broaden scope" structural rather than
    // merely a convention narrow_expiry happens to follow today.
    let mut issuer = issuer();
    let policy = allow_all_policy();
    let issued_at = MonotonicTime::from_nanos(0);
    let ttl = Duration::from_secs(30);
    let lease = issuer.issue(&policy, origin(), issued_at, ttl).unwrap();
    let original_expiry = lease.expires_at();

    let attempted_widen = lease.narrow_expiry(MonotonicTime::from_nanos(
        original_expiry.as_nanos() + 1_000_000,
    ));
    assert_eq!(attempted_widen.expires_at(), original_expiry);
}
