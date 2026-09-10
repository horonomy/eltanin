//! Golden and reproducibility tests for `ProvenanceRecord` (F-M1-003,
//! HORO-833). Complements `identity_golden.rs`/`resource_golden.rs`'s
//! pattern.

use eltanin_core::identity::{Evidence, EvidenceSource, ExecutionContext, WorkloadIdentity};
use eltanin_core::provenance::ProvenanceRecord;
use eltanin_core::resource::{
    Action, ComputeRequest, ResourceIdentity, ResourceKind, ResourceVendor,
};

fn sample_context() -> ExecutionContext {
    ExecutionContext {
        workload: WorkloadIdentity {
            pid: 42,
            process_start: Evidence::Present {
                value: eltanin_core::identity::ProcessStartToken(100),
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
                value: "/usr/bin/example".into(),
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
        session_origin: Evidence::Missing {
            reason: "no session manager detected".into(),
        },
    }
}

fn sample_request() -> ComputeRequest {
    ComputeRequest {
        resource: ResourceIdentity {
            vendor: ResourceVendor::fake(),
            kind: ResourceKind::gpu(),
            local_id: "gpu-0".into(),
        },
        action: Action::Compute,
    }
}

#[test]
fn provenance_record_round_trips_through_json() {
    let original = ProvenanceRecord::new(sample_context(), sample_request());
    let json = serde_json::to_string(&original).unwrap();
    let decoded: ProvenanceRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original, "provenance fixture must be reproducible");
}

#[test]
fn provenance_record_preserves_missing_and_unsupported_evidence_verbatim() {
    // Reconstructing "why compute was allowed/denied" (F-M1-009) needs
    // the absence of evidence to survive the round trip exactly as
    // observed — a record must never fabricate presence for a field
    // that was actually Missing or Unsupported.
    let record = ProvenanceRecord::new(sample_context(), sample_request());
    let json = serde_json::to_string(&record).unwrap();
    let decoded: ProvenanceRecord = serde_json::from_str(&json).unwrap();
    assert!(!decoded.context.namespace_hint.is_present());
    assert!(matches!(
        decoded.context.session_origin,
        Evidence::Missing { .. }
    ));
    assert_eq!(
        decoded.context.workload.executable_hash,
        record.context.workload.executable_hash
    );
}

#[test]
fn provenance_record_links_the_exact_request_it_was_built_with() {
    // A provenance record must not silently substitute a different
    // resource/action than the one actually requested — audit
    // reconstruction depends on this link being exact.
    let request = sample_request();
    let record = ProvenanceRecord::new(sample_context(), request.clone());
    assert_eq!(record.request, request);
}
