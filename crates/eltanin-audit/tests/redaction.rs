//! Redaction/data-minimization regression coverage (F-M1-009, HORO-824).
//!
//! The structural argument: this crate's evidence source
//! (`ExecutionContext`/`WorkloadIdentity`) never touches a workload's
//! argv, environment, or prompts — `eltanin-linux` only ever reads
//! `/proc/<pid>/{stat,status,exe,cgroup}`, never `cmdline` or `environ`
//! — so nothing shaped like a secret can appear in a record via that
//! path in the first place. These tests instead pin the concrete,
//! testable claims: no authority-bearing value serializes into a
//! record, and an `Evidence::Missing { reason }` string containing a
//! newline does not break one-record-per-line framing.

use eltanin_audit::record::{
    AuditEventId, AuditRecord, RecordedOperation, RecordedOutcome, RecordedPeer,
    RecordedPeerConsistency, RecordedPeerCredential, RecordedRequest, WallClockTime,
};
use eltanin_core::envelope::Versioned;
use eltanin_core::identity::{Evidence, EvidenceSource, ExecutionContext, WorkloadIdentity};
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::resource::{Action, ResourceIdentity, ResourceKind, ResourceVendor};
use eltanin_protocol::response::{AgentResponse, DenialReason};

fn base_record(observed: ExecutionContext) -> AuditRecord {
    AuditRecord {
        event_id: AuditEventId {
            instance: IssuerInstanceId::new("instance"),
            sequence: 0,
        },
        recorded_at: WallClockTime {
            unix_secs: 0,
            nanos: 0,
        },
        operation: RecordedOperation::RequestLease,
        requested: RecordedRequest::RequestLease {
            resource: ResourceIdentity {
                vendor: ResourceVendor::fake(),
                kind: ResourceKind::gpu(),
                local_id: "gpu-0".to_string(),
            },
            action: Action::Compute,
        },
        peer: RecordedPeer {
            credential: RecordedPeerCredential {
                pid: 1,
                effective_uid: 1000,
                effective_gid: 1000,
            },
            consistency: RecordedPeerConsistency::Consistent,
            observed,
        },
        outcome: RecordedOutcome::PeerNotAuthorizable,
        response: AgentResponse::LeaseDenied {
            reason: DenialReason::IndeterminateEvidence,
        },
    }
}

fn workload_with(executable_path: Evidence<String>) -> WorkloadIdentity {
    WorkloadIdentity {
        pid: 1,
        process_start: Evidence::Unsupported,
        uid: Evidence::Unsupported,
        gid: Evidence::Unsupported,
        executable_path,
        executable_hash: Evidence::Unsupported,
        ancestry: Vec::new(),
    }
}

#[test]
fn a_missing_evidence_reason_containing_a_newline_stays_one_json_line() {
    let workload = workload_with(Evidence::Missing {
        reason: "readlink failed\nsecond line pretending to be a new record".to_string(),
    });
    let record = base_record(ExecutionContext {
        workload,
        cgroup_path: Evidence::Unsupported,
        namespace_hint: Evidence::Unsupported,
        container_hint: Evidence::Unsupported,
        session_origin: Evidence::Unsupported,
    });

    let json = serde_json::to_string(&Versioned::current(record)).unwrap();
    assert_eq!(
        json.lines().count(),
        1,
        "a newline inside a field must be escaped, never break line framing: {json}"
    );
    assert!(
        json.contains("\\n"),
        "expected the newline to be JSON-escaped"
    );
}

#[test]
fn executable_path_evidence_is_recorded_verbatim_not_stripped() {
    // The redaction contract (docs/product/SECURITY_MODEL.md) is
    // specifically about not recording lease material or workload
    // argv/env — it is not a general PII scrub. Kernel-derived evidence
    // like executable_path is exactly what this feature exists to
    // preserve, so it must round-trip unmodified, not be dropped or
    // masked by an over-eager redaction pass.
    let workload = workload_with(Evidence::Present {
        value: "/usr/bin/trusted-tool".to_string(),
        source: EvidenceSource::KernelObserved,
    });
    let record = base_record(ExecutionContext {
        workload,
        cgroup_path: Evidence::Unsupported,
        namespace_hint: Evidence::Unsupported,
        container_hint: Evidence::Unsupported,
        session_origin: Evidence::Unsupported,
    });
    let json = serde_json::to_string(&Versioned::current(record.clone())).unwrap();
    let decoded: Versioned<AuditRecord> = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.payload, record);
    assert!(json.contains("/usr/bin/trusted-tool"));
}
