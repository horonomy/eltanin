//! Golden JSON coverage for [`AuditRecord`] (F-M1-006's consumer,
//! F-M1-009, HORO-824). Locks the schema's key surface: a new upstream
//! field on `ExecutionContext`/`WorkloadIdentity` shows up here as a
//! diff, not silently.

use std::time::Duration;

use eltanin_audit::record::{
    AuditEventId, AuditRecord, RecordedDelegation, RecordedOperation, RecordedOutcome,
    RecordedPeer, RecordedPeerConsistency, RecordedPeerCredential, RecordedRequest, WallClockTime,
};
use eltanin_core::delegation::ExceededBound;
use eltanin_core::envelope::Versioned;
use eltanin_core::identity::{Evidence, EvidenceSource, ExecutionContext, WorkloadIdentity};
use eltanin_core::lease::{IssuerInstanceId, LeaseId, MonotonicTime};
use eltanin_core::resource::{Action, ResourceIdentity, ResourceKind, ResourceVendor};
use eltanin_protocol::response::{AgentResponse, DenialReason};

fn observed() -> ExecutionContext {
    ExecutionContext {
        workload: WorkloadIdentity {
            pid: 4242,
            process_start: Evidence::Present {
                value: eltanin_core::identity::ProcessStartToken(9999),
                source: EvidenceSource::KernelObserved,
            },
            uid: Evidence::Present {
                value: 1000,
                source: EvidenceSource::KernelObserved,
            },
            gid: Evidence::Unsupported,
            executable_path: Evidence::Present {
                value: "/usr/bin/trusted-tool".to_string(),
                source: EvidenceSource::KernelObserved,
            },
            executable_hash: Evidence::Unsupported,
            ancestry: Vec::new(),
        },
        cgroup_path: Evidence::Unsupported,
        namespace_hint: Evidence::Unsupported,
        container_hint: Evidence::Unsupported,
        session_origin: Evidence::Unsupported,
    }
}

fn resource() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-0".to_string(),
    }
}

#[test]
fn a_denied_request_lease_record_round_trips_through_json() {
    let record = AuditRecord {
        event_id: AuditEventId {
            instance: IssuerInstanceId::new("agent-pid-1-start-1"),
            sequence: 0,
        },
        recorded_at: WallClockTime {
            unix_secs: 1_700_000_000,
            nanos: 0,
        },
        operation: RecordedOperation::RequestLease,
        requested: RecordedRequest::RequestLease {
            resource: resource(),
            action: Action::Compute,
        },
        peer: RecordedPeer {
            credential: RecordedPeerCredential {
                pid: 4242,
                effective_uid: 1000,
                effective_gid: 1000,
            },
            consistency: RecordedPeerConsistency::Consistent,
            observed: observed(),
        },
        outcome: RecordedOutcome::PeerNotAuthorizable,
        response: AgentResponse::LeaseDenied {
            reason: DenialReason::IndeterminateEvidence,
        },
    };

    let envelope = Versioned::current(record.clone());
    let json = serde_json::to_string(&envelope).unwrap();
    let decoded: Versioned<AuditRecord> = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.payload, record);
    assert_eq!(
        decoded.version,
        eltanin_core::envelope::DOMAIN_SCHEMA_VERSION
    );
}

#[test]
fn a_granted_lease_record_exposes_its_lease_id_via_the_helper() {
    let lease_id = LeaseId {
        issuer: IssuerInstanceId::new("agent-pid-1-start-1"),
        sequence: 7,
    };
    let record = AuditRecord {
        event_id: AuditEventId {
            instance: IssuerInstanceId::new("agent-pid-1-start-1"),
            sequence: 1,
        },
        recorded_at: WallClockTime {
            unix_secs: 0,
            nanos: 0,
        },
        operation: RecordedOperation::RequestLease,
        requested: RecordedRequest::RequestLease {
            resource: resource(),
            action: Action::Compute,
        },
        peer: RecordedPeer {
            credential: RecordedPeerCredential {
                pid: 4242,
                effective_uid: 1000,
                effective_gid: 1000,
            },
            consistency: RecordedPeerConsistency::Consistent,
            observed: observed(),
        },
        outcome: RecordedOutcome::Granted {
            lease_id: lease_id.clone(),
            expires_at: MonotonicTime::from_nanos(1_000_000_000),
        },
        response: AgentResponse::LeaseGranted {
            lease: eltanin_protocol::response::LeaseView {
                lease_id: lease_id.clone(),
                remaining: Duration::from_secs(60),
            },
        },
    };

    assert_eq!(record.lease_id(), Some(&lease_id));
}

#[test]
fn a_release_records_lease_id_comes_from_the_request_not_the_outcome() {
    let lease_id = LeaseId {
        issuer: IssuerInstanceId::new("agent-pid-1-start-1"),
        sequence: 7,
    };
    let record = AuditRecord {
        event_id: AuditEventId {
            instance: IssuerInstanceId::new("agent-pid-1-start-1"),
            sequence: 2,
        },
        recorded_at: WallClockTime {
            unix_secs: 0,
            nanos: 0,
        },
        operation: RecordedOperation::ReleaseLease,
        requested: RecordedRequest::ReleaseLease {
            lease_id: lease_id.clone(),
        },
        peer: RecordedPeer {
            credential: RecordedPeerCredential {
                pid: 4242,
                effective_uid: 1000,
                effective_gid: 1000,
            },
            consistency: RecordedPeerConsistency::Consistent,
            observed: observed(),
        },
        outcome: RecordedOutcome::Released {
            revocation: eltanin_core::lease::RevocationOutcome::Revoked,
            backend: None,
        },
        response: AgentResponse::LeaseReleased {
            outcome: eltanin_protocol::response::ReleaseOutcome::Released,
        },
    };

    assert_eq!(record.lease_id(), Some(&lease_id));
}

/// HORO-793: `GrantedByDelegation` round-trips through JSON and
/// `AuditRecord::lease_id()` links it the same way `Granted` already
/// does — this is the extension named explicitly in the ticket, not an
/// incidental side effect.
#[test]
fn a_granted_by_delegation_record_round_trips_and_exposes_its_lease_id() {
    let lease_id = LeaseId {
        issuer: IssuerInstanceId::new("agent-pid-1-start-1"),
        sequence: 9,
    };
    let parent_lease = LeaseId {
        issuer: IssuerInstanceId::new("agent-pid-1-start-1"),
        sequence: 3,
    };
    let record = AuditRecord {
        event_id: AuditEventId {
            instance: IssuerInstanceId::new("agent-pid-1-start-1"),
            sequence: 3,
        },
        recorded_at: WallClockTime {
            unix_secs: 0,
            nanos: 0,
        },
        operation: RecordedOperation::RequestLease,
        requested: RecordedRequest::RequestLease {
            resource: resource(),
            action: Action::Compute,
        },
        peer: RecordedPeer {
            credential: RecordedPeerCredential {
                pid: 9000,
                effective_uid: 1000,
                effective_gid: 1000,
            },
            consistency: RecordedPeerConsistency::Consistent,
            observed: observed(),
        },
        outcome: RecordedOutcome::GrantedByDelegation {
            lease_id: lease_id.clone(),
            expires_at: MonotonicTime::from_nanos(1_000_000_000),
            delegation: RecordedDelegation {
                parent_lease: parent_lease.clone(),
                depth: 1,
                holder_pid: 100,
            },
        },
        response: AgentResponse::LeaseGranted {
            lease: eltanin_protocol::response::LeaseView {
                lease_id: lease_id.clone(),
                remaining: Duration::from_secs(60),
            },
        },
    };

    let envelope = Versioned::current(record.clone());
    let json = serde_json::to_string(&envelope).unwrap();
    let decoded: Versioned<AuditRecord> = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.payload, record);
    assert_eq!(record.lease_id(), Some(&lease_id));
    assert!(json.contains("\"parent_lease\""));
    assert!(json.contains("\"depth\":1"));
}

#[test]
fn a_delegation_refused_record_round_trips_through_json() {
    let record = AuditRecord {
        event_id: AuditEventId {
            instance: IssuerInstanceId::new("agent-pid-1-start-1"),
            sequence: 4,
        },
        recorded_at: WallClockTime {
            unix_secs: 0,
            nanos: 0,
        },
        operation: RecordedOperation::RequestLease,
        requested: RecordedRequest::RequestLease {
            resource: resource(),
            action: Action::Compute,
        },
        peer: RecordedPeer {
            credential: RecordedPeerCredential {
                pid: 9000,
                effective_uid: 1000,
                effective_gid: 1000,
            },
            consistency: RecordedPeerConsistency::Consistent,
            observed: observed(),
        },
        outcome: RecordedOutcome::DelegationRefused {
            exceeded: std::collections::BTreeSet::from([ExceededBound::AncestryLinkage]),
        },
        response: AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired,
        },
    };

    let envelope = Versioned::current(record.clone());
    let json = serde_json::to_string(&envelope).unwrap();
    let decoded: Versioned<AuditRecord> = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.payload, record);
    assert_eq!(record.lease_id(), None);
}

#[test]
fn a_delegation_indeterminate_record_round_trips_through_json() {
    let record = AuditRecord {
        event_id: AuditEventId {
            instance: IssuerInstanceId::new("agent-pid-1-start-1"),
            sequence: 5,
        },
        recorded_at: WallClockTime {
            unix_secs: 0,
            nanos: 0,
        },
        operation: RecordedOperation::RequestLease,
        requested: RecordedRequest::RequestLease {
            resource: resource(),
            action: Action::Compute,
        },
        peer: RecordedPeer {
            credential: RecordedPeerCredential {
                pid: 9000,
                effective_uid: 1000,
                effective_gid: 1000,
            },
            consistency: RecordedPeerConsistency::Consistent,
            observed: observed(),
        },
        outcome: RecordedOutcome::DelegationIndeterminate {
            reason: "grant holder liveness could not be confirmed".to_string(),
        },
        response: AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired,
        },
    };

    let envelope = Versioned::current(record.clone());
    let json = serde_json::to_string(&envelope).unwrap();
    let decoded: Versioned<AuditRecord> = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.payload, record);
}
