//! Shared test support for `eltanin-dogfood` integration tests
//! (HORO-1376).
#![allow(dead_code)]

use eltanin_audit::explain::LogScan;
use eltanin_audit::record::{
    AuditEventId, AuditRecord, RecordedEnforcementMode, RecordedOperation, RecordedOutcome,
    RecordedPeer, RecordedPeerConsistency, RecordedPeerCredential, RecordedRequest, WallClockTime,
};
use eltanin_core::identity::{Evidence, ExecutionContext, WorkloadIdentity};
use eltanin_core::lease::{IssuerInstanceId, LeaseId, MonotonicTime};
use eltanin_core::resource::{Action, ResourceIdentity, ResourceKind, ResourceVendor};
use eltanin_core::session::SessionId;
use eltanin_protocol::response::{AgentResponse, DenialReason};

pub fn peer(pid: u32) -> RecordedPeer {
    RecordedPeer {
        credential: RecordedPeerCredential {
            pid,
            effective_uid: 1000,
            effective_gid: 1000,
        },
        consistency: RecordedPeerConsistency::Consistent,
        observed: ExecutionContext {
            workload: WorkloadIdentity {
                pid,
                process_start: Evidence::Unsupported,
                uid: Evidence::Unsupported,
                gid: Evidence::Unsupported,
                executable_path: Evidence::Unsupported,
                executable_hash: Evidence::Unsupported,
                ancestry: Vec::new(),
            },
            cgroup_path: Evidence::Unsupported,
            namespace_hint: Evidence::Unsupported,
            container_hint: Evidence::Unsupported,
            session_origin: Evidence::Unsupported,
        },
    }
}

pub fn resource() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-0".to_string(),
    }
}

pub fn event_id(instance: &str, sequence: u64) -> AuditEventId {
    AuditEventId {
        instance: IssuerInstanceId::new(instance),
        sequence,
    }
}

pub fn session_id(instance: &str, sequence: u64) -> SessionId {
    SessionId {
        issuer: IssuerInstanceId::new(instance),
        sequence,
    }
}

/// A minimal, otherwise-valid `AuditRecord` — callers override the
/// fields their test cares about (`mode`, `outcome`, `session`) and
/// leave everything else at this fixture's defaults.
pub fn base_record(
    instance: &str,
    sequence: u64,
    mode: RecordedEnforcementMode,
    outcome: RecordedOutcome,
    session: Option<SessionId>,
) -> AuditRecord {
    AuditRecord {
        event_id: event_id(instance, sequence),
        recorded_at: WallClockTime {
            unix_secs: 1_790_244_903,
            nanos: 0,
        },
        operation: RecordedOperation::RequestLease,
        requested: RecordedRequest::RequestLease {
            resource: resource(),
            action: Action::Compute,
        },
        peer: peer(1),
        outcome,
        response: AgentResponse::LeaseDenied {
            reason: DenialReason::IndeterminateEvidence,
        },
        mode,
        session,
    }
}

pub fn would_grant(instance: &str, sequence: u64) -> RecordedOutcome {
    RecordedOutcome::WouldGrant {
        lease_id: LeaseId {
            issuer: IssuerInstanceId::new(instance),
            sequence,
        },
        expires_at: MonotonicTime::from_nanos(1_000_000_000),
    }
}

pub fn granted(instance: &str, sequence: u64) -> RecordedOutcome {
    RecordedOutcome::Granted {
        lease_id: LeaseId {
            issuer: IssuerInstanceId::new(instance),
            sequence,
        },
        expires_at: MonotonicTime::from_nanos(1_000_000_000),
    }
}

pub fn empty_scan() -> LogScan {
    LogScan::default()
}
