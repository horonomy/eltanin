//! Explain selector coverage: event/lease/pid selection, grant↔release
//! correlation, unreadable-line and sequence-gap handling (F-M1-009,
//! HORO-824).

use std::io::Write;

use eltanin_audit::explain::{read_log, select, SelectionResult, Selector, UnreadableReason};
use eltanin_audit::sink::{AuditEntry, AuditFileSink};
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::resource::{Action, ResourceIdentity, ResourceKind, ResourceVendor};
use eltanin_protocol::response::{AgentResponse, DenialReason};

mod support;
use support::{fixed_clock, peer, temp_log_path};

fn resource() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-0".to_string(),
    }
}

fn status_entry() -> AuditEntry {
    AuditEntry {
        operation: eltanin_audit::record::RecordedOperation::AgentStatus,
        requested: eltanin_audit::record::RecordedRequest::AgentStatus,
        peer: peer(4242),
        outcome: eltanin_audit::record::RecordedOutcome::StatusReported,
        response: AgentResponse::Status {
            status: eltanin_protocol::response::AgentStatusView {
                protocol_version: 1,
            },
        },
    }
}

fn denied_entry(pid: u32) -> AuditEntry {
    AuditEntry {
        operation: eltanin_audit::record::RecordedOperation::RequestLease,
        requested: eltanin_audit::record::RecordedRequest::RequestLease {
            resource: resource(),
            action: Action::Compute,
        },
        peer: peer(pid),
        outcome: eltanin_audit::record::RecordedOutcome::PeerNotAuthorizable,
        response: AgentResponse::LeaseDenied {
            reason: DenialReason::IndeterminateEvidence,
        },
    }
}

#[test]
fn selecting_by_event_id_finds_the_exact_record() {
    let path = temp_log_path("select-event");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap();
    let id0 = sink.append(status_entry()).unwrap();
    let _id1 = sink.append(status_entry()).unwrap();

    let scan = read_log(&path).unwrap();
    match select(&scan, &Selector::Event(id0.clone())) {
        SelectionResult::Found(records) => {
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].event_id, id0);
        }
        other => panic!("expected Found, got {other:?}"),
    }
}

#[test]
fn selecting_by_pid_returns_every_match_in_file_order() {
    let path = temp_log_path("select-pid");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap();
    sink.append(denied_entry(4242)).unwrap();
    sink.append(denied_entry(9999)).unwrap();
    sink.append(denied_entry(4242)).unwrap();

    let scan = read_log(&path).unwrap();
    match select(&scan, &Selector::Pid(4242)) {
        SelectionResult::Found(records) => assert_eq!(records.len(), 2),
        other => panic!("expected Found, got {other:?}"),
    }
}

#[test]
fn an_unknown_id_that_is_outside_any_observed_gap_is_not_found() {
    let path = temp_log_path("select-not-found");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap();
    sink.append(status_entry()).unwrap();

    let scan = read_log(&path).unwrap();
    let unknown = eltanin_audit::record::AuditEventId {
        instance: IssuerInstanceId::new("i"),
        sequence: 999,
    };
    assert_eq!(
        select(&scan, &Selector::Event(unknown)),
        SelectionResult::NotFound
    );
}

#[test]
fn an_unreadable_line_is_reported_and_does_not_stop_the_rest_of_the_scan() {
    let path = temp_log_path("unreadable-line");
    {
        let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i"))
            .unwrap()
            .with_clock(fixed_clock());
        sink.append(status_entry()).unwrap();
    }
    // Append a garbage line and a version-mismatched line by hand.
    {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "not json at all").unwrap();
        writeln!(file, r#"{{"version":9999,"payload":{{}}}}"#).unwrap();
    }
    {
        let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap();
        sink.append(status_entry()).unwrap();
    }

    let scan = read_log(&path).unwrap();
    assert_eq!(
        scan.records.len(),
        2,
        "the two well-formed records must still be read"
    );
    assert_eq!(scan.unreadable.len(), 2);
    assert!(matches!(
        scan.unreadable[0].reason,
        UnreadableReason::Malformed { .. }
    ));
    assert!(matches!(
        scan.unreadable[1].reason,
        UnreadableReason::UnsupportedVersion { found: 9999, .. }
    ));
}

#[test]
fn a_sequence_gap_between_two_records_is_reported_as_possibly_lost() {
    // Simulates AuditFileSink::append reserving sequence 1 (e.g. for a
    // write that then failed) by hand-crafting a log with sequences
    // 0 and 2 present but 1 absent — exactly the shape a real failed
    // write between two successful ones would leave.
    let path = temp_log_path("gap");
    let instance = IssuerInstanceId::new("i");
    {
        let sink = AuditFileSink::open(&path, instance.clone()).unwrap();
        sink.append(status_entry()).unwrap(); // sequence 0
    }
    // Skip sequence 1 entirely (simulating a failed write that still
    // consumed it) by writing sequence 2 directly.
    {
        use eltanin_core::envelope::Versioned;
        let record = eltanin_audit::record::AuditRecord {
            event_id: eltanin_audit::record::AuditEventId {
                instance: instance.clone(),
                sequence: 2,
            },
            recorded_at: eltanin_audit::record::WallClockTime {
                unix_secs: 0,
                nanos: 0,
            },
            operation: eltanin_audit::record::RecordedOperation::AgentStatus,
            requested: eltanin_audit::record::RecordedRequest::AgentStatus,
            peer: peer(1),
            outcome: eltanin_audit::record::RecordedOutcome::StatusReported,
            response: AgentResponse::Status {
                status: eltanin_protocol::response::AgentStatusView {
                    protocol_version: 1,
                },
            },
        };
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(
            file,
            "{}",
            serde_json::to_string(&Versioned::current(record)).unwrap()
        )
        .unwrap();
    }

    let scan = read_log(&path).unwrap();
    assert_eq!(scan.records.len(), 2);
    let missing = eltanin_audit::record::AuditEventId {
        instance: instance.clone(),
        sequence: 1,
    };
    assert!(scan.gaps.contains(&missing));
    assert_eq!(
        select(&scan, &Selector::Event(missing)),
        SelectionResult::PossiblyLost
    );
}

#[test]
fn a_grant_and_its_later_release_correlate_by_lease_id() {
    let path = temp_log_path("correlate");
    let instance = IssuerInstanceId::new("i");
    let sink = AuditFileSink::open(&path, instance.clone()).unwrap();
    let lease_id = eltanin_core::lease::LeaseId {
        issuer: instance.clone(),
        sequence: 0,
    };
    sink.append(AuditEntry {
        operation: eltanin_audit::record::RecordedOperation::RequestLease,
        requested: eltanin_audit::record::RecordedRequest::RequestLease {
            resource: resource(),
            action: Action::Compute,
        },
        peer: peer(4242),
        outcome: eltanin_audit::record::RecordedOutcome::Granted {
            lease_id: lease_id.clone(),
            expires_at: eltanin_core::lease::MonotonicTime::from_nanos(1),
        },
        response: AgentResponse::LeaseGranted {
            lease: eltanin_protocol::response::LeaseView {
                lease_id: lease_id.clone(),
                remaining: std::time::Duration::from_secs(1),
            },
        },
    })
    .unwrap();
    sink.append(AuditEntry {
        operation: eltanin_audit::record::RecordedOperation::ReleaseLease,
        requested: eltanin_audit::record::RecordedRequest::ReleaseLease {
            lease_id: lease_id.clone(),
        },
        peer: peer(4242),
        outcome: eltanin_audit::record::RecordedOutcome::Released {
            revocation: eltanin_core::lease::RevocationOutcome::Revoked,
            backend: None,
        },
        response: AgentResponse::LeaseReleased {
            outcome: eltanin_protocol::response::ReleaseOutcome::Released,
        },
    })
    .unwrap();

    let scan = read_log(&path).unwrap();
    match select(&scan, &Selector::Lease(lease_id)) {
        SelectionResult::Found(records) => assert_eq!(records.len(), 2),
        other => panic!("expected Found with 2 records, got {other:?}"),
    }
}
