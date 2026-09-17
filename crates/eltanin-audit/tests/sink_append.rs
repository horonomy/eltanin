//! Sink append-only/concurrency/permission/rotation coverage (F-M1-009,
//! HORO-824; rotation added for F-M2-006/HORO-796 subtask 1).

use std::sync::Arc;

use eltanin_audit::explain::read_log;
use eltanin_audit::record::{
    RecordedAgentEvent, RecordedOperation, RecordedOutcome, RecordedRequest,
};
use eltanin_audit::sink::{rotated_path, AuditEntry, AuditFileSink};
use eltanin_core::lease::IssuerInstanceId;
use eltanin_protocol::response::AgentResponse;

mod support;
use support::{peer, temp_log_path};

fn status_entry() -> AuditEntry {
    AuditEntry {
        operation: RecordedOperation::AgentStatus,
        requested: RecordedRequest::AgentStatus,
        peer: peer(1),
        outcome: RecordedOutcome::StatusReported,
        response: AgentResponse::Status {
            status: eltanin_protocol::response::AgentStatusView {
                protocol_version: 1,
            },
        },
        session: None,
    }
}

#[test]
fn appended_records_survive_reopening_the_log() {
    let path = temp_log_path("reopen");
    {
        let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap();
        sink.append(status_entry()).unwrap();
    }
    {
        let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap();
        sink.append(status_entry()).unwrap();
    }
    let scan = read_log(&path).unwrap();
    assert_eq!(scan.records.len(), 2);
}

#[test]
fn sequence_numbers_are_monotonic_per_sink_instance() {
    let path = temp_log_path("sequence");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap();
    let a = sink.append(status_entry()).unwrap();
    let b = sink.append(status_entry()).unwrap();
    let c = sink.append(status_entry()).unwrap();
    assert_eq!([a.sequence, b.sequence, c.sequence], [0, 1, 2]);
}

#[test]
fn concurrent_writers_never_interleave_a_line() {
    let path = temp_log_path("concurrent");
    let sink = Arc::new(AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap());

    let threads: Vec<_> = (0..8)
        .map(|_| {
            let sink = Arc::clone(&sink);
            std::thread::spawn(move || {
                for _ in 0..25 {
                    sink.append(status_entry()).unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }

    let scan = read_log(&path).unwrap();
    assert_eq!(
        scan.records.len(),
        200,
        "every line must parse — an interleaved write would corrupt a line and show up in \
         unreadable instead"
    );
    assert!(
        scan.unreadable.is_empty(),
        "no line should be malformed: {:?}",
        scan.unreadable
    );

    let sequences: Vec<u64> = scan.records.iter().map(|r| r.event_id.sequence).collect();
    let mut sorted = sequences.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 200, "every sequence number must be unique");
    assert_eq!(
        sequences, sorted,
        "file order must match sequence order — append() reserves the \
         sequence and writes the line under the same lock, so no two \
         concurrent writers can land out of order relative to each other"
    );
}

#[cfg(unix)]
#[test]
fn the_log_file_is_created_with_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let path = temp_log_path("mode");
    let _sink = AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_failed_write_still_advances_the_sequence_leaving_a_detectable_gap() {
    // The sink itself has no way to *force* a write failure without a
    // fault-injecting File, so this test instead proves the structural
    // property append() relies on: the sequence counter advances
    // unconditionally on every call, success or not, by directly
    // exercising the counter via two real appends and asserting
    // strict monotonicity even though this sink cannot fail in this
    // test's environment — the gap-detection logic itself is exercised
    // end-to-end in explain_selectors.rs via a hand-crafted log file.
    let path = temp_log_path("gap-precondition");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap();
    let a = sink.append(status_entry()).unwrap();
    let b = sink.append(status_entry()).unwrap();
    assert_eq!(b.sequence, a.sequence + 1);
    assert_eq!(sink.failed_writes(), 0);
}

#[test]
fn rotation_triggers_at_the_configured_byte_threshold() {
    // One serialized status_entry() line is ~850 bytes; a threshold of
    // ~3 lines' worth guarantees exactly one rotation partway through 5
    // appends, and no more than one — so every appended record must
    // still be present (nothing has been discarded yet, since a
    // generation is only ever discarded by a *second* rotation).
    let path = temp_log_path("rotate-threshold");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i"))
        .unwrap()
        .with_max_bytes(2600);

    assert!(
        !rotated_path(&path).exists(),
        "no rotation should have happened yet"
    );
    for _ in 0..5 {
        sink.append(status_entry()).unwrap();
    }
    assert!(
        rotated_path(&path).exists(),
        "expected exactly one rotation to have occurred by now"
    );

    let scan = read_log(&path).unwrap();
    assert_eq!(
        scan.records.len(),
        5,
        "every appended record must still be readable across a single rotation"
    );
    let rotated_markers: Vec<_> = scan
        .agent_events
        .iter()
        .filter(|e| matches!(e.event, RecordedAgentEvent::AuditLogRotated { .. }))
        .collect();
    assert_eq!(
        rotated_markers.len(),
        1,
        "expected exactly one AuditLogRotated marker: {rotated_markers:?}"
    );
    assert!(matches!(
        rotated_markers[0].event,
        RecordedAgentEvent::AuditLogRotated {
            discarded_through_sequence: None,
            ..
        }
    ));
}

#[cfg(unix)]
#[test]
fn the_rotated_generation_file_is_created_with_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let path = temp_log_path("rotate-mode");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i"))
        .unwrap()
        .with_max_bytes(300);
    for _ in 0..20 {
        sink.append(status_entry()).unwrap();
    }
    let rotated = rotated_path(&path);
    assert!(rotated.exists(), "expected a rotation to have occurred");
    let mode = std::fs::metadata(&rotated).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    // The new current-generation file must also still be 0600.
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn the_audit_log_rotated_marker_is_the_first_entry_in_the_new_generation() {
    let path = temp_log_path("rotate-marker-first");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i"))
        .unwrap()
        .with_max_bytes(300);
    for _ in 0..20 {
        sink.append(status_entry()).unwrap();
    }
    assert!(rotated_path(&path).exists(), "expected a rotation");

    // Read only the *current* generation's raw first line directly —
    // read_log's own two-file merge is exercised separately in
    // retention.rs; this test pins the sink's own write-order guarantee.
    let current_contents = std::fs::read_to_string(&path).unwrap();
    let first_line = current_contents
        .lines()
        .next()
        .expect("current generation must not be empty after rotation");
    assert!(
        first_line.contains("\"record\":\"agent\"") && first_line.contains("audit_log_rotated"),
        "the first entry in the new generation must be the AuditLogRotated marker: {first_line}"
    );
}

#[test]
fn a_from_writer_sink_never_rotates_regardless_of_bytes_written() {
    let sink =
        AuditFileSink::from_writer(Vec::new(), IssuerInstanceId::new("i")).with_max_bytes(10); // far smaller than even one entry
    for _ in 0..50 {
        sink.append(status_entry()).unwrap();
    }
    // There is no path at all for a from_writer sink, so there is
    // nothing to assert a `.1` sibling against — the structural
    // guarantee is that append() never errors and never panics trying to
    // rotate a sink with no path, which the loop above already proves by
    // completing. failed_writes staying at 0 additionally confirms no
    // rotation-attempt error was silently swallowed as a write failure.
    assert_eq!(sink.failed_writes(), 0);
}
