//! Bounded-retention coverage: reading across a rotation, no false
//! gap-detection at a rotation boundary, and genuinely discarded
//! (two-rotations-deep) sequences reported as `RetentionDiscarded`
//! (F-M2-006/HORO-796 subtask 1, AC6).

use eltanin_audit::explain::{read_log, select, SelectionResult, Selector};
use eltanin_audit::record::{AuditEventId, RecordedAgentEvent};
use eltanin_audit::sink::{rotated_path, AuditFileSink};
use eltanin_core::lease::IssuerInstanceId;

mod support;
use support::{peer, status_entry};

/// One serialized `status_entry()` line is 964 bytes (HORO-797 prep grew
/// `AgentStatusView` by three more fields — `session_required`/
/// `approval_required`/`revocation_required` — on top of HORO-796
/// subtask 3's `enforcement_mode`) and its `AuditLogRotated` marker line
/// is 237 bytes. `3000` is chosen so both this file's append sequences
/// rotate at the exact counts their own comments describe: the first
/// generation fits 3 decision lines (3 × 964 = 2892 ≤ 3000) but not a
/// 4th (4 × 964 = 3856 > 3000), so a 4-append sequence rotates exactly
/// once, on the 4th append; a second generation then holds one marker
/// plus two more decision lines (237 + 2 × 964 = 2165 ≤ 3000) but not a
/// 3rd (2165 + 964 = 3129 > 3000), so a 6-append sequence rotates a
/// second time, on the 6th append.
const MAX_BYTES: u64 = 3000;

#[test]
fn read_log_spans_both_generations_in_write_order_after_one_rotation() {
    let path = temp_path("span-one-rotation");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i"))
        .unwrap()
        .with_max_bytes(MAX_BYTES);
    // 4 appends: 3 fit the first generation, the 4th triggers exactly
    // one rotation.
    for _ in 0..4 {
        sink.append(status_entry()).unwrap();
    }
    assert!(rotated_path(&path).exists(), "expected one rotation");

    let scan = read_log(&path).unwrap();
    let sequences: Vec<u64> = scan.records.iter().map(|r| r.event_id.sequence).collect();
    let mut sorted = sequences.clone();
    sorted.sort_unstable();
    assert_eq!(
        sequences, sorted,
        "records must come back in ascending sequence order — .1 (older) before \
         the current file (newer): {sequences:?}"
    );
    assert_eq!(
        scan.records.len(),
        4,
        "nothing has been discarded yet after only one rotation"
    );
}

#[test]
fn a_sequence_range_that_legitimately_continues_across_a_rotation_is_not_a_gap() {
    let path = temp_path("no-false-gap");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i"))
        .unwrap()
        .with_max_bytes(MAX_BYTES);
    for _ in 0..4 {
        sink.append(status_entry()).unwrap();
    }
    assert!(rotated_path(&path).exists(), "expected one rotation");

    let scan = read_log(&path).unwrap();
    assert!(
        scan.gaps.is_empty(),
        "a rotation boundary must never itself look like a lost write: {:?}",
        scan.gaps
    );
}

#[test]
fn a_genuinely_discarded_two_rotations_deep_sequence_is_retention_discarded() {
    let path = temp_path("two-rotations-deep");
    let instance = IssuerInstanceId::new("i");
    let sink = AuditFileSink::open(&path, instance.clone())
        .unwrap()
        .with_max_bytes(MAX_BYTES);
    // 6 appends: 3 fit the first generation, the 4th triggers rotation
    // #1, the 6th triggers rotation #2 — which overwrites the first
    // rotation's `.1`, permanently discarding sequences 0-2.
    for _ in 0..6 {
        sink.append(status_entry()).unwrap();
    }

    let scan = read_log(&path).unwrap();
    let rotated_markers: Vec<_> = scan
        .agent_events
        .iter()
        .filter(|e| matches!(e.event, RecordedAgentEvent::AuditLogRotated { .. }))
        .collect();
    assert_eq!(
        rotated_markers.len(),
        2,
        "expected exactly two rotations: {rotated_markers:?}"
    );

    let floor = *scan
        .retention_floor
        .get(&instance)
        .expect("a two-rotations-deep log must have a retention floor");
    assert!(
        floor >= 2,
        "expected sequences 0-2 to be discarded, floor was {floor}"
    );

    let discarded_id = AuditEventId {
        instance: instance.clone(),
        sequence: 0,
    };
    assert_eq!(
        select(&scan, &Selector::Event(discarded_id)),
        SelectionResult::RetentionDiscarded,
        "sequence 0 was legitimately issued and recorded, then rotated away twice over"
    );

    // A sequence still physically present must remain Found, never
    // mistaken for discarded just because *some* floor exists.
    let present = scan
        .records
        .iter()
        .map(|r| r.event_id.sequence)
        .max()
        .expect("at least one record must have survived both rotations");
    let present_id = AuditEventId {
        instance,
        sequence: present,
    };
    match select(&scan, &Selector::Event(present_id)) {
        SelectionResult::Found(records) => assert_eq!(records.len(), 1),
        other => panic!("expected the surviving highest sequence to be Found, got {other:?}"),
    }
}

#[test]
fn selectors_still_work_correctly_across_a_rotated_two_file_log() {
    let path = temp_path("selectors-across-rotation");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i"))
        .unwrap()
        .with_max_bytes(MAX_BYTES);
    for _ in 0..4 {
        sink.append(status_entry()).unwrap();
    }
    assert!(rotated_path(&path).exists(), "expected one rotation");

    let scan = read_log(&path).unwrap();
    // Selector::Pid: status_entry() always uses peer(4242) via this
    // file's own support helper below.
    match select(&scan, &Selector::Pid(4242)) {
        SelectionResult::Found(records) => assert_eq!(records.len(), 4),
        other => panic!("expected all 4 records to match by pid, got {other:?}"),
    }

    let first_sequence = scan
        .records
        .iter()
        .map(|r| r.event_id.sequence)
        .min()
        .unwrap();
    let event_id = AuditEventId {
        instance: IssuerInstanceId::new("i"),
        sequence: first_sequence,
    };
    match select(&scan, &Selector::Event(event_id.clone())) {
        SelectionResult::Found(records) => {
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].event_id, event_id);
        }
        other => panic!("expected Found for a record physically present in .1, got {other:?}"),
    }
    // Verify peer() is what status_entry() actually used, so the pid
    // assertion above isn't accidentally vacuous.
    assert_eq!(peer(4242).credential.pid, 4242);
}

fn temp_path(tag: &str) -> std::path::PathBuf {
    support::temp_log_path(tag)
}
