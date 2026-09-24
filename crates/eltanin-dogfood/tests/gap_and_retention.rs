//! DFC-RETN-01/02, DFC-FAIL-07: seeded-gap counting and backwards
//! clock-jump stability.
//!
//! A genuine mutation control was run by hand against
//! `adapter::build_summary`'s `dropped_count` line during development
//! (temporarily hardcoding `dropped_count: 0`, confirming
//! `seeded_gaps_are_counted_exactly` below fails, then reverting) — see
//! the implementation PR/commit description for the exact before/after;
//! this file only carries the passing property.

mod support;

use eltanin_audit::explain::UnreadableLine;
use eltanin_audit::record::AuditEventId;
use eltanin_dogfood::adapter::project;
use eltanin_dogfood::event::{Coverage, GapReason, Profile};

fn zero_time() -> eltanin_audit::record::WallClockTime {
    eltanin_audit::record::WallClockTime {
        unix_secs: 1_790_244_903,
        nanos: 0,
    }
}

fn synthetic_gap(instance: &str, sequence: u64) -> AuditEventId {
    support::event_id(instance, sequence)
}

/// Seed `LogScan.gaps` with N synthetic entries → `summary.dropped_count
/// == N`, `coverage=gap`, `gap_reason=source_unavailable` (DFC-RETN-01/02).
#[test]
fn seeded_gaps_are_counted_exactly() {
    let mut scan = support::empty_scan();
    let n = 7;
    for i in 0..n {
        scan.gaps.push(synthetic_gap("instance-x", i));
    }

    let projection = project(&scan, Profile::Personal, "0.1.0", zero_time());
    assert_eq!(projection.summary.dropped_count, n);
    assert_eq!(projection.summary.coverage, Coverage::Gap);
    assert_eq!(
        projection.summary.gap_reason,
        Some(GapReason::SourceUnavailable)
    );
}

/// An unreadable-but-recovered-id line (schema version mismatch, e.g.) is
/// reported as `gap_reason=unknown` — "we cannot attest to what we
/// cannot describe" (ADR-0012 §7 item 5) — and takes priority over a
/// plain sequence gap when both are present in the same scan.
#[test]
fn unreadable_recovered_line_reports_gap_reason_unknown_and_takes_priority() {
    let mut scan = support::empty_scan();
    scan.gaps.push(synthetic_gap("instance-x", 0));
    scan.unreadable.push(UnreadableLine {
        generation: eltanin_audit::explain::LogGeneration::Current,
        line_number: 3,
        reason: eltanin_audit::explain::UnreadableReason::UnsupportedVersion {
            found: 999,
            expected: eltanin_core::envelope::DOMAIN_SCHEMA_VERSION,
        },
        event_id: Some(synthetic_gap("instance-x", 1)),
    });

    let projection = project(&scan, Profile::Personal, "0.1.0", zero_time());
    assert_eq!(projection.summary.dropped_count, 2);
    assert_eq!(projection.summary.gap_reason, Some(GapReason::Unknown));
}

/// A retention-rotation-only scan (no plain gaps, no unreadable lines,
/// but a nonzero `retention_floor`) reports `coverage=gap`,
/// `gap_reason=buffer_overflow`, `dropped_count=0` — the exact discarded
/// count below the floor is never guessed — plus the disclosure note.
#[test]
fn retention_floor_alone_reports_buffer_overflow_with_zero_dropped_and_a_disclosure() {
    let mut scan = support::empty_scan();
    scan.retention_floor
        .insert(eltanin_core::lease::IssuerInstanceId::new("instance-x"), 41);
    // A record must exist above the floor so the floor is meaningful and
    // `summary_instance` has a real instance to attribute the summary to.
    scan.records.push(support::base_record(
        "instance-x",
        42,
        eltanin_audit::record::RecordedEnforcementMode::Shadow,
        support::would_grant("instance-x", 42),
        None,
    ));

    let projection = project(&scan, Profile::Personal, "0.1.0", zero_time());
    assert_eq!(projection.summary.dropped_count, 0);
    assert_eq!(projection.summary.coverage, Coverage::Gap);
    assert_eq!(
        projection.summary.gap_reason,
        Some(GapReason::BufferOverflow)
    );

    let notes = eltanin_dogfood::adapter::summary_unsupported_notes(&scan);
    assert!(notes.contains(&"exact_dropped_count_below_retention_floor"));
}

/// A clean scan (no gaps, no unreadable, no rotation) reports
/// `coverage=full`, `dropped_count=0`, no `gap_reason`.
#[test]
fn clean_scan_reports_full_coverage() {
    let mut scan = support::empty_scan();
    scan.records.push(support::base_record(
        "instance-x",
        0,
        eltanin_audit::record::RecordedEnforcementMode::Shadow,
        support::would_grant("instance-x", 0),
        None,
    ));
    let projection = project(&scan, Profile::Personal, "0.1.0", zero_time());
    assert_eq!(projection.summary.dropped_count, 0);
    assert_eq!(projection.summary.coverage, Coverage::Full);
    assert_eq!(projection.summary.gap_reason, None);
}
