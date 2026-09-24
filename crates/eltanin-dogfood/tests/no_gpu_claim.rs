//! No hardware/GPU/device-level enforcement claim, anywhere in the
//! frozen §3 event body.
//!
//! # Why the summary's `unsupported` note is not itself a violation
//!
//! The summary's `unsupported` list is required (by the ticket) to
//! contain the literal string `"device_level_gpu_enforcement"` — which
//! itself contains the substring `"gpu"`. That note is deliberately kept
//! **out of the hashed/canonicalized `Event` body** (see
//! `src/event.rs`'s top doc comment and `src/adapter.rs`'s
//! `summary_unsupported_notes`, which is a sibling function, never an
//! `Event` field) — it exists in the CLI's own rendering, not in any
//! §3 record. So this test scans only the serialized `Event` objects
//! themselves (via `serde_json::to_string`), where the substring never
//! appears, and separately confirms the disclosure note exists in its
//! correct, non-hashed location.

mod support;

use eltanin_audit::record::RecordedEnforcementMode;
use eltanin_dogfood::adapter::{
    project, scan_for_forbidden_hardware_terms, summary_unsupported_notes,
};
use eltanin_dogfood::event::Profile;

fn zero_time() -> eltanin_audit::record::WallClockTime {
    eltanin_audit::record::WallClockTime {
        unix_secs: 1_790_244_903,
        nanos: 0,
    }
}

#[test]
fn no_forbidden_hardware_term_appears_in_any_serialized_event() {
    let mut scan = support::empty_scan();
    scan.records.push(support::base_record(
        "i",
        0,
        RecordedEnforcementMode::Shadow,
        support::would_grant("i", 0),
        None,
    ));
    scan.records.push(support::base_record(
        "i",
        1,
        RecordedEnforcementMode::Enforce,
        support::granted("i", 1),
        Some(support::session_id("i", 5)),
    ));

    let projection = project(&scan, Profile::Personal, "0.1.0", zero_time());

    let mut all_serialized = String::new();
    for event in &projection.events {
        all_serialized.push_str(&serde_json::to_string(event).unwrap());
    }
    all_serialized.push_str(&serde_json::to_string(&projection.summary).unwrap());

    let hits = scan_for_forbidden_hardware_terms(&all_serialized);
    assert!(
        hits.is_empty(),
        "found forbidden hardware/GPU term(s) in serialized §3 event body: {hits:?}"
    );
}

/// The disclosure this adapter is required to make lives in the summary
/// note list, never inside a hashed `Event` — this is the positive half
/// of the split this file's top doc comment describes.
#[test]
fn device_level_gpu_enforcement_is_disclosed_in_the_unsupported_notes() {
    let scan = support::empty_scan();
    let notes = summary_unsupported_notes(&scan);
    assert!(notes.contains(&"device_level_gpu_enforcement"));
}
