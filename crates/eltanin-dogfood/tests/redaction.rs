//! DFC-SCHEMA-05/06: extends `eltanin-audit`'s `redaction.rs` pattern
//! to this adapter's own output — `payload_classification` is always
//! `metadata_only` with no configuration, and no raw workload
//! executable-path/argv-shaped content becomes a §3 field this adapter
//! doesn't already define (the schema simply has no such field to leak
//! into).

mod support;

use eltanin_audit::record::RecordedEnforcementMode;
use eltanin_dogfood::adapter::project_record;
use eltanin_dogfood::event::{PayloadClassification, Profile};

fn zero_time() -> eltanin_audit::record::WallClockTime {
    eltanin_audit::record::WallClockTime {
        unix_secs: 1_790_244_903,
        nanos: 0,
    }
}

/// DFC-SCHEMA-05: default payload classification is `metadata_only` with
/// zero configuration — there is no knob in this adapter's public API to
/// change it (see `event::PayloadClassification`, a single-variant enum).
#[test]
fn payload_classification_is_always_metadata_only() {
    let record = support::base_record(
        "i",
        0,
        RecordedEnforcementMode::Shadow,
        support::would_grant("i", 0),
        None,
    );
    let event = project_record(&record, Profile::Personal, "0.1.0", zero_time()).unwrap();
    assert_eq!(
        event.payload_classification,
        PayloadClassification::MetadataOnly
    );

    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"metadata_only\""));
}

/// DFC-SCHEMA-06: the projected event never contains a raw
/// executable-path/argv-shaped field at all — the §3 schema (see
/// `src/event.rs`) has no such field for this adapter to populate, so
/// there is nothing for a redaction pass to miss. This is the same
/// structural argument `eltanin-audit`'s own `redaction.rs` makes for
/// its evidence source (`ExecutionContext` never touches argv/environ);
/// this test pins it one layer up, for this adapter's own output shape.
#[test]
fn projected_event_has_no_field_for_raw_workload_content() {
    let record = support::base_record(
        "i",
        1,
        RecordedEnforcementMode::Shadow,
        support::would_grant("i", 1),
        None,
    );
    let event = project_record(&record, Profile::Personal, "0.1.0", zero_time()).unwrap();
    let value = serde_json::to_value(&event).unwrap();
    let object = value.as_object().unwrap();
    for forbidden_key in ["executable_path", "argv", "cmdline", "environ", "prompt"] {
        assert!(
            !object.contains_key(forbidden_key),
            "projected event must never carry a {forbidden_key:?} field"
        );
    }
}
