//! HORO-1381 sub-ticket 6 — cross-product canonicalization-vector
//! agreement example.
//!
//! Reads a `canon-v1-vector-001.json`-shaped vector on stdin and
//! hand-constructs the real, shipped `eltanin_dogfood::event::Event`
//! from its `event` member's field values -- unavoidable because `Event`
//! is `Serialize`-only (no `Deserialize`), so `serde_json::from_value`
//! cannot build one directly. A local `RawEvent` mirror struct (this
//! example's own, not a product `src/` addition) does the JSON parsing;
//! every value used to build the real `Event` comes from the vector's
//! stdin JSON, never from this crate's own `PRODUCT`/`ADAPTER_VERSION`
//! constants (which do not match this vector's pinned
//! `product: "circinus"` / `adapter_version: "0.4.2"`).
//!
//! Calls the real, shipped `eltanin_dogfood::canon::{canonicalize,
//! hash_event}` and prints one JSON line to stdout:
//! `{"canonical": "<string>", "content_hash": {"alg":"sha256","value":"<hex>"}}`.
//! Unlike Horologium/Libra Governor, this product CAN emit both the
//! canonical string and the hash, so both are reported for real (never
//! fabricated) -- the calling bash driver additionally compares this
//! example's own canonical string against the vector's pinned
//! `canonical` field to catch transcription drift.
//!
//! `Event::integrity` is never read by `canonicalize`/`hash_event` (both
//! strip the `integrity` member from the serialized form before
//! hashing, per the pinned procedure) -- this example builds a
//! throwaway placeholder `Integrity` for the struct literal, exactly as
//! this crate's own `canon.rs` tests do for the same reason.
//!
//! This example does not compare against any pin -- the calling bash
//! driver (`scripts/dogfood-journey/eltanin_canon_vector.sh`) does the
//! comparison and emits the DogFood conformance check row. This example
//! stays dumb.

use std::io::Read;

use eltanin_dogfood::canon::{canonicalize, hash_event};
use eltanin_dogfood::event::{
    ActualAction, ContentHash, Coverage, DecisionMode, Eligibility, Event, GapReason, Integrity,
    PayloadClassification, Profile, TransportState,
};
use serde::Deserialize;

/// This example's own JSON mirror of the vector's `event` object --
/// loosely typed (every enum-shaped field stays a `String`) so it can
/// parse the vector regardless of which product's typed model would
/// accept it. Not a product `src/` addition.
#[derive(Debug, Deserialize)]
struct RawEvent {
    event_id: String,
    schema_version: u32,
    product: String,
    product_version: String,
    adapter_version: String,
    occurred_at: String,
    ingested_at: String,
    profile: String,
    origin_profile: String,
    decision_mode: String,
    scope_id: Option<String>,
    actual_action: String,
    would_action: Option<String>,
    coverage: String,
    gap_reason: Option<String>,
    dropped_count: u64,
    payload_classification: String,
    destination: String,
    tenant_id: Option<String>,
    transport_state: String,
    eligibility: String,
    permanently_ineligible: bool,
    imported: bool,
}

fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn parse_profile(s: &str) -> Result<Profile, String> {
    match s {
        "personal" => Ok(Profile::Personal),
        "corporate" => Ok(Profile::Corporate),
        other => Err(format!("unrecognized profile: {other:?}")),
    }
}

fn parse_decision_mode(s: &str) -> Result<DecisionMode, String> {
    match s {
        "observe" => Ok(DecisionMode::Observe),
        "enforce" => Ok(DecisionMode::Enforce),
        other => Err(format!("unrecognized decision_mode: {other:?}")),
    }
}

fn parse_action(s: &str) -> Result<ActualAction, String> {
    match s {
        "allow" => Ok(ActualAction::Allow),
        "deny" => Ok(ActualAction::Deny),
        "warn" => Ok(ActualAction::Warn),
        "no_op" => Ok(ActualAction::NoOp),
        "error" => Ok(ActualAction::Error),
        other => Err(format!("unrecognized action: {other:?}")),
    }
}

fn parse_coverage(s: &str) -> Result<Coverage, String> {
    match s {
        "full" => Ok(Coverage::Full),
        "partial" => Ok(Coverage::Partial),
        "gap" => Ok(Coverage::Gap),
        other => Err(format!("unrecognized coverage: {other:?}")),
    }
}

fn parse_gap_reason(s: &str) -> Result<GapReason, String> {
    match s {
        "buffer_overflow" => Ok(GapReason::BufferOverflow),
        "disk_cap" => Ok(GapReason::DiskCap),
        "adapter_unsupported" => Ok(GapReason::AdapterUnsupported),
        "source_unavailable" => Ok(GapReason::SourceUnavailable),
        "redaction_failed" => Ok(GapReason::RedactionFailed),
        "unknown" => Ok(GapReason::Unknown),
        other => Err(format!("unrecognized gap_reason: {other:?}")),
    }
}

fn parse_payload_classification(s: &str) -> Result<PayloadClassification, String> {
    match s {
        // Eltanin's PayloadClassification enum has only this one variant
        // (see crate::event's doc comment) -- the vector is pinned to
        // this value for exactly that reason.
        "metadata_only" => Ok(PayloadClassification::MetadataOnly),
        other => Err(format!(
            "unrecognized payload_classification for eltanin (only metadata_only exists): {other:?}"
        )),
    }
}

fn parse_transport_state(s: &str) -> Result<TransportState, String> {
    match s {
        // Eltanin's TransportState enum has only this one variant -- the
        // vector is pinned to this value for exactly that reason.
        "pending" => Ok(TransportState::Pending),
        other => Err(format!(
            "unrecognized transport_state for eltanin (only pending exists): {other:?}"
        )),
    }
}

fn parse_eligibility(s: &str) -> Result<Eligibility, String> {
    match s {
        "replayable_evidence" => Ok(Eligibility::ReplayableEvidence),
        "non_replayable_operation" => Ok(Eligibility::NonReplayableOperation),
        other => Err(format!("unrecognized eligibility: {other:?}")),
    }
}

fn build_event(raw: RawEvent) -> Result<Event, String> {
    let gap_reason = match &raw.gap_reason {
        Some(value) => Some(parse_gap_reason(value)?),
        None => None,
    };
    let would_action = match &raw.would_action {
        Some(value) => Some(parse_action(value)?),
        None => None,
    };

    Ok(Event {
        event_id: raw.event_id,
        schema_version: raw.schema_version,
        product: leak_str(raw.product),
        product_version: raw.product_version,
        adapter_version: raw.adapter_version,
        occurred_at: raw.occurred_at,
        ingested_at: raw.ingested_at,
        profile: parse_profile(&raw.profile)?,
        origin_profile: parse_profile(&raw.origin_profile)?,
        decision_mode: parse_decision_mode(&raw.decision_mode)?,
        scope_id: raw.scope_id,
        actual_action: parse_action(&raw.actual_action)?,
        would_action,
        coverage: parse_coverage(&raw.coverage)?,
        gap_reason,
        dropped_count: raw.dropped_count,
        payload_classification: parse_payload_classification(&raw.payload_classification)?,
        // Never read by canonicalize()/hash_event() -- both strip
        // `integrity` from the serialized form before hashing. A
        // throwaway placeholder, exactly like this crate's own
        // canon.rs tests use.
        integrity: Integrity {
            canonicalization: "placeholder",
            content_hash: ContentHash {
                alg: "placeholder",
                value: "placeholder".to_string(),
            },
        },
        destination: leak_str(raw.destination),
        tenant_id: raw.tenant_id,
        transport_state: parse_transport_state(&raw.transport_state)?,
        eligibility: parse_eligibility(&raw.eligibility)?,
        permanently_ineligible: raw.permanently_ineligible,
        imported: raw.imported,
    })
}

fn main() {
    let mut input = String::new();
    if let Err(err) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("FATAL: failed to read stdin: {err}");
        std::process::exit(1);
    }

    let vector: serde_json::Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("FATAL: failed to parse vector JSON: {err}");
            std::process::exit(1);
        }
    };

    let event_value = match vector.get("event") {
        Some(event) => event.clone(),
        None => {
            eprintln!("FATAL: vector JSON has no \"event\" member");
            std::process::exit(1);
        }
    };

    let raw_event: RawEvent = match serde_json::from_value(event_value) {
        Ok(raw) => raw,
        Err(err) => {
            eprintln!("FATAL: failed to parse event into this example's RawEvent mirror: {err}");
            std::process::exit(1);
        }
    };

    let event = match build_event(raw_event) {
        Ok(event) => event,
        Err(err) => {
            eprintln!("FATAL: failed to build eltanin_dogfood::event::Event from vector: {err}");
            std::process::exit(1);
        }
    };

    let canonical = match canonicalize(&event) {
        Ok(canonical) => canonical,
        Err(err) => {
            eprintln!("FATAL: canonicalize() failed: {err}");
            std::process::exit(1);
        }
    };

    let integrity = match hash_event(&event) {
        Ok(integrity) => integrity,
        Err(err) => {
            eprintln!("FATAL: hash_event() failed: {err}");
            std::process::exit(1);
        }
    };

    let output = serde_json::json!({
        "canonical": canonical,
        "content_hash": {
            "alg": integrity.content_hash.alg,
            "value": integrity.content_hash.value,
        },
    });

    println!("{output}");
}
