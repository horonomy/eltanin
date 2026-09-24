//! `horonom-evidence-canon-v1`: RFC 8785 JCS + SHA-256, pinned by
//! `dogfood-evidence-canonicalization-v1.md`.
//!
//! # Why a hand-rolled subset of JCS is sufficient here
//!
//! Full RFC 8785 is a general-purpose JSON canonicalizer (arbitrary
//! nesting, ECMAScript number formatting, minimal string escaping). This
//! adapter's [`crate::event::Event`] is flat (no nested objects once
//! `integrity` is omitted — see step 1 of the pinned procedure), every
//! field is either a plain enum string, a plain string, a bool, or a
//! non-negative integer, and `serde_json`'s `Map` — **not** compiled with
//! the `preserve_order` feature anywhere in this workspace (confirmed:
//! no `Cargo.toml` in this workspace enables it) — is backed by a
//! `BTreeMap`, so `serde_json::to_value` already produces keys sorted by
//! byte order, which is UTF-16-code-unit order for this schema's
//! all-ASCII key set. So "serialize via `serde_json::to_value`, drop
//! `integrity`, serialize the remaining `Value` to a compact string"
//! already satisfies steps 1–3 of the pinned procedure for this event
//! shape specifically. A future field with nested objects or non-ASCII
//! string content would need a real recursive JCS implementation; this
//! module does not claim to be one.

#[cfg(test)]
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::event::{ContentHash, Event, Integrity};

/// The literal canonicalization id every record produced by this
/// procedure is stamped with — `dogfood-evidence-canonicalization-v1.md`
/// step 5.
pub const CANONICALIZATION_ID: &str = "horonom-evidence-canon-v1";

/// Errors canonicalizing an event — always a `serde_json` failure, which
/// should not be reachable for this crate's own [`Event`] type (every
/// field is plain, always-serializable data), but propagated rather than
/// unwrapped so a future field addition fails loudly instead of
/// panicking.
#[derive(Debug, thiserror::Error)]
#[error("failed to canonicalize evidence event: {reason}")]
pub struct CanonError {
    reason: String,
}

/// Canonicalize `event` per `dogfood-evidence-canonicalization-v1.md`
/// steps 1–3: omit `integrity`, sort keys, no insignificant whitespace,
/// UTF-8 bytes. Returns the canonical JSON text.
///
/// # Errors
///
/// Returns [`CanonError`] if `event` cannot be serialized to
/// `serde_json::Value` at all.
pub fn canonicalize(event: &Event) -> Result<String, CanonError> {
    let value = serde_json::to_value(event).map_err(|e| CanonError {
        reason: e.to_string(),
    })?;
    let serde_json::Value::Object(mut map) = value else {
        return Err(CanonError {
            reason: "expected Event to serialize to a JSON object".to_string(),
        });
    };
    // Step 1: omit `integrity` entirely before hashing — it is metadata
    // *about* the event, not part of the event being hashed. `Event`
    // itself doesn't carry a real `integrity` value until after this
    // function runs (see `hash_event` below, which builds it from this
    // function's own output), but the key is removed defensively here
    // too so this function's contract holds even if a future caller
    // passes an `Event` that already has one populated.
    map.remove("integrity");
    // `serde_json::to_string` on a `Value::Object` backed by a
    // (non-`preserve_order`) `Map` == `BTreeMap` emits keys in sorted
    // order with no insignificant whitespace — steps 2–3 of the pinned
    // procedure for this schema's flat, all-ASCII-key shape (see this
    // module's top doc comment).
    serde_json::to_string(&serde_json::Value::Object(map)).map_err(|e| CanonError {
        reason: e.to_string(),
    })
}

/// Compute the [`Integrity`] envelope (ADR-0012 §6) for `event`: hash the
/// canonical form (with `integrity` omitted) via SHA-256.
///
/// # Errors
///
/// Returns [`CanonError`] under the same conditions as [`canonicalize`].
pub fn hash_event(event: &Event) -> Result<Integrity, CanonError> {
    let canonical = canonicalize(event)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    Ok(Integrity {
        canonicalization: CANONICALIZATION_ID,
        content_hash: ContentHash {
            alg: "sha256",
            value: format!("{digest:x}"),
        },
    })
}

/// Canonicalize an arbitrary already-`Serialize` value the same way
/// [`canonicalize`] does — used only by this module's own tests to prove
/// key-order independence without needing a second full [`Event`]
/// constructor per test case.
#[cfg(test)]
fn canonicalize_value<T: Serialize>(value: &T) -> String {
    let value = serde_json::to_value(value).expect("serialize");
    let serde_json::Value::Object(mut map) = value else {
        panic!("expected object");
    };
    map.remove("integrity");
    serde_json::to_string(&serde_json::Value::Object(map)).expect("reserialize")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_insertion_order_does_not_affect_canonical_form_or_hash() {
        // DFC-SCHEMA-09 negative control (canon doc's own "Negative
        // control" section): two logically identical objects with keys
        // in different insertion order must canonicalize to byte-
        // identical text.
        let a = json!({"b": 1, "a": "x", "integrity": {"whatever": true}});
        let b = json!({"a": "x", "integrity": {"other": 1}, "b": 1});
        assert_eq!(canonicalize_value(&a), canonicalize_value(&b));
        assert_eq!(canonicalize_value(&a), r#"{"a":"x","b":1}"#);
    }

    #[test]
    fn dropped_count_zero_is_not_reserialized_as_a_float_or_string() {
        // Canon doc negative control: `dropped_count: 0` must never
        // serialize as `0.0` or `"0"` — that would change the bytes
        // hashed for a logically identical event.
        let a = json!({"dropped_count": 0});
        let text = canonicalize_value(&a);
        assert_eq!(text, r#"{"dropped_count":0}"#);
        assert!(!text.contains("0.0"));
        assert!(!text.contains("\"0\""));
    }
}
