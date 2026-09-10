//! Request-correlation coverage (F-M1-006, HORO-838): `request_id` is
//! echoed on success, best-effort recovered when only the body is
//! garbage, and never fabricated when it genuinely cannot be recovered.

use eltanin_protocol::framing::{decode_request, peek_request_id, peek_version};
use eltanin_protocol::request::RequestId;

#[test]
fn a_well_formed_request_id_round_trips_through_decode() {
    let body = include_bytes!("fixtures/request_lease.json");
    let decoded = decode_request(body).unwrap();
    assert_eq!(decoded.payload.request_id, RequestId(1));
}

#[test]
fn request_id_is_recoverable_even_when_the_body_is_garbage() {
    // The header (version + request_id) is well-formed; only the
    // operation-specific body is nonsense. Full decode must fail, but
    // the id is still recoverable for an error response to correlate.
    let body = br#"{"version":1,"payload":{"request_id":42,"body":{"op":"request_lease","garbage":true}}}"#;
    assert!(decode_request(body).is_err());
    assert_eq!(peek_request_id(body), Some(RequestId(42)));
}

#[test]
fn request_id_is_not_fabricated_when_the_payload_is_not_an_object() {
    let body = br#"{"version":1,"payload":42}"#;
    assert!(decode_request(body).is_err());
    assert_eq!(peek_request_id(body), None);
}

#[test]
fn request_id_is_not_fabricated_for_a_truncated_frame() {
    let full = include_bytes!("fixtures/request_lease.json");
    let truncated = &full[..full.len() / 2];
    assert_eq!(peek_request_id(truncated), None);
}

#[test]
fn version_is_recoverable_independent_of_request_id_recoverability() {
    // Even when the payload is not an object at all (so request_id can
    // never be recovered), the version alone is still peekable — this is
    // what lets decode_request report UnsupportedVersion instead of
    // Malformed in that case.
    let body = br#"{"version":99,"payload":42}"#;
    assert_eq!(peek_version(body), Some(99));
    assert_eq!(peek_request_id(body), None);
}
