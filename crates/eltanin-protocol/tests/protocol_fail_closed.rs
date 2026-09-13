//! Unknown-version/malformed/oversized fail-closed coverage (F-M1-006,
//! HORO-838). No input in this file may produce a successful decode
//! except the one test that confirms a well-formed request still does.

use eltanin_protocol::framing::{
    decode_frame_len, decode_request, encode_frame, FramingError, ProtocolError, MAX_FRAME_BYTES,
};

#[test]
fn a_well_formed_request_decodes_successfully() {
    let body = include_bytes!("fixtures/request_lease.json");
    assert!(decode_request(body).is_ok());
}

#[test]
fn unknown_version_is_reported_precisely_even_with_a_malformed_payload() {
    // The payload's body is garbage — this must still be reported as
    // the version mismatch, not masked by a payload-shape error, since
    // version is checked before the full shape is decoded.
    let body = br#"{"version":99,"payload":{"request_id":1,"body":{"garbage":1}}}"#;
    let err = decode_request(body).unwrap_err();
    assert_eq!(
        err,
        ProtocolError::Version(eltanin_core::envelope::UnsupportedVersion {
            found: 99,
            expected: eltanin_core::envelope::DOMAIN_SCHEMA_VERSION
        })
    );
}

#[test]
fn unknown_operation_fails_closed_as_malformed() {
    let body = br#"{"version":4,"payload":{"request_id":1,"body":{"op":"delete_everything"}}}"#;
    assert_eq!(decode_request(body).unwrap_err(), ProtocolError::Malformed);
}

#[test]
fn unknown_field_in_a_request_body_fails_closed_as_malformed() {
    let body = br#"{"version":4,"payload":{"request_id":1,"body":{"op":"request_lease","resource":{"vendor":"fake","kind":"gpu","local_id":"gpu-0"},"action":"compute","extra":"field"}}}"#;
    assert_eq!(decode_request(body).unwrap_err(), ProtocolError::Malformed);
}

#[test]
fn unknown_field_alongside_a_unit_variant_operation_fails_closed_as_malformed() {
    // Regression: a unit variant like AgentStatus has no struct of its
    // own to carry #[serde(deny_unknown_fields)], so this must be
    // enforced at the ClientRequest enum level instead — found by
    // independent review, which demonstrated this exact input decoding
    // successfully before the enum-level attribute was added.
    let body =
        br#"{"version":4,"payload":{"request_id":1,"body":{"op":"agent_status","sneaky":"data"}}}"#;
    assert_eq!(decode_request(body).unwrap_err(), ProtocolError::Malformed);
}

#[test]
fn a_non_object_payload_fails_closed_as_malformed() {
    let body = br#"{"version":4,"payload":42}"#;
    assert_eq!(decode_request(body).unwrap_err(), ProtocolError::Malformed);
}

#[test]
fn trailing_bytes_after_a_valid_document_fail_closed_as_malformed() {
    let mut body = include_bytes!("fixtures/agent_status_request.json").to_vec();
    body.extend_from_slice(b"{}");
    assert_eq!(decode_request(&body).unwrap_err(), ProtocolError::Malformed);
}

#[test]
fn a_truncated_frame_fails_closed_as_malformed() {
    let full = include_bytes!("fixtures/request_lease.json");
    let truncated = &full[..full.len() / 2];
    assert_eq!(
        decode_request(truncated).unwrap_err(),
        ProtocolError::Malformed
    );
}

#[test]
fn a_frame_exceeding_the_max_size_fails_closed_before_deserialization() {
    let oversized = vec![b'a'; MAX_FRAME_BYTES + 1];
    assert_eq!(
        decode_request(&oversized).unwrap_err(),
        ProtocolError::Framing(FramingError::Oversized {
            len: MAX_FRAME_BYTES + 1,
            max: MAX_FRAME_BYTES
        })
    );
}

#[test]
fn decode_frame_len_rejects_a_header_naming_a_length_over_the_max() {
    let header = u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_be_bytes();
    assert_eq!(
        decode_frame_len(header),
        Err(FramingError::Oversized {
            len: MAX_FRAME_BYTES + 1,
            max: MAX_FRAME_BYTES
        })
    );
}

#[test]
fn decode_frame_len_accepts_a_header_naming_the_max_exactly() {
    let header = u32::try_from(MAX_FRAME_BYTES).unwrap().to_be_bytes();
    assert_eq!(decode_frame_len(header), Ok(MAX_FRAME_BYTES));
}

#[test]
fn encode_frame_rejects_a_payload_over_the_max_without_writing_a_header() {
    let payload = vec![b'a'; MAX_FRAME_BYTES + 1];
    assert_eq!(
        encode_frame(&payload),
        Err(FramingError::Oversized {
            len: MAX_FRAME_BYTES + 1,
            max: MAX_FRAME_BYTES
        })
    );
}

#[test]
fn encode_frame_prepends_the_exact_big_endian_length() {
    let payload = b"{}";
    let framed = encode_frame(payload).unwrap();
    assert_eq!(&framed[..4], &2u32.to_be_bytes());
    assert_eq!(&framed[4..], payload);
}
