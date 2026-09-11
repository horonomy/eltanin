//! Client-direction framing coverage (F-M1-008, HORO-846):
//! `encode_request`/`decode_response`, the mirror pair `eltanin-cli`
//! uses. Since the agent's own transport calls `decode_request` and a
//! client calls `encode_request`, a round trip through both directions
//! establishes wire compatibility between the two sides by
//! construction, platform-neutrally — no real socket needed.

use eltanin_core::envelope::Versioned;
use eltanin_core::lease::{IssuerInstanceId, LeaseId};
use eltanin_core::resource::{Action, ResourceIdentity, ResourceKind, ResourceVendor};
use eltanin_protocol::framing::{
    decode_frame_len, decode_request, decode_response, encode_request, encode_response,
    FramingError, ProtocolError, MAX_FRAME_BYTES,
};
use eltanin_protocol::request::{ClientRequest, LeaseRequest, RequestBody, RequestId};
use eltanin_protocol::response::{AgentResponse, DenialReason, LeaseView, ResponseBody};

fn request_lease_request() -> eltanin_protocol::request::Request {
    Versioned::current(RequestBody {
        request_id: RequestId(42),
        body: ClientRequest::RequestLease(LeaseRequest {
            resource: ResourceIdentity {
                vendor: ResourceVendor::fake(),
                kind: ResourceKind::gpu(),
                local_id: "gpu-0".to_string(),
            },
            action: Action::Compute,
        }),
    })
}

#[test]
fn a_request_encoded_by_the_client_decodes_on_the_agent_side() {
    let request = request_lease_request();
    let framed = encode_request(&request).unwrap();
    let len = decode_frame_len(framed[..4].try_into().unwrap()).unwrap();
    let body = &framed[4..];
    assert_eq!(body.len(), len);
    let decoded = decode_request(body).unwrap();
    assert_eq!(decoded, request);
}

#[test]
fn a_response_encoded_by_the_agent_decodes_on_the_client_side() {
    let response = Versioned::current(ResponseBody {
        request_id: Some(RequestId(42)),
        body: AgentResponse::LeaseGranted {
            lease: LeaseView {
                lease_id: LeaseId {
                    issuer: IssuerInstanceId::new("agent-1"),
                    sequence: 0,
                },
                remaining: std::time::Duration::from_secs(60),
            },
        },
    });
    let framed = encode_response(&response).unwrap();
    let len = decode_frame_len(framed[..4].try_into().unwrap()).unwrap();
    let body = &framed[4..];
    assert_eq!(body.len(), len);
    let decoded = decode_response(body).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn a_denied_response_round_trips_through_the_client_direction() {
    let response = Versioned::current(ResponseBody {
        request_id: Some(RequestId(7)),
        body: AgentResponse::LeaseDenied {
            reason: DenialReason::ExplicitDeny,
        },
    });
    let framed = encode_response(&response).unwrap();
    let decoded = decode_response(&framed[4..]).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn encode_request_rejects_a_payload_over_the_max_without_writing_a_header() {
    // Mirrors protocol_fail_closed.rs's identical assertion for
    // encode_frame directly — here at the encode_request layer.
    let oversized_local_id = "x".repeat(MAX_FRAME_BYTES);
    let request = Versioned::current(RequestBody {
        request_id: RequestId(1),
        body: ClientRequest::RequestLease(LeaseRequest {
            resource: ResourceIdentity {
                vendor: ResourceVendor::fake(),
                kind: ResourceKind::gpu(),
                local_id: oversized_local_id,
            },
            action: Action::Compute,
        }),
    });
    assert!(matches!(
        encode_request(&request),
        Err(FramingError::Oversized { .. })
    ));
}

#[test]
fn decode_response_rejects_a_frame_exceeding_the_max_size() {
    let oversized = vec![b'x'; MAX_FRAME_BYTES + 1];
    assert_eq!(
        decode_response(&oversized).unwrap_err(),
        ProtocolError::Framing(FramingError::Oversized {
            len: MAX_FRAME_BYTES + 1,
            max: MAX_FRAME_BYTES,
        })
    );
}

#[test]
fn decode_response_reports_a_version_mismatch_precisely_even_with_a_malformed_payload() {
    let body = br#"{"version":99,"payload":{"request_id":1,"body":{"garbage":1}}}"#;
    let err = decode_response(body).unwrap_err();
    assert_eq!(
        err,
        ProtocolError::Version(eltanin_core::envelope::UnsupportedVersion {
            found: 99,
            expected: 1
        })
    );
}

#[test]
fn decode_response_fails_closed_as_malformed_on_an_unrecognized_shape() {
    let body =
        br#"{"version":1,"payload":{"request_id":1,"body":{"result":"not_a_real_variant"}}}"#;
    assert_eq!(decode_response(body).unwrap_err(), ProtocolError::Malformed);
}
