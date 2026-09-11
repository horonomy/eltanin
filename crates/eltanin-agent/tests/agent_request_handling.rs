//! Malformed/oversized/version fail-closed coverage over a real socket
//! (F-M1-006, HORO-839). Uses a stub [`PeerContextSource`] throughout so
//! this file is platform-neutral — no real Linux `/proc`/`SO_PEERCRED`
//! environment is needed to validate the transport's own behavior.

mod support;

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

use eltanin_agent::connection::serve_connection;
use eltanin_agent::handler::StatusOnlyHandler;
use eltanin_agent::peer::PeerContextSource;
use eltanin_core::envelope::{Versioned, DOMAIN_SCHEMA_VERSION};
use eltanin_core::identity::{Evidence, ExecutionContext, WorkloadIdentity};
use eltanin_linux::peer::{PeerConsistency, PeerContext, PeerCredential, PeerCredentialError};
use eltanin_protocol::request::{ClientRequest, RequestBody, RequestId};
use eltanin_protocol::response::{AgentResponse, ErrorCode, ResponseBody};
use support::temp_socket_path;

struct StubPeers;

impl PeerContextSource for StubPeers {
    fn derive(&self, _stream: &UnixStream) -> Result<PeerContext, PeerCredentialError> {
        let workload = WorkloadIdentity {
            pid: 4242,
            process_start: Evidence::Unsupported,
            uid: Evidence::Unsupported,
            gid: Evidence::Unsupported,
            executable_path: Evidence::Unsupported,
            executable_hash: Evidence::Unsupported,
            ancestry: Vec::new(),
        };
        let observed = ExecutionContext {
            workload,
            cgroup_path: Evidence::Unsupported,
            namespace_hint: Evidence::Unsupported,
            container_hint: Evidence::Unsupported,
            session_origin: Evidence::Unsupported,
        };
        Ok(PeerContext::new(
            PeerCredential::new(4242, 1000, 1000),
            PeerConsistency::Consistent,
            observed,
        ))
    }
}

/// Bind a listener, spawn one `serve_connection` call for the next
/// accepted stream, and return a connected client stream plus the
/// server thread's handle.
fn serve_one(tag: &str) -> (UnixStream, std::thread::JoinHandle<()>) {
    let path = temp_socket_path(tag);
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _addr) = listener.accept().unwrap();
        serve_connection(
            stream,
            Duration::from_secs(2),
            &StatusOnlyHandler,
            &StubPeers,
        );
    });
    let client = UnixStream::connect(&path).unwrap();
    (client, server)
}

fn send_raw(client: &mut UnixStream, body: &[u8]) {
    let len = u32::try_from(body.len()).unwrap();
    client.write_all(&len.to_be_bytes()).unwrap();
    client.write_all(body).unwrap();
}

fn read_response(client: &mut UnixStream) -> Versioned<ResponseBody> {
    let mut header = [0u8; 4];
    client.read_exact(&mut header).unwrap();
    let len = u32::from_be_bytes(header) as usize;
    let mut body = vec![0u8; len];
    client.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn status_request(id: u64) -> Vec<u8> {
    serde_json::to_vec(&Versioned::current(RequestBody {
        request_id: RequestId(id),
        body: ClientRequest::AgentStatus {},
    }))
    .unwrap()
}

#[test]
fn a_well_formed_agent_status_round_trips_with_the_correct_id() {
    let (mut client, server) = serve_one("status-roundtrip");
    send_raw(&mut client, &status_request(7));
    let response = read_response(&mut client);

    assert_eq!(response.payload.request_id, Some(RequestId(7)));
    assert!(matches!(
        response.payload.body,
        AgentResponse::Status { status } if status.protocol_version == DOMAIN_SCHEMA_VERSION
    ));
    server.join().unwrap();
}

#[test]
fn garbage_non_json_reports_malformed_with_no_id() {
    let (mut client, server) = serve_one("garbage-non-json");
    send_raw(&mut client, b"not json at all");
    let response = read_response(&mut client);

    assert_eq!(response.payload.request_id, None);
    assert!(matches!(
        response.payload.body,
        AgentResponse::Error {
            code: ErrorCode::MalformedRequest
        }
    ));
    server.join().unwrap();
}

#[test]
fn a_malformed_body_with_a_valid_envelope_recovers_the_request_id() {
    let (mut client, server) = serve_one("malformed-body-recovers-id");
    let body = format!(
        r#"{{"version":{DOMAIN_SCHEMA_VERSION},"payload":{{"request_id":99,"body":{{"op":"request_lease","garbage":true}}}}}}"#
    );
    send_raw(&mut client, body.as_bytes());
    let response = read_response(&mut client);

    assert_eq!(response.payload.request_id, Some(RequestId(99)));
    assert!(matches!(
        response.payload.body,
        AgentResponse::Error {
            code: ErrorCode::MalformedRequest
        }
    ));
    server.join().unwrap();
}

#[test]
fn an_unsupported_version_names_found_and_expected() {
    let (mut client, server) = serve_one("unsupported-version");
    let body = r#"{"version":99,"payload":{"request_id":3,"body":{"op":"agent_status"}}}"#;
    send_raw(&mut client, body.as_bytes());
    let response = read_response(&mut client);

    assert_eq!(response.payload.request_id, Some(RequestId(3)));
    assert!(matches!(
        response.payload.body,
        AgentResponse::Error {
            code: ErrorCode::UnsupportedVersion { found: 99, expected }
        } if expected == DOMAIN_SCHEMA_VERSION
    ));
    server.join().unwrap();
}

#[test]
fn an_unknown_operation_fails_closed_as_malformed() {
    let (mut client, server) = serve_one("unknown-op");
    let body = format!(
        r#"{{"version":{DOMAIN_SCHEMA_VERSION},"payload":{{"request_id":1,"body":{{"op":"delete_everything"}}}}}}"#
    );
    send_raw(&mut client, body.as_bytes());
    let response = read_response(&mut client);

    assert!(matches!(
        response.payload.body,
        AgentResponse::Error {
            code: ErrorCode::MalformedRequest
        }
    ));
    server.join().unwrap();
}

#[test]
fn a_truncated_header_fails_closed_as_malformed() {
    let path = temp_socket_path("truncated-header");
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _addr) = listener.accept().unwrap();
        serve_connection(
            stream,
            Duration::from_millis(300),
            &StatusOnlyHandler,
            &StubPeers,
        );
    });
    let mut client = UnixStream::connect(&path).unwrap();
    client.write_all(&[0u8, 1]).unwrap(); // 2 of 4 header bytes, then stall
    let response = read_response(&mut client);

    assert!(matches!(
        response.payload.body,
        AgentResponse::Error {
            code: ErrorCode::MalformedRequest
        }
    ));
    server.join().unwrap();
}

#[test]
fn a_truncated_body_fails_closed_as_malformed() {
    let path = temp_socket_path("truncated-body");
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _addr) = listener.accept().unwrap();
        serve_connection(
            stream,
            Duration::from_millis(300),
            &StatusOnlyHandler,
            &StubPeers,
        );
    });
    let mut client = UnixStream::connect(&path).unwrap();
    let full = status_request(1);
    let len = u32::try_from(full.len()).unwrap();
    client.write_all(&len.to_be_bytes()).unwrap();
    client.write_all(&full[..full.len() / 2]).unwrap(); // half the body, then stall
    let response = read_response(&mut client);

    assert!(matches!(
        response.payload.body,
        AgentResponse::Error {
            code: ErrorCode::MalformedRequest
        }
    ));
    server.join().unwrap();
}

#[test]
fn trailing_bytes_after_a_valid_document_fail_closed_as_malformed() {
    let (mut client, server) = serve_one("trailing-bytes");
    let mut body = status_request(1);
    body.extend_from_slice(b"{}");
    send_raw(&mut client, &body);
    let response = read_response(&mut client);

    assert!(matches!(
        response.payload.body,
        AgentResponse::Error {
            code: ErrorCode::MalformedRequest
        }
    ));
    server.join().unwrap();
}

#[test]
fn an_oversized_frame_is_rejected_promptly_before_the_body_is_ever_read() {
    // The load-bearing assertion is *promptness*: "responds Oversized
    // eventually" would pass even if the implementation read the whole
    // body first, which is exactly the allocation-DoS behavior
    // framing.rs's named obligation on this crate exists to prevent.
    let path = temp_socket_path("oversized-promptness");
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _addr) = listener.accept().unwrap();
        serve_connection(
            stream,
            Duration::from_secs(30),
            &StatusOnlyHandler,
            &StubPeers,
        );
    });
    let mut client = UnixStream::connect(&path).unwrap();

    let huge_len: u32 = 10 * 1024 * 1024;
    let start = Instant::now();
    client.write_all(&huge_len.to_be_bytes()).unwrap();
    // Deliberately send no body — a slow/adversarial client, or one
    // that will never send 10 MB at all.
    let response = read_response(&mut client);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "Oversized must be reported promptly from the length header alone, took {elapsed:?}"
    );
    assert!(matches!(
        response.payload.body,
        AgentResponse::Error {
            code: ErrorCode::Oversized
        }
    ));
    server.join().unwrap();
}
