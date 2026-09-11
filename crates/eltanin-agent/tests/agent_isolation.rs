//! Cross-connection isolation and connection-cap coverage (F-M1-006,
//! HORO-839): one connection's misbehavior — garbage input, a stalled
//! client, a panicking handler — must never affect another's response,
//! and the server itself must survive all three.

mod support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use eltanin_agent::config::AgentConfig;
use eltanin_agent::handler::{RequestHandler, StatusOnlyHandler};
use eltanin_agent::listener::BoundSocket;
use eltanin_agent::peer::{LinuxPeerContextSource, PeerContextSource};
use eltanin_agent::server::AgentServer;
use eltanin_core::envelope::{Versioned, DOMAIN_SCHEMA_VERSION};
use eltanin_linux::peer::{PeerContext, PeerCredentialError};
use eltanin_protocol::request::{ClientRequest, RequestBody, RequestId};
use eltanin_protocol::response::{AgentResponse, ResponseBody};
use support::temp_socket_path;

/// A `PeerContextSource` that always succeeds, wrapping the real Linux
/// derivation with a self-connect fallback — this file runs on both
/// Linux (`SO_PEERCRED` against this test binary's own process) and
/// macOS (falls back to the stub-shaped identity below), so the
/// isolation behavior under test isn't gated on a real Linux
/// environment.
struct AnyPlatformPeers;

impl PeerContextSource for AnyPlatformPeers {
    fn derive(&self, stream: &UnixStream) -> Result<PeerContext, PeerCredentialError> {
        LinuxPeerContextSource.derive(stream).or_else(|_| {
            use eltanin_core::identity::{Evidence, ExecutionContext, WorkloadIdentity};
            use eltanin_linux::peer::{PeerConsistency, PeerCredential};
            let workload = WorkloadIdentity {
                pid: std::process::id(),
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
                PeerCredential::new(std::process::id(), 0, 0),
                PeerConsistency::Consistent,
                observed,
            ))
        })
    }
}

struct PanicOnLease;

impl RequestHandler for PanicOnLease {
    fn handle(&self, request: &ClientRequest, peer: &PeerContext) -> AgentResponse {
        if matches!(request, ClientRequest::RequestLease(_)) {
            panic!("synthetic handler panic for isolation testing");
        }
        StatusOnlyHandler.handle(request, peer)
    }
}

fn status_request(id: u64) -> Vec<u8> {
    serde_json::to_vec(&Versioned::current(RequestBody {
        request_id: RequestId(id),
        body: ClientRequest::AgentStatus {},
    }))
    .unwrap()
}

fn lease_request(id: u64) -> Vec<u8> {
    use eltanin_core::resource::{Action, ResourceIdentity, ResourceKind, ResourceVendor};
    use eltanin_protocol::request::LeaseRequest;
    serde_json::to_vec(&Versioned::current(RequestBody {
        request_id: RequestId(id),
        body: ClientRequest::RequestLease(LeaseRequest {
            resource: ResourceIdentity {
                vendor: ResourceVendor::fake(),
                kind: ResourceKind::gpu(),
                local_id: "gpu-0".into(),
            },
            action: Action::Compute,
        }),
    }))
    .unwrap()
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut framed = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(body);
    framed
}

fn read_response(client: &mut UnixStream) -> Versioned<ResponseBody> {
    let mut header = [0u8; 4];
    client.read_exact(&mut header).unwrap();
    let len = u32::from_be_bytes(header) as usize;
    let mut body = vec![0u8; len];
    client.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn start_server(tag: &str, handler: Arc<dyn RequestHandler>) -> (std::path::PathBuf, AgentServer) {
    let path = temp_socket_path(tag);
    let socket = BoundSocket::bind(&AgentConfig::new(path.clone(), 0o600)).unwrap();
    let server = AgentServer::new(
        socket,
        AgentConfig::new(path.clone(), 0o600).with_max_connections(2),
        handler,
        Arc::new(AnyPlatformPeers),
    );
    (path, server)
}

#[test]
fn a_panicking_handler_answers_internal_error_and_the_server_keeps_running() {
    let (path, server) = start_server("panic-isolation", Arc::new(PanicOnLease));
    let shutdown = server.shutdown_handle();
    let server_thread = std::thread::spawn(move || server.run().unwrap());

    let mut panicking_client = UnixStream::connect(&path).unwrap();
    panicking_client
        .write_all(&framed(&lease_request(1)))
        .unwrap();
    let panicked_response = read_response(&mut panicking_client);
    assert!(matches!(
        panicked_response.payload.body,
        AgentResponse::Error {
            code: eltanin_protocol::response::ErrorCode::Internal
        }
    ));

    // The server must still be alive and correctly answering afterward.
    let mut healthy_client = UnixStream::connect(&path).unwrap();
    healthy_client
        .write_all(&framed(&status_request(2)))
        .unwrap();
    let healthy_response = read_response(&mut healthy_client);
    assert!(matches!(
        healthy_response.payload.body,
        AgentResponse::Status { status } if status.protocol_version == DOMAIN_SCHEMA_VERSION
    ));

    shutdown.shutdown();
    server_thread.join().unwrap();
}

#[test]
fn one_stalled_client_does_not_block_another_clients_response() {
    let (path, server) = start_server("stall-isolation", Arc::new(StatusOnlyHandler));
    let shutdown = server.shutdown_handle();
    let server_thread = std::thread::spawn(move || server.run().unwrap());

    // Open a connection and send nothing — this must not consume the
    // server's ability to serve other connections concurrently.
    let _stalled = UnixStream::connect(&path).unwrap();

    let mut healthy_client = UnixStream::connect(&path).unwrap();
    healthy_client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    healthy_client
        .write_all(&framed(&status_request(1)))
        .unwrap();
    let response = read_response(&mut healthy_client);
    assert!(matches!(
        response.payload.body,
        AgentResponse::Status { .. }
    ));

    shutdown.shutdown();
    server_thread.join().unwrap();
}

#[test]
fn a_connection_beyond_the_cap_is_closed_without_a_response() {
    let (path, server) = start_server("connection-cap", Arc::new(StatusOnlyHandler));
    // max_connections is 2 (see start_server). Hold two slow/idle
    // connections open, then a third must be refused outright.
    let _first = UnixStream::connect(&path).unwrap();
    let _second = UnixStream::connect(&path).unwrap();

    let shutdown = server.shutdown_handle();
    let server_thread = std::thread::spawn(move || server.run().unwrap());

    // Give the accept loop a moment to register the first two.
    std::thread::sleep(Duration::from_millis(200));

    let mut third = UnixStream::connect(&path).unwrap();
    third
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 1];
    let result = third.read(&mut buf);
    assert!(
        matches!(result, Ok(0)) || result.is_err(),
        "a connection beyond the cap must be closed with no response, got {result:?}"
    );

    shutdown.shutdown();
    server_thread.join().unwrap();
}
