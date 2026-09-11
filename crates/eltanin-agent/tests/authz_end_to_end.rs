//! Linux-only end-to-end coverage: a real `UnixStream`, real
//! `SO_PEERCRED` credential derivation via [`LinuxPeerContextSource`],
//! through [`serve_connection`], into a real [`AuthorizationHandler`]
//! (F-M1-006, HORO-840). Every other `authz_*.rs` test calls
//! `AuthorizationHandler::handle` directly with a stub `PeerContext` —
//! this file is the one place the whole stack is exercised together
//! over an actual socket, on `target_os = "linux"` only (this repo's
//! `ubuntu-latest` CI runner), matching the pattern already established
//! by `crates/eltanin-linux/tests/peer_credential.rs`.

#![cfg(target_os = "linux")]

mod support;

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;

use eltanin_agent::authz::event::NullSink;
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler};
use eltanin_agent::connection::serve_connection;
use eltanin_agent::peer::LinuxPeerContextSource;
use eltanin_backend::fake::FakeBackend;
use eltanin_core::envelope::Versioned;
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::policy::{Condition, Effect, EvidenceMatch, PolicyDocument, PolicyId, PolicySet, Rule, RuleId, TrustFloor};
use eltanin_core::resource::{Action, Capability, ProtectedResource, ResourceCapabilities};
use eltanin_protocol::request::{ClientRequest, LeaseRequest, RequestBody, RequestId};
use eltanin_protocol::response::{AgentResponse, ResponseBody};
use support::authz::resource_identity;
use support::temp_socket_path;

fn real_uid() -> u32 {
    let identity = eltanin_linux::collect_workload_identity(std::process::id());
    identity
        .uid
        .value()
        .copied()
        .expect("this process's own /proc uid must be observable in CI")
}

fn policy_allowing_this_process() -> PolicySet {
    let rule = Rule {
        id: RuleId::new("allow-self"),
        effect: Effect::Allow,
        resource: resource_identity(),
        action: Action::Compute,
        conditions: vec![Condition::Uid(EvidenceMatch {
            expected: real_uid(),
            min_trust: TrustFloor::KernelObserved,
        })],
    };
    let document = PolicyDocument {
        id: PolicyId::new("end-to-end"),
        revision: 1,
        rules: vec![rule],
    };
    PolicySet::from_document(document).expect("valid policy")
}

fn send(client: &mut UnixStream, request: &ClientRequest, id: u64) {
    let body = serde_json::to_vec(&Versioned::current(RequestBody {
        request_id: RequestId(id),
        body: request.clone(),
    }))
    .unwrap();
    let len = u32::try_from(body.len()).unwrap();
    client.write_all(&len.to_be_bytes()).unwrap();
    client.write_all(&body).unwrap();
}

fn recv(client: &mut UnixStream) -> AgentResponse {
    let mut header = [0u8; 4];
    client.read_exact(&mut header).unwrap();
    let len = u32::from_be_bytes(header) as usize;
    let mut body = vec![0u8; len];
    client.read_exact(&mut body).unwrap();
    let envelope: Versioned<ResponseBody> = serde_json::from_slice(&body).unwrap();
    envelope.into_current().unwrap().body
}

#[test]
fn a_real_peer_over_a_real_socket_is_granted_a_lease_via_the_fake_backend() {
    let backend = Arc::new(FakeBackend::new());
    backend.insert(ProtectedResource {
        identity: resource_identity(),
        capabilities: ResourceCapabilities::new([Capability::Enforce, Capability::Revoke]),
    });
    let handler = Arc::new(AuthorizationHandler::new(
        IssuerInstanceId::new("end-to-end-instance"),
        policy_allowing_this_process(),
        backend,
        Arc::new(eltanin_agent::runtime::AgentClock::new()),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    ));

    let path = temp_socket_path("authz-e2e");
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _addr) = listener.accept().unwrap();
        serve_connection(
            stream,
            Duration::from_secs(2),
            handler.as_ref(),
            &LinuxPeerContextSource,
        );
    });

    let mut client = UnixStream::connect(&path).unwrap();
    send(
        &mut client,
        &ClientRequest::RequestLease(LeaseRequest {
            resource: resource_identity(),
            action: Action::Compute,
        }),
        1,
    );
    let response = recv(&mut client);
    server.join().unwrap();

    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "expected LeaseGranted for this process's own real peer credential, got {response:?}"
    );
}
