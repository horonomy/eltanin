//! `AuditEventSink` coverage: every `AuthorizationOutcome` maps to a
//! distinct, correlatable record, a non-authorizable peer's record still
//! carries the discriminating `PeerConsistency`, and an audit write
//! failure never changes the response an already-computed decision
//! produced (F-M1-009, HORO-824 — best-effort durability, founder
//! decision).

mod support;

use std::sync::Arc;
use std::time::Duration;

use eltanin_agent::authz::audit::AuditEventSink;
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler};
use eltanin_agent::handler::RequestHandler;
use eltanin_audit::explain::{read_log, select, SelectionResult, Selector};
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::resource::Capability;
use eltanin_protocol::request::{ClientRequest, LeaseRequest, ReleaseRequest};
use eltanin_protocol::response::AgentResponse;
use support::authz::{
    allow_policy_for_uid, backend_with_resource, resource_identity, FixedClock, TestPeer,
};

fn temp_log(tag: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("eltanin-agent-audit-tests-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{tag}-{}.ndjson", std::process::id()))
}

fn lease_request() -> ClientRequest {
    ClientRequest::RequestLease(LeaseRequest {
        resource: resource_identity(),
        action: eltanin_core::resource::Action::Compute,
    })
}

#[test]
fn a_granted_and_released_lease_produce_correlated_distinct_records() {
    let log_path = temp_log("grant-release");
    let sink = Arc::new(AuditEventSink::open(&log_path, IssuerInstanceId::new("i")).unwrap());
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("i"),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        FixedClock::new(),
        sink,
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let granted = handler.handle(&lease_request(), &peer.context());
    let lease_id = match granted {
        AgentResponse::LeaseGranted { lease } => lease.lease_id,
        other => panic!("expected LeaseGranted, got {other:?}"),
    };
    let _ = handler.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest {
            lease_id: lease_id.clone(),
        }),
        &peer.context(),
    );

    let scan = read_log(&log_path).unwrap();
    assert_eq!(
        scan.records.len(),
        2,
        "grant and release must each produce one record"
    );
    match select(&scan, &Selector::Lease(lease_id)) {
        SelectionResult::Found(records) => assert_eq!(records.len(), 2),
        other => panic!("expected both records correlated by lease id, got {other:?}"),
    }
}

#[test]
fn a_non_authorizable_peer_record_still_carries_the_discriminating_consistency() {
    let log_path = temp_log("non-authorizable");
    let sink = Arc::new(AuditEventSink::open(&log_path, IssuerInstanceId::new("i")).unwrap());
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("i"),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
        FixedClock::new(),
        sink,
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let _ = handler.handle(&lease_request(), &peer.inconsistent_context());

    let scan = read_log(&log_path).unwrap();
    assert_eq!(scan.records.len(), 1);
    assert!(
        matches!(
            scan.records[0].peer.consistency,
            eltanin_audit::record::RecordedPeerConsistency::CredentialDivergence { .. }
        ),
        "expected the discriminating CredentialDivergence detail to be recorded, got {:?}",
        scan.records[0].peer.consistency
    );
}

struct AlwaysFailingWriter;

impl std::io::Write for AlwaysFailingWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("simulated disk failure"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("simulated disk failure"))
    }
}

#[test]
fn an_audit_write_failure_never_changes_the_already_computed_response() {
    let sink = Arc::new(AuditEventSink::from_writer(
        AlwaysFailingWriter,
        IssuerInstanceId::new("i"),
    ));
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("i"),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
        FixedClock::new(),
        Arc::clone(&sink) as Arc<dyn eltanin_agent::authz::event::EventSink>,
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let response = handler.handle(&lease_request(), &peer.context());
    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "an audit write failure must never change an already-computed authorization result, \
         got {response:?}"
    );
    assert_eq!(
        sink.failed_writes(),
        1,
        "the failure must be observable via failed_writes(), not silent"
    );

    // A denial must be equally unaffected by audit persistence failure.
    let denied_peer = TestPeer::fresh(2000, "sha256:untrusted");
    let response = handler.handle(&lease_request(), &denied_peer.context());
    assert!(
        matches!(response, AgentResponse::LeaseDenied { .. }),
        "a denial must also remain unaffected by audit persistence failure, got {response:?}"
    );
    assert_eq!(sink.failed_writes(), 2);
}
