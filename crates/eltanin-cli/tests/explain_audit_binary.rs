//! Binary-level coverage for `eltanin explain`/`eltanin audit`
//! (F-M2-006, HORO-796 subtask 4) — drives the real `eltanin` binary
//! against a real on-disk audit log built with
//! `eltanin_audit::sink::AuditFileSink`, mirroring
//! `crates/eltanin-audit/tests/explain_selectors.rs`'s own fixtures one
//! layer up (through the CLI, not the library).

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use eltanin_audit::record::{
    AuditEventId, RecordedAgentEvent, RecordedEnforcementMode, RecordedOperation, RecordedOutcome,
    RecordedPeer, RecordedPeerConsistency, RecordedPeerCredential, RecordedRequest,
};
use eltanin_audit::sink::{AuditEntry, AuditFileSink};
use eltanin_core::identity::{Evidence, ExecutionContext, WorkloadIdentity};
use eltanin_core::lease::{IssuerInstanceId, LeaseId, MonotonicTime, RevocationOutcome};
use eltanin_core::resource::{Action, ResourceIdentity, ResourceKind, ResourceVendor};
use eltanin_protocol::response::{
    AgentResponse, AgentStatusView, EnforcementMode, LeaseView, ReleaseOutcome,
};

fn temp_log_path(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "eltanin-cli-audit-explain-{}-{tag}-{n}.ndjson",
        std::process::id()
    ))
}

fn peer(pid: u32) -> RecordedPeer {
    RecordedPeer {
        credential: RecordedPeerCredential {
            pid,
            effective_uid: 1000,
            effective_gid: 1000,
        },
        consistency: RecordedPeerConsistency::Consistent,
        observed: ExecutionContext {
            workload: WorkloadIdentity {
                pid,
                process_start: Evidence::Unsupported,
                uid: Evidence::Unsupported,
                gid: Evidence::Unsupported,
                executable_path: Evidence::Unsupported,
                executable_hash: Evidence::Unsupported,
                ancestry: Vec::new(),
            },
            cgroup_path: Evidence::Unsupported,
            namespace_hint: Evidence::Unsupported,
            container_hint: Evidence::Unsupported,
            session_origin: Evidence::Unsupported,
        },
    }
}

fn resource() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-0".to_string(),
    }
}

fn status_entry(pid: u32) -> AuditEntry {
    AuditEntry {
        operation: RecordedOperation::AgentStatus,
        requested: RecordedRequest::AgentStatus,
        peer: peer(pid),
        outcome: RecordedOutcome::StatusReported,
        response: AgentResponse::Status {
            status: AgentStatusView {
                protocol_version: 1,
                enforcement_mode: EnforcementMode::Enforce,
                session_required: false,
                approval_required: false,
                revocation_required: false,
            },
        },
        mode: RecordedEnforcementMode::Enforce,
        session: None,
    }
}

fn eltanin(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_eltanin"))
        .args(args)
        .output()
        .expect("run eltanin binary")
}

#[test]
fn explain_finds_a_record_by_pid() {
    let path = temp_log_path("by-pid");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap();
    sink.append(status_entry(4242)).unwrap();

    let output = eltanin(&["explain", "--pid", "4242", "--log", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pid=4242"), "got: {stdout}");
}

#[test]
fn explain_reports_not_found_as_a_clean_success() {
    let path = temp_log_path("not-found");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap();
    sink.append(status_entry(1)).unwrap();

    let output = eltanin(&[
        "explain",
        "--pid",
        "999999",
        "--log",
        path.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no matching record found"), "got: {stdout}");
}

#[test]
fn explain_against_a_nonexistent_log_is_a_clean_success_not_a_failure() {
    let path = temp_log_path("nonexistent");
    let output = eltanin(&["explain", "--pid", "1", "--log", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no audit log found"), "got: {stdout}");
}

#[test]
fn explain_against_an_unreadable_path_exits_71() {
    // A directory can never be read as a log file — a real, distinct
    // I/O failure from "does not exist," exercising the
    // LaunchFailure::AuditLogUnavailable path rather than the "no log
    // yet" one.
    let path = temp_log_path("unreadable-dir");
    std::fs::create_dir_all(&path).unwrap();

    let output = eltanin(&["explain", "--pid", "1", "--log", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(71));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("could not read the audit log"),
        "got: {stderr}"
    );
}

#[test]
fn explain_chain_pulls_in_the_originating_grant_for_a_release_record() {
    let path = temp_log_path("chain-lease");
    let instance = IssuerInstanceId::new("i");
    let sink = AuditFileSink::open(&path, instance.clone()).unwrap();
    let lease_id = LeaseId {
        issuer: instance.clone(),
        sequence: 0,
    };

    let grant_id = sink
        .append(AuditEntry {
            operation: RecordedOperation::RequestLease,
            requested: RecordedRequest::RequestLease {
                resource: resource(),
                action: Action::Compute,
            },
            peer: peer(4242),
            outcome: RecordedOutcome::Granted {
                lease_id: lease_id.clone(),
                expires_at: MonotonicTime::from_nanos(1),
            },
            response: AgentResponse::LeaseGranted {
                lease: LeaseView {
                    lease_id: lease_id.clone(),
                    remaining: Duration::from_secs(1),
                },
            },
            mode: RecordedEnforcementMode::Enforce,
            session: None,
        })
        .unwrap();
    let release_id = sink
        .append(AuditEntry {
            operation: RecordedOperation::ReleaseLease,
            requested: RecordedRequest::ReleaseLease {
                lease_id: lease_id.clone(),
            },
            peer: peer(4242),
            outcome: RecordedOutcome::Released {
                revocation: RevocationOutcome::Revoked,
                backend: None,
            },
            response: AgentResponse::LeaseReleased {
                outcome: ReleaseOutcome::Released,
            },
            mode: RecordedEnforcementMode::Enforce,
            session: None,
        })
        .unwrap();
    assert_ne!(grant_id, release_id);

    // Without --chain, selecting the release event by id finds only that
    // one record.
    let without_chain = eltanin(&[
        "explain",
        "--event",
        &release_id.to_string(),
        "--log",
        path.to_str().unwrap(),
    ]);
    assert_eq!(without_chain.status.code(), Some(0));
    let stdout_no_chain = String::from_utf8_lossy(&without_chain.stdout);
    assert_eq!(
        stdout_no_chain.matches("event: ").count(),
        1,
        "got: {stdout_no_chain}"
    );

    // With --chain, the originating grant is pulled in too.
    let with_chain = eltanin(&[
        "explain",
        "--event",
        &release_id.to_string(),
        "--chain",
        "--log",
        path.to_str().unwrap(),
    ]);
    assert_eq!(with_chain.status.code(), Some(0));
    let stdout_chain = String::from_utf8_lossy(&with_chain.stdout);
    assert_eq!(
        stdout_chain.matches("event: ").count(),
        2,
        "expected --chain to also surface the originating grant, got: {stdout_chain}"
    );
    assert!(
        stdout_chain.contains(&grant_id.to_string()),
        "got: {stdout_chain}"
    );
}

#[test]
fn audit_orders_most_recent_first_and_respects_limit() {
    let path = temp_log_path("ordering");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap();
    for pid in [1, 2, 3] {
        sink.append(status_entry(pid)).unwrap();
    }

    let output = eltanin(&["audit", "--limit", "2", "--log", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pos3 = stdout.find("pid=3").expect("pid=3 present");
    let pos2 = stdout.find("pid=2").expect("pid=2 present");
    assert!(
        !stdout.contains("pid=1"),
        "--limit 2 must exclude the oldest of 3 entries, got: {stdout}"
    );
    assert!(
        pos3 < pos2,
        "expected the most recently written entry (pid=3) first, got: {stdout}"
    );
}

#[test]
fn audit_against_a_nonexistent_log_is_a_clean_success() {
    let path = temp_log_path("audit-nonexistent");
    let output = eltanin(&["audit", "--log", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no audit log found"), "got: {stdout}");
}

#[test]
fn audit_renders_agent_events_alongside_decisions() {
    let path = temp_log_path("agent-events");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap();
    sink.append(status_entry(1)).unwrap();
    sink.append_agent_event(RecordedAgentEvent::AuditLogRotated {
        rotated_at_sequence: 1,
        discarded_through_sequence: None,
    })
    .unwrap();

    let output = eltanin(&["audit", "--log", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("audit log rotated"), "got: {stdout}");
    assert!(stdout.contains("pid=1"), "got: {stdout}");
}

/// Confirms this file's constructed [`AuditEventId`]s actually differ —
/// a mutation-style self-check for `explain_chain_pulls_in_the_originating_grant_for_a_release_record`:
/// if `AuditFileSink::append` ever stopped minting distinct sequence
/// numbers per call, that test's `assert_ne!` would catch it directly,
/// but this makes the assumption explicit on its own.
#[test]
fn two_appends_to_the_same_sink_mint_distinct_event_ids() {
    let path = temp_log_path("distinct-ids");
    let sink = AuditFileSink::open(&path, IssuerInstanceId::new("i")).unwrap();
    let a: AuditEventId = sink.append(status_entry(1)).unwrap();
    let b: AuditEventId = sink.append(status_entry(2)).unwrap();
    assert_ne!(a, b);
}
