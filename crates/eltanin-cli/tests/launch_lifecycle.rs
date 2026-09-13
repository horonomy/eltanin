//! Binary-level launch/exit/cleanup lifecycle coverage (F-M1-008,
//! HORO-846) — drives the real `eltanin` binary against a scripted fake
//! agent over a real Unix Domain Socket.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eltanin_core::lease::{IssuerInstanceId, LeaseId};
use eltanin_core::resource::{Action, ResourceIdentity, ResourceKind, ResourceVendor};
use eltanin_protocol::request::ClientRequest;
use eltanin_protocol::response::{AgentResponse, DenialReason, LeaseView};
use rustix::process::{kill_process, Pid, Signal};
use support::fake_agent::FakeAgent;

fn resource() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-0".to_string(),
    }
}

fn lease_id(sequence: u64) -> LeaseId {
    LeaseId {
        issuer: IssuerInstanceId::new("fake-agent"),
        sequence,
    }
}

fn granted(sequence: u64, remaining_secs: u64) -> AgentResponse {
    AgentResponse::LeaseGranted {
        lease: LeaseView {
            lease_id: lease_id(sequence),
            remaining: Duration::from_secs(remaining_secs),
        },
    }
}

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = NEXT_DIR.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "eltanin-cli-launch-lifecycle-{}-{tag}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn profile_dir_with(resource: &ResourceIdentity, action: Action) -> PathBuf {
    let dir = temp_dir("profiles");
    let document = serde_json::json!({
        "version": eltanin_core::envelope::DOMAIN_SCHEMA_VERSION,
        "payload": { "resource": resource, "action": action },
    });
    std::fs::write(dir.join("test.json"), document.to_string()).unwrap();
    dir
}

/// Build (but do not run) a command for the real `eltanin` binary,
/// pointed at `agent` and `profile_dir`, launching `workload_argv`.
fn eltanin_command(agent: &FakeAgent, profile_dir: &Path, workload_argv: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_eltanin"));
    command
        .env("ELTANIN_AGENT_SOCKET", agent.socket_path())
        .env("ELTANIN_PROFILE_DIR", profile_dir)
        .arg("run")
        .arg("--profile")
        .arg("test")
        .arg("--")
        .args(workload_argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn run_to_completion(
    agent: &FakeAgent,
    profile_dir: &Path,
    workload_argv: &[&str],
) -> std::process::Output {
    eltanin_command(agent, profile_dir, workload_argv)
        .output()
        .expect("run eltanin binary")
}

fn sentinel_path(tag: &str) -> PathBuf {
    temp_dir("sentinel").join(format!("{tag}.marker"))
}

#[test]
fn a_denied_lease_never_spawns_the_workload() {
    let agent = FakeAgent::start(|_| AgentResponse::LeaseDenied {
        reason: DenialReason::ExplicitDeny,
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);
    let sentinel = sentinel_path("denied");

    let output = run_to_completion(
        &agent,
        &profile_dir,
        &["sh", "-c", &format!("touch {}", sentinel.display())],
    );

    assert_eq!(output.status.code(), Some(77));
    assert!(!sentinel.exists(), "the workload must never have run");
    assert_eq!(agent.requests().len(), 1);
    assert!(matches!(
        agent.requests()[0],
        ClientRequest::RequestLease(_)
    ));
}

#[test]
fn an_agent_error_never_spawns_the_workload() {
    let agent = FakeAgent::start(|_| AgentResponse::Error {
        code: eltanin_protocol::response::ErrorCode::Internal,
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);
    let sentinel = sentinel_path("agent-error");

    let output = run_to_completion(
        &agent,
        &profile_dir,
        &["sh", "-c", &format!("touch {}", sentinel.display())],
    );

    assert_eq!(output.status.code(), Some(70));
    assert!(!sentinel.exists());
    assert_eq!(agent.requests().len(), 1);
}

#[test]
fn an_unreachable_agent_exits_69_without_spawning() {
    let socket_path = std::env::temp_dir().join(format!(
        "eltanin-cli-nonexistent-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let profile_dir = profile_dir_with(&resource(), Action::Compute);
    let sentinel = sentinel_path("unreachable");

    let output = Command::new(env!("CARGO_BIN_EXE_eltanin"))
        .env("ELTANIN_AGENT_SOCKET", &socket_path)
        .env("ELTANIN_PROFILE_DIR", &profile_dir)
        .arg("run")
        .arg("--profile")
        .arg("test")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg(format!("touch {}", sentinel.display()))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(69));
    assert!(!sentinel.exists());
}

#[test]
fn a_granted_lease_spawns_and_passes_through_the_exit_status() {
    let requests_seen = Arc::new(Mutex::new(0u64));
    let agent = FakeAgent::start(move |_| {
        let mut n = requests_seen.lock().unwrap();
        *n += 1;
        if *n == 1 {
            granted(0, 60)
        } else {
            AgentResponse::LeaseReleased {
                outcome: eltanin_protocol::response::ReleaseOutcome::Released,
            }
        }
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);

    let output = run_to_completion(&agent, &profile_dir, &["sh", "-c", "exit 3"]);

    assert_eq!(output.status.code(), Some(3));
    let requests = agent.requests();
    assert_eq!(requests.len(), 2);
    assert!(matches!(requests[0], ClientRequest::RequestLease(_)));
    assert!(matches!(requests[1], ClientRequest::ReleaseLease(_)));
}

#[test]
fn a_zero_exit_status_passes_through() {
    let agent = FakeAgent::start(|request| match request {
        ClientRequest::RequestLease(_) => granted(0, 60),
        _ => AgentResponse::LeaseReleased {
            outcome: eltanin_protocol::response::ReleaseOutcome::Released,
        },
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);

    let output = run_to_completion(&agent, &profile_dir, &["true"]);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn a_signal_terminated_workload_exits_128_plus_n() {
    let agent = FakeAgent::start(|request| match request {
        ClientRequest::RequestLease(_) => granted(0, 60),
        _ => AgentResponse::LeaseReleased {
            outcome: eltanin_protocol::response::ReleaseOutcome::Released,
        },
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);

    // The workload sends itself SIGTERM (15).
    let output = run_to_completion(
        &agent,
        &profile_dir,
        &["sh", "-c", "kill -TERM $$; sleep 1"],
    );
    assert_eq!(output.status.code(), Some(128 + 15));

    let requests = agent.requests();
    assert!(
        requests
            .iter()
            .any(|r| matches!(r, ClientRequest::ReleaseLease(_))),
        "ReleaseLease must still be sent for a signal-terminated workload"
    );
}

#[test]
fn a_missing_workload_exits_127_and_still_releases() {
    let agent = FakeAgent::start(|request| match request {
        ClientRequest::RequestLease(_) => granted(0, 60),
        _ => AgentResponse::LeaseReleased {
            outcome: eltanin_protocol::response::ReleaseOutcome::Released,
        },
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);

    let output = run_to_completion(
        &agent,
        &profile_dir,
        &["/no/such/eltanin-test-workload-binary"],
    );
    assert_eq!(output.status.code(), Some(127));
    assert!(agent
        .requests()
        .iter()
        .any(|r| matches!(r, ClientRequest::ReleaseLease(_))));
}

#[test]
fn a_non_executable_workload_exits_126_and_still_releases() {
    let agent = FakeAgent::start(|request| match request {
        ClientRequest::RequestLease(_) => granted(0, 60),
        _ => AgentResponse::LeaseReleased {
            outcome: eltanin_protocol::response::ReleaseOutcome::Released,
        },
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);

    let not_executable = temp_dir("not-exec").join("workload");
    std::fs::write(&not_executable, "#!/bin/sh\necho hi\n").unwrap();
    // Deliberately no execute bit.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&not_executable, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    let output = run_to_completion(&agent, &profile_dir, &[not_executable.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(126));
    assert!(agent
        .requests()
        .iter()
        .any(|r| matches!(r, ClientRequest::ReleaseLease(_))));
}

#[test]
fn a_renewal_acquires_before_releasing_the_old_lease() {
    let call = Arc::new(Mutex::new(0u64));
    let agent = FakeAgent::start(move |request| {
        let mut n = call.lock().unwrap();
        *n += 1;
        match (*n, request) {
            (1, ClientRequest::RequestLease(_)) => granted(0, 4),
            (_, ClientRequest::RequestLease(_)) => granted(1, 60),
            (_, ClientRequest::ReleaseLease(_)) => AgentResponse::LeaseReleased {
                outcome: eltanin_protocol::response::ReleaseOutcome::Released,
            },
            _ => AgentResponse::Error {
                code: eltanin_protocol::response::ErrorCode::Internal,
            },
        }
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);

    // Sleeps past the renewal point (~2s, half of the 4s initial lease)
    // with a generous margin against a slow/loaded CI runner, but exits
    // well before the test itself times out.
    let output = run_to_completion(&agent, &profile_dir, &["sh", "-c", "sleep 6"]);
    assert_eq!(output.status.code(), Some(0));

    let requests = agent.requests();
    let ops: Vec<&str> = requests
        .iter()
        .map(|r| match r {
            ClientRequest::RequestLease(_) => "request",
            ClientRequest::ReleaseLease(_) => "release",
            ClientRequest::AgentStatus {} => "status",
            ClientRequest::CreateSession(_) => "create_session",
            ClientRequest::ListSessions {} => "list_sessions",
            ClientRequest::TerminateSession {} => "terminate_session",
            ClientRequest::Approve(_) => "approve",
            ClientRequest::ListApprovals {} => "list_approvals",
            ClientRequest::ForgetApproval(_) => "forget_approval",
        })
        .collect();
    assert_eq!(
        ops,
        vec!["request", "request", "release", "release"],
        "expected acquire-then-release ordering, got {ops:?}"
    );
    let release_ids: Vec<&LeaseId> = requests
        .iter()
        .filter_map(|r| match r {
            ClientRequest::ReleaseLease(release) => Some(&release.lease_id),
            _ => None,
        })
        .collect();
    assert_eq!(
        release_ids,
        vec![&lease_id(0), &lease_id(1)],
        "the old lease (sequence 0) must be released before the new one (sequence 1)"
    );
}

#[test]
fn a_renewal_denial_does_not_terminate_the_workload_early() {
    let call = Arc::new(Mutex::new(0u64));
    let agent = FakeAgent::start(move |request| {
        let mut n = call.lock().unwrap();
        *n += 1;
        match (*n, request) {
            (1, ClientRequest::RequestLease(_)) => granted(0, 2),
            (_, ClientRequest::RequestLease(_)) => AgentResponse::LeaseDenied {
                reason: DenialReason::NoMatchingRule,
            },
            _ => AgentResponse::LeaseReleased {
                outcome: eltanin_protocol::response::ReleaseOutcome::Released,
            },
        }
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);

    // Sleeps well past the ~1s renewal point (so the denial is
    // actually observed, not raced by the workload exiting first — the
    // sibling exhaustion test proves the 2s deadline itself is honored)
    // but still exits before the 2s deadline.
    let output = run_to_completion(&agent, &profile_dir, &["sh", "-c", "sleep 1.7"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a renewal denial must not terminate an already-authorized workload early"
    );

    let requests = agent.requests();
    let request_lease_count = requests
        .iter()
        .filter(|r| matches!(r, ClientRequest::RequestLease(_)))
        .count();
    assert!(
        request_lease_count >= 2,
        "expected at least one renewal attempt (and its denial) to actually occur, got only \
         {request_lease_count} RequestLease call(s): {requests:?}"
    );
}

#[test]
fn renewal_exhaustion_terminates_the_workload_and_exits_76() {
    let call = Arc::new(Mutex::new(0u64));
    let agent = FakeAgent::start(move |request| {
        let mut n = call.lock().unwrap();
        *n += 1;
        match (*n, request) {
            (1, ClientRequest::RequestLease(_)) => granted(0, 2),
            // Every renewal attempt is denied, so the deadline is never
            // pushed out — exhaustion is forced at the original grant's
            // 2s deadline.
            (_, ClientRequest::RequestLease(_)) => AgentResponse::LeaseDenied {
                reason: DenialReason::NoMatchingRule,
            },
            (_, ClientRequest::ReleaseLease(_)) => AgentResponse::LeaseReleased {
                outcome: eltanin_protocol::response::ReleaseOutcome::Released,
            },
            _ => AgentResponse::Error {
                code: eltanin_protocol::response::ErrorCode::Internal,
            },
        }
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);

    let output = run_to_completion(&agent, &profile_dir, &["sh", "-c", "sleep 30"]);
    assert_eq!(output.status.code(), Some(76));
}

#[test]
fn a_failed_release_warns_but_does_not_change_the_exit_status() {
    let agent = FakeAgent::start(|request| match request {
        ClientRequest::RequestLease(_) => granted(0, 60),
        _ => AgentResponse::Error {
            code: eltanin_protocol::response::ErrorCode::Internal,
        },
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);

    let output = run_to_completion(&agent, &profile_dir, &["sh", "-c", "exit 5"]);
    assert_eq!(output.status.code(), Some(5));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to release lease"),
        "expected a release-failure warning on stderr, got: {stderr}"
    );
    assert!(stderr.contains("eltanin-explain"));
}

#[test]
fn a_forwarded_sigterm_reaches_the_workload_exactly_once() {
    let agent = FakeAgent::start(|request| match request {
        ClientRequest::RequestLease(_) => granted(0, 60),
        _ => AgentResponse::LeaseReleased {
            outcome: eltanin_protocol::response::ReleaseOutcome::Released,
        },
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);
    let count_file = sentinel_path("sigterm-count");

    let child = eltanin_command(
        &agent,
        &profile_dir,
        &[
            "sh",
            "-c",
            &format!(
                "trap 'echo received >> {}' TERM; sleep 2",
                count_file.display()
            ),
        ],
    )
    .spawn()
    .expect("spawn eltanin");

    std::thread::sleep(Duration::from_millis(400));
    let eltanin_pid = Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    kill_process(eltanin_pid, Signal::TERM).expect("send SIGTERM to eltanin");

    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0));

    let contents = std::fs::read_to_string(&count_file).unwrap_or_default();
    let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines,
        vec!["received"],
        "expected the workload to receive exactly one forwarded SIGTERM"
    );
}
