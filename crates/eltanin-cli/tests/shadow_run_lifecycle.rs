//! Binary-level coverage for `eltanin run`'s shadow-mode leg (F-M2-006,
//! HORO-796 subtask 4) — mirrors `launch_lifecycle.rs`'s own conventions
//! exactly, but scripts the fake agent to answer `ShadowObserved`
//! instead of `LeaseGranted`/`LeaseDenied`.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use eltanin_core::resource::{Action, ResourceIdentity, ResourceKind, ResourceVendor};
use eltanin_protocol::request::ClientRequest;
use eltanin_protocol::response::{AgentResponse, ShadowVerdict};
use support::fake_agent::FakeAgent;

fn resource() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-0".to_string(),
    }
}

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = NEXT_DIR.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "eltanin-cli-shadow-run-{}-{tag}-{n}",
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

fn run_shadow(
    agent: &FakeAgent,
    profile_dir: &Path,
    workload_argv: &[&str],
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_eltanin"))
        .env("ELTANIN_AGENT_SOCKET", agent.socket_path())
        .env("ELTANIN_PROFILE_DIR", profile_dir)
        .arg("run")
        .arg("--profile")
        .arg("test")
        .arg("--")
        .args(workload_argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run eltanin binary")
}

#[test]
fn a_shadow_would_allow_response_still_spawns_the_workload() {
    let agent = FakeAgent::start(|_| AgentResponse::ShadowObserved {
        verdict: ShadowVerdict::WouldAllow,
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);
    let sentinel = temp_dir("sentinel").join("marker");

    let output = run_shadow(
        &agent,
        &profile_dir,
        &["sh", "-c", &format!("touch {}", sentinel.display())],
    );

    assert_eq!(output.status.code(), Some(0));
    assert!(
        sentinel.exists(),
        "shadow mode must never block the workload from running"
    );
}

#[test]
fn a_shadow_would_deny_response_still_spawns_the_workload() {
    // The defining property of shadow mode: even a verdict that would
    // have been a real denial under Enforce mode does not block anything
    // here — it is only ever observed.
    let agent = FakeAgent::start(|_| AgentResponse::ShadowObserved {
        verdict: ShadowVerdict::WouldDeny,
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);
    let sentinel = temp_dir("sentinel").join("marker");

    let output = run_shadow(
        &agent,
        &profile_dir,
        &["sh", "-c", &format!("touch {}", sentinel.display())],
    );

    assert_eq!(output.status.code(), Some(0));
    assert!(
        sentinel.exists(),
        "a WouldDeny verdict must still not block the workload in shadow mode"
    );
}

#[test]
fn a_shadow_run_prints_an_unenforced_banner_naming_the_verdict() {
    let agent = FakeAgent::start(|_| AgentResponse::ShadowObserved {
        verdict: ShadowVerdict::WouldStepUp,
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);

    let output = run_shadow(&agent, &profile_dir, &["true"]);
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("UNENFORCED/OBSERVED-ONLY"), "got: {stderr}");
    assert!(stderr.contains("would-step-up"), "got: {stderr}");
}

#[test]
fn a_shadow_run_passes_through_the_workloads_own_exit_status() {
    let agent = FakeAgent::start(|_| AgentResponse::ShadowObserved {
        verdict: ShadowVerdict::WouldAllow,
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);

    let output = run_shadow(&agent, &profile_dir, &["sh", "-c", "exit 7"]);
    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn a_shadow_run_never_sends_release_lease_since_nothing_was_granted() {
    let agent = FakeAgent::start(|_| AgentResponse::ShadowObserved {
        verdict: ShadowVerdict::WouldAllow,
    });
    let profile_dir = profile_dir_with(&resource(), Action::Compute);

    let output = run_shadow(&agent, &profile_dir, &["true"]);
    assert_eq!(output.status.code(), Some(0));

    let requests = agent.requests();
    assert_eq!(requests.len(), 1, "got: {requests:?}");
    assert!(matches!(requests[0], ClientRequest::RequestLease(_)));
    assert!(
        !requests
            .iter()
            .any(|r| matches!(r, ClientRequest::ReleaseLease(_))),
        "shadow mode granted nothing, so nothing should ever be released: {requests:?}"
    );
}
