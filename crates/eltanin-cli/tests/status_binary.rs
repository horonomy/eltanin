//! Binary-level coverage for `eltanin status` (F-M2-006, HORO-796
//! subtask 4) — drives the real `eltanin` binary against a scripted fake
//! agent, mirroring `launch_lifecycle.rs`'s own conventions.

mod support;

use std::process::Command;

use eltanin_protocol::response::{AgentResponse, AgentStatusView, EnforcementMode};
use support::fake_agent::FakeAgent;

fn eltanin_status(agent: &FakeAgent) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_eltanin"))
        .env("ELTANIN_AGENT_SOCKET", agent.socket_path())
        .arg("status")
        .output()
        .expect("run eltanin binary")
}

#[test]
fn status_reports_enforce_mode() {
    let agent = FakeAgent::start(|_| AgentResponse::Status {
        status: AgentStatusView {
            protocol_version: 6,
            enforcement_mode: EnforcementMode::Enforce,
            session_required: false,
            approval_required: false,
            revocation_required: false,
            delegation_configured: false,
            step_up_configured: false,
        },
    });

    let output = eltanin_status(&agent);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("enforce"), "got: {stdout}");
    assert!(!stdout.to_lowercase().contains("shadow"), "got: {stdout}");
}

#[test]
fn status_reports_shadow_mode_with_an_unenforced_warning() {
    let agent = FakeAgent::start(|_| AgentResponse::Status {
        status: AgentStatusView {
            protocol_version: 6,
            enforcement_mode: EnforcementMode::Shadow,
            session_required: false,
            approval_required: false,
            revocation_required: false,
            delegation_configured: false,
            step_up_configured: false,
        },
    });

    let output = eltanin_status(&agent);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("shadow"), "got: {stdout}");
    assert!(stdout.contains("UNENFORCED/OBSERVED-ONLY"), "got: {stdout}");
}

#[test]
fn status_discloses_every_gate_not_required_by_default() {
    let agent = FakeAgent::start(|_| AgentResponse::Status {
        status: AgentStatusView {
            protocol_version: 6,
            enforcement_mode: EnforcementMode::Enforce,
            session_required: false,
            approval_required: false,
            revocation_required: false,
            delegation_configured: false,
            step_up_configured: false,
        },
    });

    let output = eltanin_status(&agent);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("session required: NO"), "got: {stdout}");
    assert!(stdout.contains("approval required: NO"), "got: {stdout}");
    assert!(stdout.contains("revocation required: NO"), "got: {stdout}");
}

#[test]
fn status_discloses_every_gate_when_required() {
    let agent = FakeAgent::start(|_| AgentResponse::Status {
        status: AgentStatusView {
            protocol_version: 6,
            enforcement_mode: EnforcementMode::Enforce,
            session_required: true,
            approval_required: true,
            revocation_required: true,
            delegation_configured: false,
            step_up_configured: false,
        },
    });

    let output = eltanin_status(&agent);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("session required: yes"), "got: {stdout}");
    assert!(stdout.contains("approval required: yes"), "got: {stdout}");
    assert!(stdout.contains("revocation required: yes"), "got: {stdout}");
}

#[test]
fn status_against_an_unreachable_agent_exits_69() {
    let socket_path = std::env::temp_dir().join(format!(
        "eltanin-cli-status-nonexistent-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);

    let output = Command::new(env!("CARGO_BIN_EXE_eltanin"))
        .env("ELTANIN_AGENT_SOCKET", &socket_path)
        .arg("status")
        .output()
        .expect("run eltanin binary");
    assert_eq!(output.status.code(), Some(69));
}
