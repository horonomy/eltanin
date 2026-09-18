//! Regression coverage for D1b (HORO-797 prep): `eltanin session start`
//! previously printed a plain "established ..." success message
//! whether or not the agent actually requires a session at all —
//! silently implying a gate now exists when the agent's own
//! `AuthorizationConfig` never heard of `SessionRequirement::Required`
//! (see `crates/eltanin-agent/tests/authz_session.rs`'s
//! `a_session_established_when_not_required_still_permits_leases_unchanged`
//! for the underlying behavior this disclosure is about). Mirrors
//! `status_binary.rs`'s FakeAgent-driven convention, and the same "state
//! an unenforced/weak posture loudly, not silently" discipline
//! `status_binary.rs::status_reports_shadow_mode_with_an_unenforced_warning`
//! already established for shadow mode.
//!
//! Both scenarios live in one `#[test]` function, not two: `session::run`
//! reads `ELTANIN_AGENT_SOCKET` via `std::env::set_var`/process env
//! (`AgentClient::from_env`), and `cargo test` runs `#[test]` functions
//! within one binary concurrently by default — two tests setting that
//! process-global var independently would race.

mod support;

use std::time::Duration;

use eltanin_cli::args::SessionInvocation;
use eltanin_cli::session::{self, SessionCliOutcome};
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::session::SessionId;
use eltanin_protocol::request::ClientRequest;
use eltanin_protocol::response::{AgentResponse, AgentStatusView, EnforcementMode, SessionView};
use support::fake_agent::FakeAgent;

fn session_established() -> AgentResponse {
    AgentResponse::SessionEstablished {
        session: SessionView {
            session_id: SessionId {
                issuer: IssuerInstanceId::new("test-issuer"),
                sequence: 1,
            },
            remaining: Duration::from_secs(3600),
            resources: Vec::new(),
        },
    }
}

fn status_with(session_required: bool) -> AgentResponse {
    AgentResponse::Status {
        status: AgentStatusView {
            protocol_version: 6,
            enforcement_mode: EnforcementMode::Enforce,
            session_required,
            approval_required: false,
            revocation_required: false,
            delegation_configured: false,
            step_up_configured: false,
        },
    }
}

fn start_session() -> SessionCliOutcome {
    session::run(&SessionInvocation::Start {
        profiles: Vec::new(),
        ttl: Duration::from_secs(3600),
    })
}

#[test]
fn session_start_discloses_whether_the_agent_actually_requires_a_session() {
    // Not required: the disclosure must appear.
    let not_required_agent = FakeAgent::start(|request| match request {
        ClientRequest::CreateSession(_) => session_established(),
        ClientRequest::AgentStatus {} => status_with(false),
        other => panic!("unexpected request in this fixture: {other:?}"),
    });
    std::env::set_var("ELTANIN_AGENT_SOCKET", not_required_agent.socket_path());
    let SessionCliOutcome::Ok(message) = start_session() else {
        panic!("expected Ok outcome");
    };
    assert!(message.contains("established"), "got: {message}");
    assert!(
        message.contains("does not require a Trusted Compute Session"),
        "got: {message}"
    );

    // Required: no such disclosure — the established session is a real
    // gate, not a no-op.
    let required_agent = FakeAgent::start(|request| match request {
        ClientRequest::CreateSession(_) => session_established(),
        ClientRequest::AgentStatus {} => status_with(true),
        other => panic!("unexpected request in this fixture: {other:?}"),
    });
    std::env::set_var("ELTANIN_AGENT_SOCKET", required_agent.socket_path());
    let SessionCliOutcome::Ok(message) = start_session() else {
        panic!("expected Ok outcome");
    };
    assert!(message.contains("established"), "got: {message}");
    assert!(
        !message.contains("does not require a Trusted Compute Session"),
        "got: {message}"
    );
}
