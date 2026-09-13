//! Trusted Compute Session coverage (F-M2-001, HORO-791) — the ACs this
//! ticket lists:
//!
//! - AC1: one session admits multiple ordinary `RequestLease` calls with
//!   no per-request friction.
//! - AC2: another ordinary process cannot join merely by copying session
//!   metadata/ID (proven here via a real foreign-session child process,
//!   not a synthetic identity — see `session_probe_fixture`).
//! - AC3: session expiry/termination prevents new lease issuance.
//! - AC4: restart/recovery semantics are explicit (a fresh
//!   `AuthorizationHandler` — a new agent instance — never honors a
//!   session established by a prior one).
//! - AC5: no long-lived plaintext bearer secret is the trust root — a
//!   type-level property (`TrustedSession`/`SessionView` are never
//!   `Deserialize`, `TerminateSession`/`ListSessions` carry no session
//!   id) verified by this workspace simply compiling, not by a runtime
//!   assertion here.

mod support;

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use eltanin_agent::authz::event::NullSink;
use eltanin_agent::authz::session::SessionRequirement;
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler};
use eltanin_agent::handler::RequestHandler;
use eltanin_core::identity::{Evidence, ExecutionContext};
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::peer::{PeerConsistency, PeerContext, PeerCredential};
use eltanin_protocol::request::{ClientRequest, CreateSessionRequest, LeaseRequest};
use eltanin_protocol::response::{AgentResponse, DenialReason, TerminationOutcome};
use support::authz::{allow_policy_for_uid, backend_with_resource, resource_identity, FixedClock};

#[cfg(not(target_os = "macos"))]
use eltanin_linux as platform;
#[cfg(target_os = "macos")]
use eltanin_macos as platform;

/// A [`PeerContext`] for a *real* pid on this host — required because
/// `eltanin-agent`'s session layer collects session-key/leader evidence
/// straight from the platform collector for whatever pid a
/// `WorkloadIdentity` names (see `eltanin_agent::authz::session`'s own
/// docs on why there is deliberately no injectable seam here). A
/// synthetic pid cannot honestly exercise this path.
fn peer_context_for_pid(pid: u32, uid: u32) -> PeerContext {
    let workload = platform::collect_workload_identity(pid);
    let context = ExecutionContext {
        workload,
        cgroup_path: Evidence::Unsupported,
        namespace_hint: Evidence::Unsupported,
        container_hint: Evidence::Unsupported,
        session_origin: Evidence::Unsupported,
    };
    PeerContext::new(
        PeerCredential::new(pid, uid, uid),
        PeerConsistency::Consistent,
        context,
    )
}

/// This test binary's own real, kernel-observed uid — every test peer
/// in this file is `std::process::id()` itself (see the module docs on
/// why a real pid is required), so the policy allow-rule must match
/// whatever uid the platform collector actually reports for it, not a
/// hardcoded stand-in that would only coincidentally match on some
/// hosts.
fn real_self_uid() -> u32 {
    match platform::collect_workload_identity(std::process::id()).uid {
        Evidence::Present { value, .. } => value,
        other => {
            panic!("expected this test process's own uid to be kernel-observed, got {other:?}")
        }
    }
}

fn self_peer_context() -> PeerContext {
    peer_context_for_pid(std::process::id(), real_self_uid())
}

fn handler_with(session_requirement: SessionRequirement) -> AuthorizationHandler {
    AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(real_self_uid()),
        backend_with_resource(&[
            eltanin_core::resource::Capability::DeviceEnforce,
            eltanin_core::resource::Capability::DeviceRevoke,
        ]),
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_session_requirement(session_requirement),
    )
}

fn create_session(handler: &AuthorizationHandler, peer: &PeerContext) -> AgentResponse {
    handler.handle(
        &ClientRequest::CreateSession(CreateSessionRequest {
            resources: vec![resource_identity()],
            ttl: Duration::from_secs(30),
        }),
        peer,
    )
}

fn lease_request() -> ClientRequest {
    ClientRequest::RequestLease(LeaseRequest {
        resource: resource_identity(),
        action: eltanin_core::resource::Action::Compute,
    })
}

#[test]
fn without_a_session_a_required_deployment_denies_with_no_trusted_session() {
    let handler = handler_with(SessionRequirement::Required);
    let peer = self_peer_context();

    let response = handler.handle(&lease_request(), &peer);

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::NoTrustedSession
        }
    );
}

#[test]
fn ac1_one_session_admits_multiple_ordinary_lease_requests() {
    let handler = handler_with(SessionRequirement::Required);
    let peer = self_peer_context();

    let established = create_session(&handler, &peer);
    assert!(
        matches!(established, AgentResponse::SessionEstablished { .. }),
        "expected SessionEstablished, got {established:?}"
    );

    for _ in 0..3 {
        let response = handler.handle(&lease_request(), &peer);
        assert!(
            matches!(response, AgentResponse::LeaseGranted { .. }),
            "expected every ordinary request after one session establish to be granted with no \
             further friction, got {response:?}"
        );
        // Release immediately so outstanding-lease capacity never
        // becomes the reason a later iteration is denied.
        if let AgentResponse::LeaseGranted { lease } = response {
            handler.handle(
                &ClientRequest::ReleaseLease(eltanin_protocol::request::ReleaseRequest {
                    lease_id: lease.lease_id,
                }),
                &peer,
            );
        }
    }
}

#[test]
fn a_session_established_when_not_required_still_permits_leases_unchanged() {
    // Blast-radius guard: NotRequired (the default for every existing
    // MVP 1.0 deployment/test harness) must behave exactly as before —
    // a lease request succeeds whether or not a session happens to
    // exist.
    let handler = handler_with(SessionRequirement::NotRequired);
    let peer = self_peer_context();

    let response = handler.handle(&lease_request(), &peer);
    assert!(matches!(response, AgentResponse::LeaseGranted { .. }));
}

#[test]
fn ac3_terminating_a_session_prevents_new_lease_issuance_under_required() {
    let handler = handler_with(SessionRequirement::Required);
    let peer = self_peer_context();

    let established = create_session(&handler, &peer);
    assert!(matches!(
        established,
        AgentResponse::SessionEstablished { .. }
    ));

    let terminated = handler.handle(&ClientRequest::TerminateSession {}, &peer);
    assert_eq!(
        terminated,
        AgentResponse::SessionTerminated {
            outcome: TerminationOutcome::Terminated
        }
    );

    let response = handler.handle(&lease_request(), &peer);
    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::NoTrustedSession
        }
    );
}

#[test]
fn ac3_terminating_a_session_revokes_leases_issued_under_it() {
    let handler = handler_with(SessionRequirement::Required);
    let peer = self_peer_context();

    create_session(&handler, &peer);
    let granted = handler.handle(&lease_request(), &peer);
    let AgentResponse::LeaseGranted { lease } = granted else {
        panic!("expected a granted lease, got {granted:?}");
    };

    handler.handle(&ClientRequest::TerminateSession {}, &peer);

    // The lease issued under the now-terminated session must itself be
    // gone — releasing it again reports Refused, never Released twice.
    let release = handler.handle(
        &ClientRequest::ReleaseLease(eltanin_protocol::request::ReleaseRequest {
            lease_id: lease.lease_id,
        }),
        &peer,
    );
    assert_eq!(
        release,
        AgentResponse::LeaseReleased {
            outcome: eltanin_protocol::response::ReleaseOutcome::Refused
        }
    );
}

#[test]
fn ac4_a_fresh_agent_instance_never_honors_a_prior_instances_session() {
    // Restart/recovery semantics, made explicit: `handler_a` and
    // `handler_b` are two independent `AuthorizationHandler`s (as if
    // the agent process had restarted between them) — each owns its own
    // `SessionAuthority` with its own `IssuerInstanceId`, so a session
    // established under `handler_a` is simply invisible to `handler_b`.
    let handler_a = handler_with(SessionRequirement::Required);
    let peer = self_peer_context();
    create_session(&handler_a, &peer);

    let handler_b = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance-restarted"),
        allow_policy_for_uid(real_self_uid()),
        backend_with_resource(&[
            eltanin_core::resource::Capability::DeviceEnforce,
            eltanin_core::resource::Capability::DeviceRevoke,
        ]),
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_session_requirement(SessionRequirement::Required),
    );

    let response = handler_b.handle(&lease_request(), &peer);
    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::NoTrustedSession
        }
    );
}

/// AC2: another ordinary process cannot join merely by copying session
/// metadata/ID. Spawns a real child (`session_probe_fixture`) that
/// detaches into its own fresh POSIX session, and proves the handler
/// never treats it as a member of a session established by *this* test
/// process — the strongest available test, since both peers are real
/// pids observed through the real platform collector, not synthetic
/// identities.
#[test]
fn ac2_a_foreign_session_process_cannot_join_by_pid_alone() {
    let handler = handler_with(SessionRequirement::Required);
    let owner_peer = self_peer_context();
    let established = create_session(&handler, &owner_peer);
    assert!(matches!(
        established,
        AgentResponse::SessionEstablished { .. }
    ));

    let mut child = Command::new(env!("CARGO_BIN_EXE_session_probe_fixture"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn session_probe_fixture");

    // Wait for the fixture's readiness line so `setsid()` has already
    // run before this test observes its pid/session.
    let mut reader = BufReader::new(child.stdout.take().expect("child stdout"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("read readiness line");
    assert!(
        line.starts_with("ready"),
        "unexpected fixture output: {line:?}"
    );

    let foreign_pid: u32 = line
        .trim()
        .strip_prefix("ready pid=")
        .expect("readiness line names a pid")
        .parse()
        .expect("pid is a valid u32");

    let foreign_peer = peer_context_for_pid(foreign_pid, real_self_uid());
    let response = handler.handle(&lease_request(), &foreign_peer);

    // Clean up the child before asserting, so a failed assertion doesn't
    // leak a blocked process.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"x");
    }
    let _ = child.wait();

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::NoTrustedSession
        },
        "a process in a different POSIX session must never be admitted as a session member"
    );
}
