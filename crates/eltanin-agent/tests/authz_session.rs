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

use eltanin_agent::authz::event::{AuthorizationEvent, AuthorizationOutcome, EventSink, NullSink};
use eltanin_agent::authz::session::SessionRequirement;
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler};
use eltanin_agent::handler::RequestHandler;
use eltanin_audit::record::RecordedAgentEvent;
use eltanin_core::identity::{Evidence, ExecutionContext};
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::peer::{PeerConsistency, PeerContext, PeerCredential};
use eltanin_core::session::SessionId;
use eltanin_protocol::request::{ClientRequest, CreateSessionRequest, LeaseRequest};
use eltanin_protocol::response::{AgentResponse, DenialReason, TerminationOutcome};
use support::authz::{allow_policy_for_uid, backend_with_resource, resource_identity, FixedClock};
use support::temp_approval_store_path;

/// Captures every `(outcome, session)` pair this handler's single
/// `sink.record` call site produces, in order — HORO-796 subtask 2's
/// session-threading has no wire-visible effect, so tests for it must
/// observe this seam.
#[derive(Default)]
struct CapturingSessionSink {
    events: std::sync::Mutex<Vec<(AuthorizationOutcome, Option<SessionId>)>>,
}

impl EventSink for CapturingSessionSink {
    fn record(&self, event: &AuthorizationEvent<'_>) {
        self.events
            .lock()
            .unwrap()
            .push((event.outcome.clone(), event.session.clone()));
    }

    fn record_agent_event(&self, _event: RecordedAgentEvent) {}
}

impl CapturingSessionSink {
    fn last(&self) -> (AuthorizationOutcome, Option<SessionId>) {
        self.events.lock().unwrap().last().cloned().unwrap()
    }
}

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

/// Bug regression (F-M2-005, HORO-795): a session reaped by EXPIRY —
/// never explicitly `TerminateSession`d — must cascade-revoke the
/// leases it issued, exactly like `ac3_terminating_a_session_revokes_leases_issued_under_it`
/// above already proves for the *explicit* path. Before the fix,
/// `SessionState::reap`'s returned lease ids were silently discarded at
/// every lazy-reaping call site, so a killed `eltanin run` process's
/// device-level access outlived its own now-dead session indefinitely.
#[test]
fn bug_a_a_session_reaped_by_expiry_cascade_revokes_its_leases() {
    let backend = backend_with_resource(&[
        eltanin_core::resource::Capability::DeviceEnforce,
        eltanin_core::resource::Capability::DeviceRevoke,
    ]);
    let clock = FixedClock::new();
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(real_self_uid()),
        Arc::clone(&backend) as Arc<dyn eltanin_backend::contract::ComputeBackend>,
        Arc::clone(&clock) as Arc<dyn eltanin_agent::authz::Clock>,
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_session_requirement(SessionRequirement::Required),
    );
    let peer = self_peer_context();

    let established = handler.handle(
        &ClientRequest::CreateSession(CreateSessionRequest {
            resources: vec![resource_identity()],
            ttl: Duration::from_secs(30),
        }),
        &peer,
    );
    assert!(matches!(
        established,
        AgentResponse::SessionEstablished { .. }
    ));

    let granted = handler.handle(&lease_request(), &peer);
    assert!(
        matches!(granted, AgentResponse::LeaseGranted { .. }),
        "expected a granted lease, got {granted:?}"
    );
    assert_eq!(backend.revoke_call_count(&resource_identity()), 0);

    // Time passes beyond the session's own TTL. Nothing has explicitly
    // terminated it — this is EXPIRY, not TerminateSession.
    clock.advance(Duration::from_secs(31));

    // Any session-touching operation lazily reaps the now-expired
    // session. This call is itself refused for lack of a (now-expired)
    // session — the point is the side effect the reap it triggers must
    // have on the lease issued under that session.
    let response = handler.handle(&lease_request(), &peer);
    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::NoTrustedSession
        }
    );

    assert_eq!(
        backend.revoke_call_count(&resource_identity()),
        1,
        "a session reaped by expiry must cascade-revoke the leases it issued at the backend \
         layer, not merely disappear from the session store"
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

/// F-M2-006 (HORO-796 subtask 2): the resolved session id must be
/// threaded onto the audit record for every gate outcome that has one
/// available — not just `Granted`. This one test file exercises all
/// three distinct paths the design calls out (grant, approval-refused,
/// delegation-refused) plus the two honest-`None` cases, so a reviewer
/// can see all five side by side.
mod session_threading {
    use super::{
        allow_policy_for_uid, backend_with_resource, create_session, real_self_uid,
        resource_identity, self_peer_context, temp_approval_store_path, AgentResponse,
        AuthorizationConfig, AuthorizationHandler, AuthorizationOutcome, CapturingSessionSink,
        ClientRequest, DenialReason, FixedClock, IssuerInstanceId, LeaseRequest, RequestHandler,
    };
    use std::sync::Arc;
    use std::time::Duration;

    fn lease_request() -> ClientRequest {
        ClientRequest::RequestLease(LeaseRequest {
            resource: resource_identity(),
            action: eltanin_core::resource::Action::Compute,
        })
    }

    fn handler_with_approval(
        store_path: std::path::PathBuf,
        sink: Arc<CapturingSessionSink>,
    ) -> AuthorizationHandler {
        AuthorizationHandler::new(
            IssuerInstanceId::new("test-instance"),
            allow_policy_for_uid(real_self_uid()),
            backend_with_resource(&[
                eltanin_core::resource::Capability::DeviceEnforce,
                eltanin_core::resource::Capability::DeviceRevoke,
            ]),
            FixedClock::new(),
            sink,
            &AuthorizationConfig::new(Duration::from_secs(60))
                .unwrap()
                .with_approval_store(store_path),
        )
    }

    fn handler_with_delegation(
        store_path: std::path::PathBuf,
        sink: Arc<CapturingSessionSink>,
    ) -> AuthorizationHandler {
        let bounds = eltanin_core::delegation::DelegationBounds::new(
            4,
            Duration::from_secs(300),
            Duration::from_secs(1),
            [eltanin_core::resource::Action::Compute],
            std::collections::BTreeSet::new(),
            false,
            false,
        )
        .unwrap();
        AuthorizationHandler::new(
            IssuerInstanceId::new("test-instance"),
            allow_policy_for_uid(real_self_uid()),
            backend_with_resource(&[
                eltanin_core::resource::Capability::DeviceEnforce,
                eltanin_core::resource::Capability::DeviceRevoke,
            ]),
            FixedClock::new(),
            sink,
            &AuthorizationConfig::new(Duration::from_secs(60))
                .unwrap()
                .with_delegation(store_path, bounds),
        )
    }

    #[test]
    fn a_successful_grant_while_a_session_is_active_carries_that_session_id() {
        let sink = Arc::new(CapturingSessionSink::default());
        let handler = handler_with_approval(
            temp_approval_store_path("session-thread-grant"),
            sink.clone(),
        );
        let peer = self_peer_context();

        let created = create_session(&handler, &peer);
        let session_id = match created {
            AgentResponse::SessionEstablished { session } => session.session_id,
            other => panic!("expected SessionEstablished, got {other:?}"),
        };

        // The approval gate would refuse an ordinary lease request here
        // (no approval was ever recorded), so approve it first — the
        // point of this test is the grant path's session field, not the
        // approval gate itself.
        let _ = handler.handle(
            &ClientRequest::Approve(eltanin_protocol::request::ApproveRequest {
                resource: resource_identity(),
                action: eltanin_core::resource::Action::Compute,
                disposition: eltanin_core::approval::ApprovalDisposition::Remember,
            }),
            &peer,
        );

        let response = handler.handle(&lease_request(), &peer);
        assert!(matches!(response, AgentResponse::LeaseGranted { .. }));

        let (outcome, session) = sink.last();
        assert!(matches!(outcome, AuthorizationOutcome::Granted { .. }));
        assert_eq!(
            session,
            Some(session_id),
            "a successful grant while a session is active must carry that session's id"
        );
    }

    #[test]
    fn an_approval_refused_request_while_a_session_is_active_carries_that_session_id() {
        let sink = Arc::new(CapturingSessionSink::default());
        let handler = handler_with_approval(
            temp_approval_store_path("session-thread-approval-refused"),
            sink.clone(),
        );
        let peer = self_peer_context();

        let created = create_session(&handler, &peer);
        let session_id = match created {
            AgentResponse::SessionEstablished { session } => session.session_id,
            other => panic!("expected SessionEstablished, got {other:?}"),
        };

        // No approval was ever recorded, so the approval gate refuses
        // this request — pre-policy, exactly as `crate::authz`'s module
        // docs describe.
        let response = handler.handle(&lease_request(), &peer);
        assert_eq!(
            response,
            AgentResponse::LeaseDenied {
                reason: DenialReason::ApprovalRequired
            }
        );

        let (outcome, session) = sink.last();
        assert!(matches!(outcome, AuthorizationOutcome::ApprovalRequired));
        assert_eq!(
            session,
            Some(session_id),
            "an approval-refused request must still carry the active session's id — \
             session resolution runs before the approval gate"
        );
    }

    #[test]
    fn a_delegation_refused_request_while_a_session_is_active_carries_that_session_id() {
        let sink = Arc::new(CapturingSessionSink::default());
        let handler = handler_with_delegation(
            temp_approval_store_path("session-thread-delegation-refused"),
            sink.clone(),
        );
        let peer = self_peer_context();

        let created = create_session(&handler, &peer);
        let session_id = match created {
            AgentResponse::SessionEstablished { session } => session.session_id,
            other => panic!("expected SessionEstablished, got {other:?}"),
        };

        // No approval and no delegation grant exists anywhere, so the
        // approval gate refuses, delegation is consulted, and — with
        // zero delegation candidates — is refused too.
        let response = handler.handle(&lease_request(), &peer);
        assert_eq!(
            response,
            AgentResponse::LeaseDenied {
                reason: DenialReason::ApprovalRequired
            }
        );

        let (outcome, session) = sink.last();
        assert!(matches!(
            outcome,
            AuthorizationOutcome::DelegationRefused { .. }
        ));
        assert_eq!(
            session,
            Some(session_id),
            "a delegation-refused request must still carry the active session's id"
        );
    }

    #[test]
    fn a_request_with_no_active_session_carries_no_session_id() {
        let sink = Arc::new(CapturingSessionSink::default());
        let handler = handler_with_approval(
            temp_approval_store_path("session-thread-no-session"),
            sink.clone(),
        );
        let peer = self_peer_context();

        // No CreateSession was ever called for this peer.
        let response = handler.handle(&lease_request(), &peer);
        assert_eq!(
            response,
            AgentResponse::LeaseDenied {
                reason: DenialReason::ApprovalRequired
            }
        );

        let (outcome, session) = sink.last();
        assert!(matches!(outcome, AuthorizationOutcome::ApprovalRequired));
        assert_eq!(
            session, None,
            "no session was ever established for this peer — None is the honest value"
        );
    }

    /// `peer.authorizable()` fails before session resolution ever runs
    /// (see `AuthorizationHandler::handle_request_lease`'s own doc
    /// comment) — `None` here is correct, not a gap.
    #[test]
    fn a_request_refused_before_session_resolution_carries_no_session_id() {
        let sink = Arc::new(CapturingSessionSink::default());
        let handler = handler_with_approval(
            temp_approval_store_path("session-thread-before-resolution"),
            sink.clone(),
        );
        let uid = real_self_uid();
        let pid = std::process::id();
        let workload = super::platform::collect_workload_identity(pid);
        let context = eltanin_core::identity::ExecutionContext {
            workload,
            cgroup_path: eltanin_core::identity::Evidence::Unsupported,
            namespace_hint: eltanin_core::identity::Evidence::Unsupported,
            container_hint: eltanin_core::identity::Evidence::Unsupported,
            session_origin: eltanin_core::identity::Evidence::Unsupported,
        };
        let peer = eltanin_core::peer::PeerContext::new(
            eltanin_core::peer::PeerCredential::new(pid, uid, uid),
            eltanin_core::peer::PeerConsistency::CredentialDivergence {
                peer_effective_uid: uid,
                observed_real_uid: eltanin_core::identity::Evidence::Present {
                    value: uid + 1,
                    source: eltanin_core::identity::EvidenceSource::KernelObserved,
                },
                observed_effective_uid: eltanin_core::identity::Evidence::Present {
                    value: uid + 1,
                    source: eltanin_core::identity::EvidenceSource::KernelObserved,
                },
            },
            context,
        );

        let response = handler.handle(&lease_request(), &peer);
        assert_eq!(
            response,
            AgentResponse::LeaseDenied {
                reason: DenialReason::IndeterminateEvidence
            }
        );

        let (outcome, session) = sink.last();
        assert!(matches!(outcome, AuthorizationOutcome::PeerNotAuthorizable));
        assert_eq!(
            session, None,
            "a request refused before session resolution ever runs must report None, \
             not a fabricated value"
        );
    }
}
