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
use eltanin_core::approval::ApprovalDisposition;
use eltanin_core::identity::{Evidence, EvidenceSource, ExecutionContext};
use eltanin_core::lease::{IssuerInstanceId, MonotonicTime};
use eltanin_core::peer::{PeerConsistency, PeerContext, PeerCredential};
use eltanin_core::session::{
    membership, HostId, IntentProof, LeaderCorroboration, LocalSessionAnchor, MembershipVerdict,
    NotMemberReason, SessionAssurance, SessionAuthority, SessionId, SessionKey, SessionNonce,
    SessionScope,
};
use eltanin_protocol::request::{
    ApproveRequest, ClientRequest, CreateSessionRequest, LeaseRequest, ReleaseRequest,
};
use eltanin_protocol::response::{AgentResponse, DenialReason, ReleaseOutcome, TerminationOutcome};
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

fn approve_request(disposition: ApprovalDisposition) -> ClientRequest {
    ClientRequest::Approve(ApproveRequest {
        resource: resource_identity(),
        action: eltanin_core::resource::Action::Compute,
        disposition,
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

/// S3 (HORO-797 adversarial matrix) — `PINS_LIMITATION`: a same-uid,
/// same-POSIX-session but otherwise **unrelated** process is admitted as
/// a session member with no further defense at this layer. This is not
/// a bug in `membership()` — it is exactly what ADR 0009's headline
/// trade-off discloses: "intent is proven once per terminal, and
/// thereafter inherited by everything spawned in that terminal, with no
/// further act of intent... A `postinstall` script run in the same shell
/// after `eltanin session start` is a session member exactly as much as
/// the interactive command the user actually intended to authorize."
/// ADR 0010 disclosure 2 states the same boundary from the approval
/// side: "Not a boundary against the same user's other processes."
///
/// HORO-1278's session-anchor redesign does not close this gap: its new
/// uid/host checks in `membership()` only reject a *different* uid (or
/// host) than the session owner's, and this scenario is specifically the
/// *same* uid — so this test is expected to keep passing unmodified after
/// that redesign, and it does.
///
/// Unlike `ac2_a_foreign_session_process_cannot_join_by_pid_alone` above
/// (which proves a *different*-session process is correctly refused),
/// this test spawns a real child that never calls `setsid()` — it
/// inherits this test process's own POSIX session exactly as a
/// `postinstall` script inherits its parent shell's session — and proves
/// `membership()` admits it, because nothing about `membership()`'s
/// contract (session-key equality plus anchor-leader liveness) ever
/// asked "is this the same process that established the session."
#[test]
fn s3_a_same_session_unrelated_process_is_admitted_with_no_further_defense() {
    let handler = handler_with(SessionRequirement::Required);
    let owner_peer = self_peer_context();
    let established = create_session(&handler, &owner_peer);
    assert!(matches!(
        established,
        AgentResponse::SessionEstablished { .. }
    ));

    // A real child of this test process that never calls `setsid()` —
    // it inherits this process's own POSIX session by ordinary fork/exec
    // semantics, exactly as any ordinary command run in the same
    // terminal would. It is otherwise wholly unrelated to the session
    // owner's actual intended workload.
    let mut child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn /bin/cat as an unrelated same-session child");
    let unrelated_pid = child.id();

    // Confirm the child is actually kernel-observable before building
    // its peer context — a false `NoTrustedSession` from a spawn/collect
    // race would look like the limitation not existing, rather than the
    // flaky harness issue it would actually be.
    match platform::collect_workload_identity(unrelated_pid).process_start {
        Evidence::Present { .. } => {}
        other => {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "expected the spawned child's process_start to be kernel-observed before \
                    proceeding, got {other:?}"
            );
        }
    }

    let unrelated_peer = peer_context_for_pid(unrelated_pid, real_self_uid());
    let response = handler.handle(&lease_request(), &unrelated_peer);

    // Clean up before asserting, so a failed assertion doesn't leak a
    // blocked process.
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "a same-uid, same-session, otherwise-unrelated process must be admitted as a session \
         member — this is ADR 0009's disclosed postinstall-script trade-off combined with \
         ADR 0010 disclosure 2 ('not a boundary against the same user's other processes'), \
         not a bug — got {response:?}"
    );
}

/// HORO-1278 ground-truth regression: a session established while the
/// *establishing peer's own process* is real and then genuinely killed
/// must still be honored by a later request in the same POSIX session.
/// Before HORO-1278's fix, `handle_create_session` anchored the session
/// to the connecting peer's own identity (`observed.workload.clone()`)
/// rather than to the session's own sid leader — so a session
/// established by a short-lived process (exactly the shape of `eltanin
/// session start`) could never be recognized again once that process
/// exited. `self_peer_context()` alone (used by every other test in
/// this file) can never catch this bug, because it is the *same* live
/// test-process object for the whole test — the establishing peer never
/// actually dies. This test uses the real-child-spawn pattern already
/// established by `s3_a_same_session_unrelated_process_is_admitted_with_no_further_defense`
/// above to make the establishing peer a genuinely separate process that
/// is killed and waited on before the later request is made.
#[test]
fn horo1278_a_session_survives_the_establishing_peer_process_exiting() {
    let handler = handler_with(SessionRequirement::Required);

    // A real child of this test process that never calls `setsid()` — it
    // inherits this process's own POSIX session, exactly as `eltanin
    // session start` inherits the interactive shell's session. This
    // process — not `self_peer_context()` — is the one that calls
    // `CreateSession`.
    let mut establishing_child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn /bin/cat as the establishing peer");
    let establishing_pid = establishing_child.id();

    match platform::collect_workload_identity(establishing_pid).process_start {
        Evidence::Present { .. } => {}
        other => {
            let _ = establishing_child.kill();
            let _ = establishing_child.wait();
            panic!(
                "expected the establishing child's process_start to be kernel-observed before \
                 proceeding, got {other:?}"
            );
        }
    }

    let establishing_peer = peer_context_for_pid(establishing_pid, real_self_uid());
    let established = create_session(&handler, &establishing_peer);
    assert!(
        matches!(established, AgentResponse::SessionEstablished { .. }),
        "expected SessionEstablished, got {established:?}"
    );

    // Kill the establishing peer and genuinely wait for it to exit —
    // this is the crux of the regression: the process this session was
    // established "through" is now truly dead, exactly as `eltanin
    // session start` always is by the time any later invocation runs.
    let _ = establishing_child.kill();
    let _ = establishing_child.wait();

    // A later request from a *different*, still-live process in the
    // same POSIX session (this test process itself) must still be
    // honored.
    let response = handler.handle(&lease_request(), &self_peer_context());
    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "a session must survive its establishing peer process exiting — got {response:?}"
    );
}

/// Bug fix (HORO-1278): `TrustedSession::owner_uid` was stored at
/// establishment time but never actually compared by `membership` —
/// closed by extending `membership`'s combined signature to check it.
/// Simulates a different observed uid in the same POSIX session by
/// overriding the freshly collected `WorkloadIdentity.uid` evidence
/// directly (same technique `a_request_refused_before_session_resolution_carries_no_session_id`
/// above already uses to simulate divergent evidence without requiring
/// real multi-user infrastructure in a test process).
#[test]
fn horo1278_a_different_uid_in_the_same_posix_session_is_refused() {
    let handler = handler_with(SessionRequirement::Required);
    let owner_peer = self_peer_context();
    let established = create_session(&handler, &owner_peer);
    assert!(matches!(
        established,
        AgentResponse::SessionEstablished { .. }
    ));

    let pid = std::process::id();
    let mut workload = platform::collect_workload_identity(pid);
    workload.uid = Evidence::Present {
        value: real_self_uid() + 1,
        source: EvidenceSource::KernelObserved,
    };
    let context = ExecutionContext {
        workload,
        cgroup_path: Evidence::Unsupported,
        namespace_hint: Evidence::Unsupported,
        container_hint: Evidence::Unsupported,
        session_origin: Evidence::Unsupported,
    };
    let spoofed_uid_peer = PeerContext::new(
        PeerCredential::new(pid, real_self_uid(), real_self_uid()),
        PeerConsistency::Consistent,
        context,
    );

    let response = handler.handle(&lease_request(), &spoofed_uid_peer);
    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::NoTrustedSession
        },
        "a different observed uid in the same POSIX session must be refused, not silently \
         admitted — the wire response collapses `NotMemberReason::OwnerUidMismatch` into the \
         same NoTrustedSession denial every other NotMember reason gets"
    );
}

/// Bug fix (HORO-1278): expiry must be structural inside `membership`
/// itself, never dependent on `SessionState::reap` having already run
/// under the same lock. Calls `eltanin_core::session::membership`
/// directly against a session built with the real platform collector's
/// own `WorkloadIdentity`/`HostId` shapes — no `AuthorizationHandler`,
/// no `SessionState`, and therefore no `reap` call anywhere in this
/// test.
#[test]
fn horo1278_an_expired_session_is_refused_by_membership_itself() {
    let mut authority = SessionAuthority::new(
        IssuerInstanceId::new("test-instance"),
        Duration::from_secs(3600),
    );
    let pid = std::process::id();
    let uid = real_self_uid();
    let leader_identity = platform::collect_workload_identity(pid);
    let session = authority
        .establish(
            uid,
            LocalSessionAnchor {
                key: SessionKey(4242),
                leader: LeaderCorroboration::Recorded(leader_identity.clone()),
            },
            SessionScope::new([resource_identity()]).unwrap(),
            IntentProof::LocalPeerPresence,
            SessionAssurance::LocalKernelSession,
            HostId("test-host".to_string()),
            SessionNonce::from_bytes([0u8; 32]),
            MonotonicTime::from_nanos(0),
            Duration::from_secs(60),
        )
        .unwrap();

    let peer_uid = Evidence::Present {
        value: uid,
        source: EvidenceSource::KernelObserved,
    };
    let peer_key = Evidence::Present {
        value: SessionKey(4242),
        source: EvidenceSource::KernelObserved,
    };
    let observed_host = Evidence::Present {
        value: HostId("test-host".to_string()),
        source: EvidenceSource::KernelObserved,
    };
    let at_expiry =
        MonotonicTime::from_nanos(u64::try_from(Duration::from_secs(60).as_nanos()).unwrap());

    assert_eq!(
        membership(
            &session,
            &peer_uid,
            &peer_key,
            &observed_host,
            &leader_identity,
            at_expiry,
        ),
        MembershipVerdict::NotMember {
            reason: NotMemberReason::Expired {
                expired_at: session.expires_at()
            }
        }
    );
}

/// S8c (HORO-797 adversarial matrix, HORO-1278 redesign) — `PINS_TRADEOFF`,
/// not a regression: a same-session process that never calls `setsid()`
/// (S8's "detached persistent daemon" — reached here by a real second
/// child that inherits this test process's own POSIX session exactly
/// like `s3_a_same_session_unrelated_process_is_admitted_with_no_further_defense`/
/// `horo1278_a_session_survives_the_establishing_peer_process_exiting`
/// above, standing in for a double-fork-without-`setsid()` daemon, which
/// has the identical property that actually matters here — same sid,
/// established leader now genuinely dead) is admitted for the FULL
/// session TTL, bounded only by session expiry, never by the
/// establishing leader process's own lifetime.
///
/// This is disclosed and deliberate, not a bug: `SessionAuthority::validate`'s
/// own doc states plainly that "what now bounds a `TrustedSession`'s
/// lifetime... is TTL/expiry alone, not leader liveness. This is not a
/// regression; it is exactly the founder's 'explicit TTL/expiry'
/// requirement (HORO-1278), made structural rather than incidental."
/// Before HORO-1278, ANY same-session detached process was killed the
/// moment the session leader (the CLI process) exited — that was the
/// bug's own accidental "protection," not a real security boundary. The
/// distinguishing fact this test pins is TTL-*bounded* admission
/// (correct, proven by this test's second half) versus
/// permanent/indefinite admission with no expiry (which would be wrong
/// and is NOT what this test asserts) — a future reader must not mistake
/// this test's first-half "admitted after leader death" assertion for the
/// bug HORO-1278 fixed.
#[test]
fn s8c_a_same_session_detached_process_is_bounded_by_ttl_not_by_terminal_lifetime() {
    let clock = FixedClock::new();
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(real_self_uid()),
        backend_with_resource(&[
            eltanin_core::resource::Capability::DeviceEnforce,
            eltanin_core::resource::Capability::DeviceRevoke,
        ]),
        Arc::clone(&clock) as Arc<dyn eltanin_agent::authz::Clock>,
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_session_requirement(SessionRequirement::Required),
    );

    // The "CLI"/leader process — a real child, never calling `setsid()`,
    // that establishes the session and then genuinely exits, exactly like
    // `horo1278_a_session_survives_the_establishing_peer_process_exiting`
    // above.
    let mut establishing_child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn /bin/cat as the establishing peer");
    let establishing_pid = establishing_child.id();
    match platform::collect_workload_identity(establishing_pid).process_start {
        Evidence::Present { .. } => {}
        other => {
            let _ = establishing_child.kill();
            let _ = establishing_child.wait();
            panic!(
                "expected the establishing child's process_start to be kernel-observed before \
                 proceeding, got {other:?}"
            );
        }
    }
    let establishing_peer = peer_context_for_pid(establishing_pid, real_self_uid());
    let established = create_session(&handler, &establishing_peer);
    assert!(
        matches!(established, AgentResponse::SessionEstablished { .. }),
        "expected SessionEstablished, got {established:?}"
    );

    // The "detached persistent daemon" — a second real child, ALSO never
    // calling `setsid()`, so it stays in the SAME POSIX session as the
    // (about-to-die) leader by ordinary fork/exec inheritance, exactly
    // the shape a double-fork-without-`setsid()` daemon leaves behind.
    let mut detached_child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn /bin/cat as the same-session detached daemon");
    let detached_pid = detached_child.id();
    match platform::collect_workload_identity(detached_pid).process_start {
        Evidence::Present { .. } => {}
        other => {
            let _ = establishing_child.kill();
            let _ = establishing_child.wait();
            let _ = detached_child.kill();
            let _ = detached_child.wait();
            panic!(
                "expected the detached child's process_start to be kernel-observed before \
                 proceeding, got {other:?}"
            );
        }
    }
    let detached_peer = peer_context_for_pid(detached_pid, real_self_uid());

    // Kill and genuinely wait for the leader to exit — the session's
    // anchor leader is now truly dead, well within the session's TTL.
    let _ = establishing_child.kill();
    let _ = establishing_child.wait();

    let admitted = handler.handle(&lease_request(), &detached_peer);
    assert!(
        matches!(admitted, AgentResponse::LeaseGranted { .. }),
        "immediately after the leader's death, well within the session TTL, the same-session \
         detached daemon must be admitted — leader death alone must never kill the session, \
         got {admitted:?}"
    );
    if let AgentResponse::LeaseGranted { lease } = admitted {
        handler.handle(
            &ClientRequest::ReleaseLease(ReleaseRequest {
                lease_id: lease.lease_id,
            }),
            &detached_peer,
        );
    }

    // Advance the clock past the session's own TTL (`create_session`
    // above requests 30s) — no real sleep, deterministic.
    clock.advance(Duration::from_secs(31));

    let denied = handler.handle(&lease_request(), &detached_peer);

    let _ = detached_child.kill();
    let _ = detached_child.wait();

    assert_eq!(
        denied,
        AgentResponse::LeaseDenied {
            reason: DenialReason::NoTrustedSession
        },
        "past the session's own TTL, the same-session detached daemon must be denied — \
         `NotMemberReason::Expired`/`SessionValidity::Expired` collapses at the wire into \
         `DenialReason::NoTrustedSession`, exactly like every other NotMember reason (see \
         `horo1278_a_different_uid_in_the_same_posix_session_is_refused` above) — proving TTL, \
         not the terminal/leader's lifetime, is what actually bounds this admission. got \
         {denied:?}"
    );
}

/// S12 (HORO-797 adversarial matrix) — `PROVES_DEFENSE` (design-honesty
/// cross-check): a single scenario exercising the asymmetry that a
/// durable `Remember` approval survives an agent restart while a
/// Trusted Compute Session and the leases issued under it do not.
/// Reads, in one restart scenario, exactly the four properties already
/// separately proven by `remember_admits_a_restarted_workload_without_reprompting`
/// (`authz_approval.rs`), `ac4_a_fresh_agent_instance_never_honors_a_prior_instances_session`
/// (above), `lease_from_a_prior_issuer_instance_is_rejected_as_foreign`
/// (`eltanin-core/tests/lease_restart.rs`), and
/// `a_lease_from_a_prior_agent_instance_does_not_survive_a_restart`
/// (`eltanin-agent/tests/authz_lifecycle.rs`) — proving here that the
/// asymmetry is a real, intentional design property, not accidental
/// drift between four independently-written tests.
///
/// ADR 0010's "`Approval` is the deliberate exception to the
/// Serialize-only rule ADR 0009 established": a durable `Approval` must
/// survive an agent restart ("that is the entire point"), while
/// `TrustedSession`/`ComputeLease` are `Serialize`-only by design and
/// hold no path back from disk at all — an agent restart is a fresh
/// `SessionAuthority`/`LeaseIssuer` with an empty in-memory store, per
/// `ac4_a_fresh_agent_instance_never_honors_a_prior_instances_session`'s
/// own comment.
#[test]
fn s12_a_durable_approval_survives_restart_while_the_session_and_its_lease_do_not() {
    let uid = real_self_uid();
    let store_path = temp_approval_store_path("s12-restart-asymmetry");

    let before_restart = AuthorizationHandler::new(
        IssuerInstanceId::new("instance-before"),
        allow_policy_for_uid(uid),
        backend_with_resource(&[
            eltanin_core::resource::Capability::DeviceEnforce,
            eltanin_core::resource::Capability::DeviceRevoke,
        ]),
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_approval_store(store_path.clone())
            .with_session_requirement(SessionRequirement::Required),
    );
    let peer = self_peer_context();

    let recorded = before_restart.handle(&approve_request(ApprovalDisposition::Remember), &peer);
    assert!(
        matches!(recorded, AgentResponse::ApprovalRecorded { .. }),
        "expected ApprovalRecorded, got {recorded:?}"
    );

    let established = create_session(&before_restart, &peer);
    assert!(matches!(
        established,
        AgentResponse::SessionEstablished { .. }
    ));

    let granted = before_restart.handle(&lease_request(), &peer);
    let AgentResponse::LeaseGranted { lease } = granted else {
        panic!("expected a granted lease before restart, got {granted:?}");
    };
    assert_eq!(
        lease.lease_id.issuer,
        IssuerInstanceId::new("instance-before")
    );

    // "Restart" = a fresh `AuthorizationHandler` — fresh `SessionAuthority`
    // and `LeaseIssuer` instances, empty in-memory stores — reusing only
    // the same on-disk approval store path, exactly as a real agent
    // restart would.
    let after_restart = AuthorizationHandler::new(
        IssuerInstanceId::new("instance-after"),
        allow_policy_for_uid(uid),
        backend_with_resource(&[
            eltanin_core::resource::Capability::DeviceEnforce,
            eltanin_core::resource::Capability::DeviceRevoke,
        ]),
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_approval_store(store_path)
            .with_session_requirement(SessionRequirement::Required),
    );

    // Half 1: the session does NOT survive — the exact same peer, with
    // no session re-established under the new instance, is denied
    // `NoTrustedSession` even though its durable approval would match.
    let response = after_restart.handle(&lease_request(), &peer);
    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::NoTrustedSession
        },
        "a Trusted Compute Session must never survive an agent restart"
    );

    // Half 2: the pre-restart lease does NOT survive — releasing it
    // against the new instance is Refused, never Released.
    let release = after_restart.handle(
        &ClientRequest::ReleaseLease(ReleaseRequest {
            lease_id: lease.lease_id,
        }),
        &peer,
    );
    assert_eq!(
        release,
        AgentResponse::LeaseReleased {
            outcome: ReleaseOutcome::Refused
        },
        "a lease minted by a prior agent instance must never resolve against a new one"
    );

    // Half 3: the durable approval DOES survive — a freshly established
    // session (the human re-proving intent post-restart, as ADR 0009
    // expects) plus the SAME approval recorded before restart admits a
    // fresh lease with zero new `eltanin approve` calls.
    let established_after = create_session(&after_restart, &peer);
    assert!(matches!(
        established_after,
        AgentResponse::SessionEstablished { .. }
    ));
    let response = after_restart.handle(&lease_request(), &peer);
    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "a durable Remember approval must survive an agent restart with zero new approve \
         calls, once the (freshly re-established) session gate is satisfied — got {response:?}"
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
        ClientRequest, DenialReason, FixedClock, IssuerInstanceId, LeaseRequest, MembershipVerdict,
        NotMemberReason, RequestHandler, SessionRequirement,
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

    fn handler_with_session_required(
        sink: Arc<CapturingSessionSink>,
        clock: Arc<FixedClock>,
    ) -> AuthorizationHandler {
        AuthorizationHandler::new(
            IssuerInstanceId::new("test-instance"),
            allow_policy_for_uid(real_self_uid()),
            backend_with_resource(&[
                eltanin_core::resource::Capability::DeviceEnforce,
                eltanin_core::resource::Capability::DeviceRevoke,
            ]),
            clock as Arc<dyn eltanin_agent::authz::Clock>,
            sink,
            &AuthorizationConfig::new(Duration::from_secs(60))
                .unwrap()
                .with_session_requirement(SessionRequirement::Required),
        )
    }

    /// HORO-1278: an audit-observability regression test proving an
    /// expired session's refusal reaches the audit log with real
    /// fidelity, specifically `NotMemberReason::Expired`, not a generic
    /// `SessionRequired`/`Indeterminate`.
    ///
    /// This is non-trivial precisely because
    /// `AuthorizationHandler::membership_for_peer` calls
    /// `SessionState::reap` (which itself calls
    /// `SessionAuthority::validate`, reporting `Expired` and evicting the
    /// session) *before* `find_by_key` ever runs — so by the time
    /// `membership()` would be called, the expired session is already
    /// gone from the store, and `find_by_key` finds nothing. Without
    /// `membership_for_peer` recovering the evicting `SessionValidity`
    /// for a reaped session whose key matches this peer's own key (see
    /// `recorded_reason_for_reaped_validity`), this would report the
    /// same generic `Indeterminate { reason: "no session found..." }`
    /// every other never-established-a-session case reports —
    /// indistinguishable from a peer that never called `CreateSession`
    /// at all. This test pins that recovery.
    #[test]
    fn session_required_reports_the_expired_reason_to_the_audit_log() {
        let sink = Arc::new(CapturingSessionSink::default());
        let clock = FixedClock::new();
        let handler = handler_with_session_required(sink.clone(), clock.clone());
        let peer = self_peer_context();

        let established = create_session(&handler, &peer);
        assert!(matches!(
            established,
            AgentResponse::SessionEstablished { .. }
        ));

        // The session created by `create_session` has a 30s ttl —
        // advance the shared clock well past it, with no explicit
        // `TerminateSession` anywhere in this test.
        clock.advance(Duration::from_secs(31));

        let response = handler.handle(&lease_request(), &peer);
        assert_eq!(
            response,
            AgentResponse::LeaseDenied {
                reason: DenialReason::NoTrustedSession
            },
            "the wire response stays the single, coarse NoTrustedSession denial"
        );

        let (outcome, _session) = sink.last();
        match outcome {
            AuthorizationOutcome::SessionRequired { verdict } => {
                assert!(
                    matches!(
                        verdict,
                        MembershipVerdict::NotMember {
                            reason: NotMemberReason::Expired { .. }
                        }
                    ),
                    "expected an Expired NotMemberReason on the audit-facing outcome, got \
                     {verdict:?}"
                );
            }
            other => panic!("expected AuthorizationOutcome::SessionRequired, got {other:?}"),
        }
    }

    // Note (HORO-1278): `NotMemberReason::HostMismatch`/`AnchorRecycled`
    // are covered only at the conversion level, in
    // `eltanin-agent::authz::audit`'s own unit tests
    // (`recorded_session_refusal_covers_every_not_member_reason`) and
    // `eltanin-audit`'s golden tests, not end-to-end through a real
    // `AuthorizationHandler` here. `membership_for_peer`'s reaped-session
    // recovery (`recorded_reason_for_reaped_validity`) uses the exact
    // same code path for every `SessionValidity` variant regardless of
    // which one fires, so the expiry test above already exercises that
    // recovery mechanism itself — what's missing for `HostMismatch`/
    // `AnchorRecycled` specifically is only a way to make
    // `SessionAuthority::validate` actually report them from this test
    // file: every peer here is a real pid observed through the real
    // platform collector (see the module docs), and there is no
    // injectable seam to fake "the host changed since establishment" or
    // "a different live process now occupies this sid" without either a
    // second real host or a genuine PID-reuse race, neither of which a
    // portable test can construct deterministically.

    /// HORO-1278: same audit-observability regression as above, for
    /// `NotMemberReason::OwnerUidMismatch` — the scenario is exactly
    /// `horo1278_a_different_uid_in_the_same_posix_session_is_refused`'s
    /// (a spoofed observed uid in the same POSIX session), with a
    /// capturing sink added so the audit-facing outcome can be asserted
    /// too, not just the wire response.
    #[test]
    fn session_required_reports_the_owner_uid_mismatch_reason_to_the_audit_log() {
        let sink = Arc::new(CapturingSessionSink::default());
        let handler = handler_with_session_required(sink.clone(), FixedClock::new());
        let owner_peer = self_peer_context();

        let established = create_session(&handler, &owner_peer);
        assert!(matches!(
            established,
            AgentResponse::SessionEstablished { .. }
        ));

        let pid = std::process::id();
        let mut workload = super::platform::collect_workload_identity(pid);
        workload.uid = eltanin_core::identity::Evidence::Present {
            value: real_self_uid() + 1,
            source: eltanin_core::identity::EvidenceSource::KernelObserved,
        };
        let context = eltanin_core::identity::ExecutionContext {
            workload,
            cgroup_path: eltanin_core::identity::Evidence::Unsupported,
            namespace_hint: eltanin_core::identity::Evidence::Unsupported,
            container_hint: eltanin_core::identity::Evidence::Unsupported,
            session_origin: eltanin_core::identity::Evidence::Unsupported,
        };
        let spoofed_uid_peer = eltanin_core::peer::PeerContext::new(
            eltanin_core::peer::PeerCredential::new(pid, real_self_uid(), real_self_uid()),
            eltanin_core::peer::PeerConsistency::Consistent,
            context,
        );

        let response = handler.handle(&lease_request(), &spoofed_uid_peer);
        assert_eq!(
            response,
            AgentResponse::LeaseDenied {
                reason: DenialReason::NoTrustedSession
            }
        );

        let (outcome, _session) = sink.last();
        match outcome {
            AuthorizationOutcome::SessionRequired { verdict } => {
                assert!(
                    matches!(
                        verdict,
                        MembershipVerdict::NotMember {
                            reason: NotMemberReason::OwnerUidMismatch
                        }
                    ),
                    "expected an OwnerUidMismatch NotMemberReason on the audit-facing outcome, \
                     got {verdict:?}"
                );
            }
            other => panic!("expected AuthorizationOutcome::SessionRequired, got {other:?}"),
        }
    }
}
