//! Bounded compute delegation admission and revocation-cascade coverage
//! (F-M2-003, HORO-793). Exercises every acceptance criterion through
//! the same public `RequestHandler` interface a real client uses — never
//! by reaching into `authz::delegation_state` directly, which is
//! intentionally private. Uses a `CapturingSink` to inspect the rich
//! internal `AuthorizationOutcome` a test needs (e.g.
//! `GrantedByDelegation`'s `parent_lease`/`depth`) that the deliberately
//! lossy wire response cannot provide.
//!
//! # Every delegation "holder" must be a real, observable process
//!
//! `delegated_admission`'s holder-liveness check re-observes the grant
//! holder's pid straight through the real platform collector (mirroring
//! `authz::session`'s identical, deliberately non-injectable contract —
//! see `authz_session.rs`'s own module docs on why a synthetic pid
//! cannot honestly exercise this path). Every test below anchors its
//! "parent"/"holder" role on this test binary's own real pid
//! (`std::process::id()`), which is alive for the test's whole duration.
//! The one test that needs a *second* real holder (the two-level depth
//! chain) spawns a real child process. A *descendant* role never needs
//! to be real — only its ancestry entry naming the (real) holder does —
//! so every descendant peer in this file is a synthetic identity whose
//! `ancestry` is built from the real holder's actual observed pid/start
//! token.

mod support;

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eltanin_agent::authz::event::{AuthorizationEvent, AuthorizationOutcome, EventSink};
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler};
use eltanin_agent::handler::RequestHandler;
use eltanin_backend::fake::FakeBackend;
use eltanin_core::approval::ApprovalDisposition;
use eltanin_core::delegation::{DelegationBounds, ExceededBound};
use eltanin_core::identity::{
    Evidence, EvidenceSource, ExecutionContext, ProcessAncestor, ProcessStartToken,
    WorkloadIdentity,
};
use eltanin_core::lease::{IssuerInstanceId, LeaseId};
use eltanin_core::peer::{PeerConsistency, PeerContext, PeerCredential};
use eltanin_core::policy::{
    Condition, Effect, EvidenceMatch, PolicyDocument, PolicyId, PolicySet, Rule, RuleId, TrustFloor,
};
use eltanin_core::resource::{Action, Capability};
use eltanin_protocol::request::{
    ApproveRequest, ClientRequest, CreateSessionRequest, LeaseRequest, ReleaseRequest,
};
use eltanin_protocol::response::{AgentResponse, DenialReason};
use support::authz::{backend_with_resource, resource_identity, FixedClock};
use support::temp_approval_store_path;

#[cfg(not(target_os = "macos"))]
use eltanin_linux as platform;
#[cfg(target_os = "macos")]
use eltanin_macos as platform;

// ---------------------------------------------------------------------
// Shared support (local to this file — no other suite needs a
// delegation-shaped peer).
// ---------------------------------------------------------------------

/// A [`PeerContext`] for a *real* pid on this host, mirroring
/// `authz_session.rs::peer_context_for_pid` exactly.
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

/// This test binary's own real, kernel-observed uid.
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

/// Build a synthetic descendant `PeerContext` whose immediate parent
/// (ancestry index 0) is `holder` — extracted from `holder`'s own
/// already-observed `pid`/`process_start`, real or otherwise. This is
/// the exact shape `delegated_admission`'s ancestry-linkage check
/// requires.
fn descendant_of(holder: &PeerContext, uid: u32, executable_hash: &str, tag: u32) -> PeerContext {
    let holder_workload = &holder.observed().workload;
    let holder_start = match &holder_workload.process_start {
        Evidence::Present { value, .. } => value.clone(),
        other => panic!("holder must have a present process_start, got {other:?}"),
    };
    let pid = holder_workload.pid + 2_000_000 + tag;
    let workload = WorkloadIdentity {
        pid,
        process_start: Evidence::Present {
            value: ProcessStartToken(u64::from(pid)),
            source: EvidenceSource::KernelObserved,
        },
        uid: Evidence::Present {
            value: uid,
            source: EvidenceSource::KernelObserved,
        },
        gid: Evidence::Unsupported,
        executable_path: Evidence::Present {
            value: "/usr/bin/eltanin-test-descendant".to_string(),
            source: EvidenceSource::KernelObserved,
        },
        executable_hash: Evidence::Present {
            value: executable_hash.to_string(),
            source: EvidenceSource::KernelObserved,
        },
        ancestry: vec![ProcessAncestor {
            pid: holder_workload.pid,
            start: Evidence::Present {
                value: holder_start,
                source: EvidenceSource::KernelObserved,
            },
            executable_path: holder_workload.executable_path.clone(),
        }],
    };
    let observed = ExecutionContext {
        workload,
        cgroup_path: Evidence::Unsupported,
        namespace_hint: Evidence::Unsupported,
        container_hint: Evidence::Unsupported,
        session_origin: Evidence::Unsupported,
    };
    PeerContext::new(
        PeerCredential::new(pid, uid, uid),
        PeerConsistency::Consistent,
        observed,
    )
}

/// Spawn a real child process (reusing the existing `session_probe_fixture`
/// binary purely as "a real, controllable child process with this binary
/// as its real ppid" — its `setsid()` call changes only the POSIX session,
/// never the parent-pid ancestry this test relies on). Returns the child
/// handle (caller must eventually clean it up via [`kill_probe`]) and its
/// real pid.
fn spawn_real_child() -> (Child, u32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_session_probe_fixture"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn session_probe_fixture");
    let mut reader = std::io::BufReader::new(child.stdout.take().expect("child stdout"));
    let mut line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut line).expect("read readiness line");
    assert!(
        line.starts_with("ready"),
        "unexpected fixture output: {line:?}"
    );
    let pid: u32 = line
        .trim()
        .strip_prefix("ready pid=")
        .expect("readiness line names a pid")
        .parse()
        .expect("pid is a valid u32");
    (child, pid)
}

fn kill_probe(mut child: Child) {
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"x");
    }
    let _ = child.wait();
}

/// Records every [`AuthorizationOutcome`] this handler produces, in
/// order — tests assert against these rather than the wire response
/// when they need internal fidelity.
#[derive(Default)]
struct CapturingSink {
    outcomes: Mutex<Vec<AuthorizationOutcome>>,
}

impl EventSink for CapturingSink {
    fn record(&self, event: &AuthorizationEvent<'_>) {
        self.outcomes.lock().unwrap().push(event.outcome.clone());
    }
}

impl CapturingSink {
    fn last(&self) -> AuthorizationOutcome {
        self.outcomes
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("at least one outcome must have been recorded")
    }
}

fn lease_request() -> ClientRequest {
    ClientRequest::RequestLease(LeaseRequest {
        resource: resource_identity(),
        action: Action::Compute,
    })
}

fn approve_request(disposition: ApprovalDisposition) -> ClientRequest {
    ClientRequest::Approve(ApproveRequest {
        resource: resource_identity(),
        action: Action::Compute,
        disposition,
    })
}

fn release_request(lease_id: LeaseId) -> ClientRequest {
    ClientRequest::ReleaseLease(ReleaseRequest { lease_id })
}

fn default_bounds(max_depth: u8) -> DelegationBounds {
    DelegationBounds::new(
        max_depth,
        Duration::from_secs(300),
        Duration::from_secs(1),
        [Action::Compute],
        std::collections::BTreeSet::new(),
        false,
        false,
    )
    .unwrap()
}

fn allow_policy_for_uid(uid: u32) -> PolicySet {
    let rule = Rule {
        id: RuleId::new("allow-uid"),
        effect: Effect::Allow,
        resource: resource_identity(),
        action: Action::Compute,
        conditions: vec![Condition::Uid(EvidenceMatch {
            expected: uid,
            min_trust: TrustFloor::KernelObserved,
        })],
    };
    PolicySet::from_document(PolicyDocument {
        id: PolicyId::new("test-policy"),
        revision: 1,
        rules: vec![rule],
    })
    .expect("valid test policy")
}

/// A policy allowing `uid` **and** requiring `executable_path` to match
/// exactly — used by the "policy still denies a delegated request" test,
/// where the descendant's own (synthetic) executable path legitimately
/// differs from its (real) parent's.
fn allow_policy_for_uid_and_path(uid: u32, path: &str) -> PolicySet {
    let rule = Rule {
        id: RuleId::new("allow-uid-and-path"),
        effect: Effect::Allow,
        resource: resource_identity(),
        action: Action::Compute,
        conditions: vec![
            Condition::Uid(EvidenceMatch {
                expected: uid,
                min_trust: TrustFloor::KernelObserved,
            }),
            Condition::ExecutablePath(EvidenceMatch {
                expected: path.to_string(),
                min_trust: TrustFloor::KernelObserved,
            }),
        ],
    };
    PolicySet::from_document(PolicyDocument {
        id: PolicyId::new("path-scoped-policy"),
        revision: 1,
        rules: vec![rule],
    })
    .expect("valid test policy")
}

/// An explicit `Deny` rule for `uid`/`Compute` (deny-overrides) — used to
/// prove `PolicySet::evaluate` stays fully authoritative regardless of
/// delegation.
fn deny_uid_policy(uid: u32) -> PolicySet {
    let rule = Rule {
        id: RuleId::new("deny-uid"),
        effect: Effect::Deny,
        resource: resource_identity(),
        action: Action::Compute,
        conditions: vec![Condition::Uid(EvidenceMatch {
            expected: uid,
            min_trust: TrustFloor::KernelObserved,
        })],
    };
    PolicySet::from_document(PolicyDocument {
        id: PolicyId::new("deny-uid-policy"),
        revision: 1,
        rules: vec![rule],
    })
    .expect("valid test policy")
}

/// Approvals required, delegation **not** configured — the exact
/// pre-HORO-793 shape of `handler_with_delegation` below, isolating
/// delegation's own contribution rather than the approval gate's.
fn handler_approvals_only(
    policy: PolicySet,
    backend: Arc<FakeBackend>,
    store_path: std::path::PathBuf,
    sink: Arc<CapturingSink>,
) -> AuthorizationHandler {
    AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        policy,
        backend,
        FixedClock::new(),
        sink,
        &AuthorizationConfig::new(Duration::from_secs(300))
            .unwrap()
            .with_approval_store(store_path),
    )
}

fn handler_with_delegation(
    policy: PolicySet,
    backend: Arc<FakeBackend>,
    store_path: std::path::PathBuf,
    bounds: DelegationBounds,
    sink: Arc<CapturingSink>,
) -> AuthorizationHandler {
    AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        policy,
        backend,
        FixedClock::new(),
        sink,
        &AuthorizationConfig::new(Duration::from_secs(300))
            .unwrap()
            .with_delegation(store_path, bounds),
    )
}

/// Establish an ordinary (non-delegated, depth-0) grant for `peer`:
/// records a `Remember` approval, then requests the lease. Returns the
/// granted `LeaseId`.
fn establish_parent_grant(handler: &AuthorizationHandler, peer: &PeerContext) -> LeaseId {
    let response = handler.handle(&approve_request(ApprovalDisposition::Remember), peer);
    assert!(
        matches!(response, AgentResponse::ApprovalRecorded { .. }),
        "expected ApprovalRecorded, got {response:?}"
    );
    let response = handler.handle(&lease_request(), peer);
    let AgentResponse::LeaseGranted { lease } = response else {
        panic!("expected LeaseGranted for the parent's own ordinary grant, got {response:?}");
    };
    lease.lease_id
}

// ---------------------------------------------------------------------
// AC: expected developer descendant chain can run silently under
// bounded authority.
// ---------------------------------------------------------------------

#[test]
fn non_negotiable_regression_delegation_not_configured_is_byte_identical() {
    // Same shape as authz_approval.rs's own default-config regression
    // test: a descendant with no matching approval must be refused
    // exactly as before HORO-793, never silently admitted, when
    // delegation was never configured — even though its ancestry
    // genuinely links it to an already-admitted, still-live parent.
    let uid = real_self_uid();
    let parent = self_peer_context();
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    let handler = handler_approvals_only(
        allow_policy_for_uid(uid),
        backend,
        temp_approval_store_path("delegation-not-configured-regression"),
        sink,
    );

    establish_parent_grant(&handler, &parent);

    let descendant = descendant_of(&parent, uid, "sha256:trusted-child", 1);
    let response = handler.handle(&lease_request(), &descendant);

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired
        },
        "delegation not configured must behave exactly as pre-HORO-793: no approval, no grant"
    );
}

#[test]
fn descendant_admitted_silently_and_audit_records_granted_by_delegation() {
    let uid = real_self_uid();
    let parent = self_peer_context();
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    let handler = handler_with_delegation(
        allow_policy_for_uid(uid),
        backend,
        temp_approval_store_path("delegation-basic"),
        default_bounds(4),
        sink.clone(),
    );

    let parent_lease_id = establish_parent_grant(&handler, &parent);

    let descendant = descendant_of(&parent, uid, "sha256:trusted-child", 1);
    let response = handler.handle(&lease_request(), &descendant);

    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "descendant with no approval of its own must still be silently admitted via delegation, got {response:?}"
    );

    match sink.last() {
        AuthorizationOutcome::GrantedByDelegation {
            parent_lease,
            depth,
            holder_pid,
            ..
        } => {
            assert_eq!(parent_lease, parent_lease_id);
            assert_eq!(depth, 1);
            assert_eq!(holder_pid, std::process::id());
        }
        other => panic!("expected GrantedByDelegation, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// AC: a child cannot expand resource/action/duration beyond delegator
// allowance (deny-overrides / policy-still-applies variants).
// ---------------------------------------------------------------------

#[test]
fn explicit_deny_approval_for_the_child_beats_delegation() {
    let uid = real_self_uid();
    let parent = self_peer_context();
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    let handler = handler_with_delegation(
        allow_policy_for_uid(uid),
        backend,
        temp_approval_store_path("delegation-deny-overrides"),
        default_bounds(4),
        sink,
    );

    establish_parent_grant(&handler, &parent);

    let descendant = descendant_of(&parent, uid, "sha256:trusted-child", 2);
    // The descendant explicitly records its own Deny for this exact
    // (resource, action) — this must win over an otherwise-admitting
    // delegation grant, exactly like it wins over an ordinary matching
    // approval.
    let response = handler.handle(&approve_request(ApprovalDisposition::Deny), &descendant);
    assert!(matches!(response, AgentResponse::ApprovalRecorded { .. }));

    let response = handler.handle(&lease_request(), &descendant);
    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalDenied
        }
    );
}

#[test]
fn policy_deny_still_denies_a_delegated_request() {
    let uid = real_self_uid();
    let parent = self_peer_context();
    let parent_path = match &parent.observed().workload.executable_path {
        Evidence::Present { value, .. } => value.clone(),
        other => {
            panic!("expected this test process's own executable path to be present, got {other:?}")
        }
    };
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    // Policy allows `uid` only when the executable path matches the
    // parent's own real one — the descendant's own (legitimately
    // different, synthetic) path fails this at
    // `issue_reserving_capacity`'s fresh policy evaluation, even though
    // delegation itself admitted the request.
    let policy = allow_policy_for_uid_and_path(uid, &parent_path);
    let handler = handler_with_delegation(
        policy,
        backend,
        temp_approval_store_path("delegation-policy-still-applies"),
        default_bounds(4),
        sink,
    );

    establish_parent_grant(&handler, &parent);

    let descendant = descendant_of(&parent, uid, "sha256:trusted-child", 3);
    let response = handler.handle(&lease_request(), &descendant);

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::NoMatchingRule
        },
        "delegation only widens admission past the approval gate — policy must still independently deny"
    );
}

#[test]
fn policy_deny_rule_denies_a_delegated_request_too() {
    // Same point as above, via an explicit Deny rule (deny-overrides)
    // instead of default-deny, proving PolicySet::evaluate is completely
    // untouched by delegation either way: under a Deny-everything (for
    // this uid) policy, even the parent's own ordinary grant cannot be
    // issued.
    let uid = real_self_uid();
    let parent = self_peer_context();
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    let handler = handler_with_delegation(
        deny_uid_policy(uid),
        backend,
        temp_approval_store_path("delegation-deny-rule"),
        default_bounds(4),
        sink,
    );

    let response = handler.handle(&approve_request(ApprovalDisposition::Remember), &parent);
    assert!(matches!(response, AgentResponse::ApprovalRecorded { .. }));
    let response = handler.handle(&lease_request(), &parent);
    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ExplicitDeny
        }
    );
}

// ---------------------------------------------------------------------
// AC: revoking parent/session authority invalidates future delegated
// lease issue.
// ---------------------------------------------------------------------

#[test]
fn revoking_the_parent_lease_removes_the_descendant_grant() {
    let uid = real_self_uid();
    let parent = self_peer_context();
    let backend = backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]);
    let sink = Arc::new(CapturingSink::default());
    let handler = handler_with_delegation(
        allow_policy_for_uid(uid),
        backend,
        temp_approval_store_path("delegation-revoke-parent"),
        default_bounds(4),
        sink,
    );

    let parent_lease_id = establish_parent_grant(&handler, &parent);

    let descendant = descendant_of(&parent, uid, "sha256:trusted-child", 4);
    let response = handler.handle(&lease_request(), &descendant);
    assert!(matches!(response, AgentResponse::LeaseGranted { .. }));

    let response = handler.handle(&release_request(parent_lease_id), &parent);
    assert_eq!(
        response,
        AgentResponse::LeaseReleased {
            outcome: eltanin_protocol::response::ReleaseOutcome::Released
        }
    );

    // The descendant's own grant must be gone with it — a fresh request
    // (no approval of its own, no live grant to admit under) is refused.
    let response = handler.handle(&lease_request(), &descendant);
    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired
        }
    );
}

#[test]
fn terminating_the_session_cascades_through_the_parent_lease_to_the_descendant() {
    let uid = real_self_uid();
    let parent = self_peer_context();
    let backend = backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]);
    let sink = Arc::new(CapturingSink::default());
    let handler = handler_with_delegation(
        allow_policy_for_uid(uid),
        backend,
        temp_approval_store_path("delegation-terminate-session"),
        default_bounds(4),
        sink,
    );

    let create_session = ClientRequest::CreateSession(CreateSessionRequest {
        resources: vec![resource_identity()],
        ttl: Duration::from_secs(120),
    });
    let response = handler.handle(&create_session, &parent);
    assert!(
        matches!(response, AgentResponse::SessionEstablished { .. }),
        "expected SessionEstablished, got {response:?}"
    );

    establish_parent_grant(&handler, &parent);

    let descendant = descendant_of(&parent, uid, "sha256:trusted-child", 5);
    let response = handler.handle(&lease_request(), &descendant);
    assert!(matches!(response, AgentResponse::LeaseGranted { .. }));

    let response = handler.handle(&ClientRequest::TerminateSession {}, &parent);
    assert!(matches!(
        response,
        AgentResponse::SessionTerminated {
            outcome: eltanin_protocol::response::TerminationOutcome::Terminated
        }
    ));

    let response = handler.handle(&lease_request(), &descendant);
    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired
        },
        "terminating the session must have cascaded through the parent lease to the descendant's grant"
    );
}

// ---------------------------------------------------------------------
// Depth chain end-to-end. Needs a second real process (the depth-1
// holder) so the grandchild's own holder-liveness check has something
// genuinely observable to confirm — see this file's module docs.
// ---------------------------------------------------------------------

#[test]
fn two_level_chain_admits_to_max_depth_and_refuses_beyond_it() {
    let uid = real_self_uid();
    let parent = self_peer_context();
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    let handler = handler_with_delegation(
        allow_policy_for_uid(uid),
        backend,
        temp_approval_store_path("delegation-depth-chain"),
        default_bounds(2),
        sink.clone(),
    );

    establish_parent_grant(&handler, &parent);

    let (child_process, child_pid) = spawn_real_child();
    let child = peer_context_for_pid(child_pid, uid);

    // depth 0 -> 1, child is a real process.
    let response = handler.handle(&lease_request(), &child);
    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "expected LeaseGranted for the real child, got {response:?}"
    );
    assert!(matches!(
        sink.last(),
        AuthorizationOutcome::GrantedByDelegation { depth: 1, .. }
    ));

    // depth 1 -> 2 (== max_depth, still admitted). The grandchild is
    // synthetic — only its ancestry entry naming the (real, still alive)
    // child matters.
    let grandchild = descendant_of(&child, uid, "sha256:trusted-grandchild", 6);
    let response = handler.handle(&lease_request(), &grandchild);
    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "depth == max_depth must still admit, got {response:?}"
    );
    assert!(matches!(
        sink.last(),
        AuthorizationOutcome::GrantedByDelegation { depth: 2, .. }
    ));

    kill_probe(child_process);
}

#[test]
fn depth_exceeding_max_depth_is_refused() {
    let uid = real_self_uid();
    let parent = self_peer_context();
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    // max_depth = 1: the real child's own grant (depth 1) is fine, but a
    // further descendant of it (depth 2) exceeds the bound.
    let handler = handler_with_delegation(
        allow_policy_for_uid(uid),
        backend,
        temp_approval_store_path("delegation-depth-exceeded"),
        default_bounds(1),
        sink.clone(),
    );

    establish_parent_grant(&handler, &parent);

    let (child_process, child_pid) = spawn_real_child();
    let child = peer_context_for_pid(child_pid, uid);
    let response = handler.handle(&lease_request(), &child);
    assert!(matches!(response, AgentResponse::LeaseGranted { .. }));

    let grandchild = descendant_of(&child, uid, "sha256:trusted-grandchild", 7);
    let response = handler.handle(&lease_request(), &grandchild);

    kill_probe(child_process);

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired
        }
    );
    match sink.last() {
        AuthorizationOutcome::DelegationRefused { exceeded } => {
            assert!(
                exceeded.contains(&ExceededBound::Depth),
                "expected Depth in {exceeded:?}"
            );
        }
        other => panic!("expected DelegationRefused, got {other:?}"),
    }
}
