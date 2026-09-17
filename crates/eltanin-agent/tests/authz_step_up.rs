//! Risk-based step-up classification coverage (F-M2-004, HORO-794).
//! Exercises every acceptance criterion through the same public
//! `RequestHandler` interface a real client uses — never by reaching
//! into `authz::risk` directly, which is intentionally private. Uses a
//! `CapturingSink` (same shape as `authz_delegation.rs`'s own) to
//! inspect the rich internal `AuthorizationOutcome`/`RiskSignal` detail
//! the deliberately lossy wire response cannot provide.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eltanin_agent::authz::event::{AuthorizationEvent, AuthorizationOutcome, EventSink};
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler};
use eltanin_agent::handler::RequestHandler;
use eltanin_backend::fake::FakeBackend;
use eltanin_core::approval::ApprovalDisposition;
use eltanin_core::delegation::DelegationBounds;
use eltanin_core::identity::{
    Evidence, EvidenceSource, ExecutionContext, ProcessAncestor, ProcessStartToken,
    WorkloadIdentity,
};
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::peer::{PeerConsistency, PeerContext, PeerCredential};
use eltanin_core::resource::{
    AcceleratorMemory, Action, Capability, ProtectedResource, ResourceCapabilities,
    ResourceIdentity, ResourceKind, ResourceVendor,
};
use eltanin_core::risk::{RiskSignal, SignalDisposition, StepUpPolicy};
use eltanin_protocol::request::{ApproveRequest, ClientRequest, LeaseRequest};
use eltanin_protocol::response::{AgentResponse, DenialReason};
use support::authz::{allow_policy_for_uid, resource_identity, FixedClock, TestPeer};
use support::temp_approval_store_path;

#[cfg(not(target_os = "macos"))]
use eltanin_linux as platform;
#[cfg(target_os = "macos")]
use eltanin_macos as platform;

/// A [`PeerContext`] for a *real* pid on this host, mirroring
/// `authz_delegation.rs`'s identical helper — delegation's
/// holder-liveness check re-observes the holder pid through the real
/// platform collector, so a synthetic `TestPeer` cannot honestly play
/// the "holder" role in these regression tests.
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

/// Spawn a real child process, mirroring `authz_delegation.rs`'s
/// identical helper — used as a second, genuinely distinct real holder.
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
/// order — mirrors `authz_delegation.rs`'s identical helper.
#[derive(Default)]
struct CapturingSink {
    outcomes: Mutex<Vec<AuthorizationOutcome>>,
}

impl EventSink for CapturingSink {
    fn record(&self, event: &AuthorizationEvent<'_>) {
        self.outcomes.lock().unwrap().push(event.outcome.clone());
    }

    // No agent-emitted event assertions in this test file; discarding
    // here mirrors NullSink's own explicit (not defaulted) no-op.
    fn record_agent_event(&self, _event: eltanin_audit::record::RecordedAgentEvent) {}
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

fn backend_with_resource(
    identity: &ResourceIdentity,
    capabilities: &[Capability],
) -> Arc<FakeBackend> {
    let backend = Arc::new(FakeBackend::new());
    backend.insert(ProtectedResource {
        identity: identity.clone(),
        capabilities: ResourceCapabilities::new(capabilities.iter().copied()),
        memory: AcceleratorMemory::NotReportable,
    });
    backend
}

/// A [`PolicySet`] allowing `uid` for every resource in `resources` —
/// used by the delegation-bug-regression tests, which need two distinct
/// resources both admissible so the parent/unrelated-holder's own
/// ordinary grants can each be established.
fn allow_policy_for_uid_over(
    uid: u32,
    resources: &[ResourceIdentity],
) -> eltanin_core::policy::PolicySet {
    use eltanin_core::policy::{
        Condition, Effect, EvidenceMatch, PolicyDocument, PolicyId, PolicySet, Rule, RuleId,
        TrustFloor,
    };
    let rules = resources
        .iter()
        .enumerate()
        .map(|(index, resource)| Rule {
            id: RuleId::new(format!("allow-uid-{index}")),
            effect: Effect::Allow,
            resource: resource.clone(),
            action: Action::Compute,
            conditions: vec![Condition::Uid(EvidenceMatch {
                expected: uid,
                min_trust: TrustFloor::KernelObserved,
            })],
        })
        .collect();
    PolicySet::from_document(PolicyDocument {
        id: PolicyId::new("test-policy-multi"),
        revision: 1,
        rules,
    })
    .expect("valid test policy")
}

fn second_resource_identity() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-1".to_string(),
    }
}

fn lease_request_for(resource: &ResourceIdentity) -> ClientRequest {
    ClientRequest::RequestLease(LeaseRequest {
        resource: resource.clone(),
        action: Action::Compute,
    })
}

fn lease_request() -> ClientRequest {
    lease_request_for(&resource_identity())
}

fn approve_request_for(
    resource: &ResourceIdentity,
    disposition: ApprovalDisposition,
) -> ClientRequest {
    ClientRequest::Approve(ApproveRequest {
        resource: resource.clone(),
        action: Action::Compute,
        disposition,
    })
}

fn approve_request(disposition: ApprovalDisposition) -> ClientRequest {
    approve_request_for(&resource_identity(), disposition)
}

fn step_up_policy(dispositions: &[(RiskSignal, SignalDisposition)]) -> StepUpPolicy {
    StepUpPolicy::new(dispositions.iter().copied().collect(), BTreeSet::new()).unwrap()
}

fn handler_with_step_up(
    policy: eltanin_core::policy::PolicySet,
    backend: Arc<FakeBackend>,
    store_path: std::path::PathBuf,
    step_up: StepUpPolicy,
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
            .with_step_up(store_path, step_up),
    )
}

fn handler_approvals_only(
    policy: eltanin_core::policy::PolicySet,
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

// ---------------------------------------------------------------------
// Seeded trust-boundary changes deterministically trigger configured
// deny/step-up.
// ---------------------------------------------------------------------

#[test]
fn seeded_digest_change_triggers_step_up_and_audit_names_launcher_identity_changed() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let backend = backend_with_resource(&resource_identity(), &[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    let handler = handler_with_step_up(
        allow_policy_for_uid(1000),
        backend,
        temp_approval_store_path("step-up-digest-change"),
        step_up_policy(&[(
            RiskSignal::LauncherIdentityChanged,
            SignalDisposition::StepUp,
        )]),
        sink.clone(),
    );

    handler.handle(
        &approve_request(ApprovalDisposition::Remember),
        &peer.context(),
    );

    let mut replaced = peer.clone();
    replaced.executable_hash = "sha256:replaced-binary";
    let response = handler.handle(&lease_request(), &replaced.context());

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::StepUpRequired
        }
    );
    match sink.last() {
        AuthorizationOutcome::StepUpRequired { signals } => {
            assert!(
                signals.contains(&RiskSignal::LauncherIdentityChanged),
                "expected LauncherIdentityChanged in {signals:?}"
            );
        }
        other => panic!("expected StepUpRequired, got {other:?}"),
    }
}

#[test]
fn uid_transition_to_root_is_risk_denied_naming_privilege_escalation_to_root() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let backend = backend_with_resource(&resource_identity(), &[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    let handler = handler_with_step_up(
        allow_policy_for_uid(1000),
        backend,
        temp_approval_store_path("step-up-root-escalation"),
        step_up_policy(&[
            (RiskSignal::PrivilegeTransition, SignalDisposition::StepUp),
            (
                RiskSignal::PrivilegeEscalationToRoot,
                SignalDisposition::Deny,
            ),
        ]),
        sink.clone(),
    );

    handler.handle(
        &approve_request(ApprovalDisposition::Remember),
        &peer.context(),
    );

    let root_peer = TestPeer::fresh(0, peer.executable_hash);
    let response = handler.handle(&lease_request(), &root_peer.context());

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::RiskDenied
        }
    );
    match sink.last() {
        AuthorizationOutcome::RiskDenied { signals } => {
            assert!(
                signals.contains(&RiskSignal::PrivilegeEscalationToRoot),
                "expected PrivilegeEscalationToRoot in {signals:?}"
            );
        }
        other => panic!("expected RiskDenied, got {other:?}"),
    }
}

#[test]
fn capability_drift_triggers_security_posture_changed() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let identity = resource_identity();
    let backend = backend_with_resource(&identity, &[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    let handler = handler_with_step_up(
        allow_policy_for_uid(1000),
        Arc::clone(&backend),
        temp_approval_store_path("step-up-capability-drift"),
        step_up_policy(&[(
            RiskSignal::SecurityPostureChanged,
            SignalDisposition::StepUp,
        )]),
        sink.clone(),
    );

    handler.handle(
        &approve_request(ApprovalDisposition::Remember),
        &peer.context(),
    );

    // The resource's advertised capabilities changed since the approval
    // was recorded — same identity, different snapshot.
    backend.insert(ProtectedResource {
        identity,
        capabilities: ResourceCapabilities::new([
            Capability::DeviceEnforce,
            Capability::DeviceRevoke,
        ]),
        memory: AcceleratorMemory::NotReportable,
    });

    let response = handler.handle(&lease_request(), &peer.context());

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::StepUpRequired
        }
    );
    match sink.last() {
        AuthorizationOutcome::StepUpRequired { signals } => {
            assert!(
                signals.contains(&RiskSignal::SecurityPostureChanged),
                "expected SecurityPostureChanged in {signals:?}"
            );
        }
        other => panic!("expected StepUpRequired, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// All-Informational config: refusal stays plain ApprovalRequired.
// ---------------------------------------------------------------------

#[test]
fn all_informational_config_leaves_refusal_as_plain_approval_required() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let backend = backend_with_resource(&resource_identity(), &[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    let handler = handler_with_step_up(
        allow_policy_for_uid(1000),
        backend,
        temp_approval_store_path("step-up-informational-only"),
        step_up_policy(&[(
            RiskSignal::LauncherIdentityChanged,
            SignalDisposition::Informational,
        )]),
        sink.clone(),
    );

    handler.handle(
        &approve_request(ApprovalDisposition::Remember),
        &peer.context(),
    );

    let mut replaced = peer.clone();
    replaced.executable_hash = "sha256:replaced-binary";
    let response = handler.handle(&lease_request(), &replaced.context());

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired
        },
        "Informational-only disposition must never surface as a stricter denial"
    );
    assert!(matches!(
        sink.last(),
        AuthorizationOutcome::ApprovalRequired
    ));
}

// ---------------------------------------------------------------------
// Regression for the HORO-793 bug fix: an unrelated stored grant for a
// different resource must not produce DelegationScopeExpanded; a
// linked descendant genuinely exceeding a scope bound must.
// ---------------------------------------------------------------------

fn descendant_of(holder: &PeerContext, uid: u32, tag: u32) -> PeerContext {
    let holder_workload = &holder.observed().workload;
    let holder_start = match &holder_workload.process_start {
        Evidence::Present { value, .. } => value.clone(),
        other => panic!("holder must have a present process_start, got {other:?}"),
    };
    let pid = holder_workload.pid + 3_000_000 + tag;
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
            value: "sha256:trusted-child".to_string(),
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

fn bounds(max_depth: u8) -> DelegationBounds {
    DelegationBounds::new(
        max_depth,
        Duration::from_secs(300),
        Duration::from_secs(1),
        [Action::Compute],
        BTreeSet::new(),
        false,
        false,
    )
    .unwrap()
}

fn handler_with_delegation_and_step_up(
    policy: eltanin_core::policy::PolicySet,
    backend: Arc<FakeBackend>,
    store_path: std::path::PathBuf,
    delegation_bounds: DelegationBounds,
    step_up: StepUpPolicy,
    sink: Arc<CapturingSink>,
) -> AuthorizationHandler {
    // `with_step_up` and `with_delegation` both couple
    // approval_requirement/approval_store_path — apply delegation first,
    // then step_up, so both end up set (mirrors the ticket's own
    // "with_step_up sets Required + store path in the same call"
    // contract; calling both in sequence on the same builder composes
    // cleanly since neither clears the other's field).
    let config = AuthorizationConfig::new(Duration::from_secs(300))
        .unwrap()
        .with_delegation(store_path.clone(), delegation_bounds)
        .with_step_up(store_path, step_up);
    AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        policy,
        backend,
        FixedClock::new(),
        sink,
        &config,
    )
}

#[test]
fn unrelated_grant_for_a_different_resource_does_not_leak_into_delegation_scope_expanded() {
    let gpu0 = resource_identity();
    let gpu1 = second_resource_identity();

    let backend = Arc::new(FakeBackend::new());
    backend.insert(ProtectedResource {
        identity: gpu0.clone(),
        capabilities: ResourceCapabilities::new([Capability::DeviceEnforce]),
        memory: AcceleratorMemory::NotReportable,
    });
    backend.insert(ProtectedResource {
        identity: gpu1.clone(),
        capabilities: ResourceCapabilities::new([Capability::DeviceEnforce]),
        memory: AcceleratorMemory::NotReportable,
    });

    let uid = real_self_uid();
    let policy = allow_policy_for_uid_over(uid, &[gpu0.clone(), gpu1.clone()]);
    let sink = Arc::new(CapturingSink::default());
    // max_depth = 4 so depth alone never exceeds; the point of this test
    // is the uid mismatch (a non-scope bound) versus the unrelated
    // grant's spurious Resource bound.
    let handler = handler_with_delegation_and_step_up(
        policy,
        backend,
        temp_approval_store_path("step-up-delegation-bug-regression"),
        bounds(4),
        step_up_policy(&[
            (RiskSignal::PrivilegeTransition, SignalDisposition::StepUp),
            (RiskSignal::DelegationScopeExpanded, SignalDisposition::Deny),
        ]),
        sink.clone(),
    );

    // Parent P: a real, alive process (this test binary itself) with an
    // ordinary depth-0 grant for gpu0 — delegation's holder-liveness
    // check re-observes the holder pid for real, so P must be real.
    let parent = self_peer_context();
    let response = handler.handle(
        &approve_request_for(&gpu0, ApprovalDisposition::Remember),
        &parent,
    );
    assert!(matches!(response, AgentResponse::ApprovalRecorded { .. }));
    let response = handler.handle(&lease_request_for(&gpu0), &parent);
    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "expected the parent's own ordinary grant to succeed, got {response:?}"
    );

    // Unrelated holder Q: a second, genuinely distinct real process with
    // a completely separate ordinary depth-0 grant for gpu1 — present in
    // the store purely to exercise DelegationState::candidates()'s
    // unfiltered scan. The requester below is not its descendant.
    let (unrelated_process, unrelated_pid) = spawn_real_child();
    let unrelated_holder = peer_context_for_pid(unrelated_pid, uid);
    let response = handler.handle(
        &approve_request_for(&gpu1, ApprovalDisposition::Remember),
        &unrelated_holder,
    );
    assert!(matches!(response, AgentResponse::ApprovalRecorded { .. }));
    let response = handler.handle(&lease_request_for(&gpu1), &unrelated_holder);
    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "expected the unrelated holder's own grant to succeed, got {response:?}"
    );

    // The requester descends from P (genuinely linked, alive) but has a
    // different uid than P's grant recorded — fails OwnerUid only (not
    // a scope-class bound). It is NOT a descendant of the unrelated
    // holder Q at all.
    let requester = descendant_of(&parent, uid.wrapping_add(1), 1);
    let response = handler.handle(&lease_request_for(&gpu0), &requester);
    kill_probe(unrelated_process);

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::StepUpRequired
        },
        "the unrelated grant's spurious Resource bound must not escalate this to RiskDenied"
    );
    match sink.last() {
        AuthorizationOutcome::StepUpRequired { signals } => {
            assert!(
                signals.contains(&RiskSignal::PrivilegeTransition),
                "expected PrivilegeTransition (OwnerUid mismatch) in {signals:?}"
            );
            assert!(
                !signals.contains(&RiskSignal::DelegationScopeExpanded),
                "the unrelated grant's Resource bound (a lookup miss, not a scope-expansion \
                 attempt) must not surface as DelegationScopeExpanded — signals: {signals:?}"
            );
        }
        other => panic!("expected StepUpRequired, got {other:?}"),
    }
}

#[test]
fn a_genuinely_linked_descendant_exceeding_scope_does_trigger_delegation_scope_expanded() {
    let gpu0 = resource_identity();
    let backend = backend_with_resource(&gpu0, &[Capability::DeviceEnforce]);
    let uid = real_self_uid();
    let policy = allow_policy_for_uid(uid);
    let sink = Arc::new(CapturingSink::default());
    // max_depth = 0: the parent's own grant is depth 0, so any
    // descendant of it (depth 1) genuinely exceeds Depth — a real
    // scope-expansion attempt by a linked descendant.
    let handler = handler_with_delegation_and_step_up(
        policy,
        backend,
        temp_approval_store_path("step-up-delegation-genuine-scope-expansion"),
        bounds(0),
        step_up_policy(&[(
            RiskSignal::DelegationScopeExpanded,
            SignalDisposition::StepUp,
        )]),
        sink.clone(),
    );

    let parent = self_peer_context();
    handler.handle(
        &approve_request_for(&gpu0, ApprovalDisposition::Remember),
        &parent,
    );
    let response = handler.handle(&lease_request_for(&gpu0), &parent);
    assert!(matches!(response, AgentResponse::LeaseGranted { .. }));

    let requester = descendant_of(&parent, uid, 2);
    let response = handler.handle(&lease_request_for(&gpu0), &requester);

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::StepUpRequired
        }
    );
    match sink.last() {
        AuthorizationOutcome::StepUpRequired { signals } => {
            assert!(signals.contains(&RiskSignal::DelegationScopeExpanded));
        }
        other => panic!("expected StepUpRequired, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// AC1: normal declared dev chain has no repeated prompts in steady
// state — the risk layer is never consulted on an admission path.
// ---------------------------------------------------------------------

#[test]
fn steady_state_admission_never_consults_the_risk_layer() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let backend = backend_with_resource(&resource_identity(), &[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    // A maximally strict policy — if `assess` were ever reachable from
    // the admission path, this would turn an ordinary matched approval
    // into a denial.
    let all_deny: BTreeMap<RiskSignal, SignalDisposition> = RiskSignal::ALL
        .iter()
        .filter(|signal| **signal != RiskSignal::UntrustedExecutionPath)
        .map(|signal| (*signal, SignalDisposition::Deny))
        .collect();
    let handler = handler_with_step_up(
        allow_policy_for_uid(1000),
        backend,
        temp_approval_store_path("step-up-steady-state"),
        StepUpPolicy::new(all_deny, BTreeSet::new()).unwrap(),
        sink,
    );

    handler.handle(
        &approve_request(ApprovalDisposition::Remember),
        &peer.context(),
    );

    // Same exact workload, restarted — an ordinary Matched recall,
    // never a refusal.
    let restarted = TestPeer::fresh(peer.uid, peer.executable_hash);
    let response = handler.handle(&lease_request(), &restarted.context());

    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "a maximally strict step-up policy must never affect an admitted request, got {response:?}"
    );
}

// ---------------------------------------------------------------------
// Prompt-storm guardrail: eltanin approve --remember clears a step-up
// refusal without a second mechanism.
// ---------------------------------------------------------------------

#[test]
fn approve_remember_then_rerun_produces_no_second_step_up() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let backend = backend_with_resource(&resource_identity(), &[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    let handler = handler_with_step_up(
        allow_policy_for_uid(1000),
        backend,
        temp_approval_store_path("step-up-remember-clears"),
        step_up_policy(&[(
            RiskSignal::LauncherIdentityChanged,
            SignalDisposition::StepUp,
        )]),
        sink.clone(),
    );

    handler.handle(
        &approve_request(ApprovalDisposition::Remember),
        &peer.context(),
    );

    let mut replaced = peer.clone();
    replaced.executable_hash = "sha256:replaced-binary";
    let first = handler.handle(&lease_request(), &replaced.context());
    assert_eq!(
        first,
        AgentResponse::LeaseDenied {
            reason: DenialReason::StepUpRequired
        }
    );

    // The step-up act itself: re-approve with --remember for the new
    // (replaced) launcher identity.
    let approve_response = handler.handle(
        &approve_request(ApprovalDisposition::Remember),
        &replaced.context(),
    );
    assert!(matches!(
        approve_response,
        AgentResponse::ApprovalRecorded { .. }
    ));

    // Re-run: the binding now matches, recall returns Matched, the
    // approval gate admits — assess() is never called again for this
    // context.
    let second = handler.handle(&lease_request(), &replaced.context());
    assert!(
        matches!(second, AgentResponse::LeaseGranted { .. }),
        "expected LeaseGranted after remembering the new identity, got {second:?}"
    );
}

// ---------------------------------------------------------------------
// Non-negotiable: default config (no with_step_up) is byte-identical to
// pre-HORO-794 behavior.
// ---------------------------------------------------------------------

#[test]
fn default_config_without_step_up_is_byte_identical_to_pre_horo_794() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let backend = backend_with_resource(&resource_identity(), &[Capability::DeviceEnforce]);
    let sink = Arc::new(CapturingSink::default());
    let handler = handler_approvals_only(
        allow_policy_for_uid(1000),
        backend,
        temp_approval_store_path("step-up-default-config-regression"),
        sink.clone(),
    );

    handler.handle(
        &approve_request(ApprovalDisposition::Remember),
        &peer.context(),
    );

    // A digest change, a uid change to root, and a capability drift all
    // would trigger step-up/risk-denial if configured — with no
    // StepUpPolicy configured at all, every one of these must produce
    // exactly the same plain ApprovalRequired this crate produced
    // before HORO-794.
    let mut replaced = peer.clone();
    replaced.executable_hash = "sha256:replaced-binary";
    let response = handler.handle(&lease_request(), &replaced.context());
    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired
        }
    );
    assert!(matches!(
        sink.last(),
        AuthorizationOutcome::ApprovalRequired
    ));

    let root_peer = TestPeer::fresh(0, peer.executable_hash);
    let response = handler.handle(&lease_request(), &root_peer.context());
    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired
        }
    );
    assert!(matches!(
        sink.last(),
        AuthorizationOutcome::ApprovalRequired
    ));

    assert_eq!(
        AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .step_up(),
        None,
        "the default config must never carry a StepUpPolicy"
    );
}
