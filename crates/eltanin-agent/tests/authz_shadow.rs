//! Differential mode-equivalence coverage for shadow-enforcement mode
//! (F-M2-006, HORO-796 subtask 3): for the same request against the
//! same policy/backend/config, `EnforcementMode::Shadow` must reach
//! `PolicySet::evaluate` and every gate through the exact same call
//! chain as `EnforcementMode::Enforce`, must record the identical
//! `AuthorizationOutcome` to audit for every refusal (the differential-
//! equivalence property this file is named for), and must never call
//! `ComputeBackend::enforce`.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use eltanin_agent::authz::event::{AuthorizationEvent, AuthorizationOutcome, EventSink};
use eltanin_agent::authz::session::SessionRequirement;
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler, RevocationRequirement};
use eltanin_agent::handler::RequestHandler;
use eltanin_backend::fake::FakeBackend;
use eltanin_core::approval::ApprovalDisposition;
use eltanin_core::delegation::DelegationBounds;
use eltanin_core::identity::{Evidence, ExecutionContext};
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::peer::{PeerConsistency, PeerContext, PeerCredential};
use eltanin_core::policy::{
    Condition, Effect, EvidenceMatch, PolicyDocument, PolicyId, PolicySet, Rule, RuleId, TrustFloor,
};
use eltanin_core::resource::{Action, Capability};
use eltanin_core::risk::{RiskSignal, SignalDisposition, StepUpPolicy};
use eltanin_protocol::request::{ApproveRequest, ClientRequest, LeaseRequest};
use eltanin_protocol::response::{AgentResponse, EnforcementMode, ShadowVerdict};
use support::authz::{
    allow_policy_for_uid, backend_with_resource, deny_all_policy, resource_identity, FixedClock,
    TestPeer,
};
use support::temp_approval_store_path;

#[cfg(not(target_os = "macos"))]
use eltanin_linux as platform;
#[cfg(target_os = "macos")]
use eltanin_macos as platform;

// ---------------------------------------------------------------------
// Shared support
// ---------------------------------------------------------------------

/// Records every [`AuthorizationOutcome`] this handler produces, in
/// order — mirrors every other `authz_*.rs` suite's identical fixture.
#[derive(Default)]
struct CapturingSink {
    outcomes: Mutex<Vec<AuthorizationOutcome>>,
}

impl EventSink for CapturingSink {
    fn record(&self, event: &AuthorizationEvent<'_>) {
        self.outcomes.lock().unwrap().push(event.outcome.clone());
    }

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

fn step_up_policy(dispositions: &[(RiskSignal, SignalDisposition)]) -> StepUpPolicy {
    StepUpPolicy::new(
        dispositions.iter().copied().collect(),
        std::collections::BTreeSet::new(),
    )
    .unwrap()
}

/// A handler builder with everything but `enforcement_mode` fixed —
/// `build(mode)` produces one fresh handler/sink/backend triple per
/// call, so the "same policy/backend/config, different mode" comparison
/// never accidentally shares mutable state between the two runs.
type HandlerFactory =
    Box<dyn Fn(EnforcementMode) -> (AuthorizationHandler, Arc<CapturingSink>, Arc<FakeBackend>)>;

fn factory(
    policy: impl Fn() -> PolicySet + 'static,
    backend: impl Fn() -> Arc<FakeBackend> + 'static,
    config: impl Fn(EnforcementMode) -> AuthorizationConfig + 'static,
) -> HandlerFactory {
    Box::new(move |mode| {
        let sink = Arc::new(CapturingSink::default());
        let backend = backend();
        let handler = AuthorizationHandler::new(
            IssuerInstanceId::new("test-instance"),
            policy(),
            backend.clone(),
            FixedClock::new(),
            sink.clone(),
            &config(mode),
        );
        (handler, sink, backend)
    })
}

/// Run identical `setup` steps against both an `Enforce` and a `Shadow`
/// handler built from `make`, then the same final `request`, and return
/// each mode's captured `AuthorizationOutcome` and wire `AgentResponse`
/// for that final request.
struct DualOutcome {
    enforce_outcome: AuthorizationOutcome,
    enforce_response: AgentResponse,
    shadow_outcome: AuthorizationOutcome,
    shadow_response: AgentResponse,
    shadow_backend: Arc<FakeBackend>,
}

fn run_dual(
    make: &HandlerFactory,
    setup: impl Fn(&AuthorizationHandler),
    peer: &PeerContext,
    request: &ClientRequest,
) -> DualOutcome {
    let (enforce_handler, enforce_sink, _enforce_backend) = make(EnforcementMode::Enforce);
    setup(&enforce_handler);
    let enforce_response = enforce_handler.handle(request, peer);
    let enforce_outcome = enforce_sink.last();

    let (shadow_handler, shadow_sink, shadow_backend) = make(EnforcementMode::Shadow);
    setup(&shadow_handler);
    let shadow_response = shadow_handler.handle(request, peer);
    let shadow_outcome = shadow_sink.last();

    DualOutcome {
        enforce_outcome,
        enforce_response,
        shadow_outcome,
        shadow_response,
        shadow_backend,
    }
}

fn assert_outcomes_equal(dual: &DualOutcome, label: &str) {
    assert_eq!(
        dual.enforce_outcome, dual.shadow_outcome,
        "{label}: AuthorizationOutcome recorded to audit must be byte-identical between \
         Enforce and Shadow for the same input"
    );
    // Neither run granted anything — a refusal must never call
    // `ComputeBackend::enforce` in either mode (only a successful
    // `RequestLease` ever reaches that call at all).
    assert_eq!(
        dual.shadow_backend.enforce_call_count(&resource_identity()),
        0,
        "{label}: a refusal must never call ComputeBackend::enforce"
    );
    // The wire response genuinely diverges on a refusal: `Enforce` sends
    // a concrete `LeaseDenied`/`Error` variant, `Shadow` always projects
    // through `ShadowObserved` instead (or, for a non-decision internal
    // failure, keeps the identical `Error` — see `shadow_project_refusal`'s
    // own doc) — but the two are never the *same* `AgentResponse` value
    // for a decision-shaped refusal, which is exactly the "same audit,
    // different wire" property this suite exists to prove.
    if matches!(dual.shadow_response, AgentResponse::ShadowObserved { .. }) {
        assert_ne!(
            dual.enforce_response, dual.shadow_response,
            "{label}: a decision-shaped refusal must project to a different wire response in \
             Shadow mode, even though the audited outcome is identical"
        );
    }
}

// ---------------------------------------------------------------------
// Refusal buckets: AuthorizationOutcome equality + ShadowObserved shape
// ---------------------------------------------------------------------

#[test]
fn peer_not_authorizable_is_identical_across_modes() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let make = factory(
        || allow_policy_for_uid(1000),
        || backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        |mode| {
            AuthorizationConfig::new(Duration::from_secs(300))
                .unwrap()
                .with_enforcement_mode(mode)
        },
    );

    let dual = run_dual(
        &make,
        |_| {},
        &peer.inconsistent_context(),
        &lease_request(),
    );

    assert_outcomes_equal(&dual, "PeerNotAuthorizable");
    assert!(matches!(
        dual.enforce_outcome,
        AuthorizationOutcome::PeerNotAuthorizable
    ));
    assert_eq!(
        dual.shadow_response,
        AgentResponse::ShadowObserved {
            verdict: ShadowVerdict::WouldDeny
        }
    );
}

#[test]
fn session_required_is_identical_across_modes() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let make = factory(
        || allow_policy_for_uid(1000),
        || backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        |mode| {
            AuthorizationConfig::new(Duration::from_secs(300))
                .unwrap()
                .with_session_requirement(SessionRequirement::Required)
                .with_enforcement_mode(mode)
        },
    );

    let dual = run_dual(&make, |_| {}, &peer.context(), &lease_request());

    assert_outcomes_equal(&dual, "SessionRequired");
    assert!(matches!(
        dual.enforce_outcome,
        AuthorizationOutcome::SessionRequired { .. }
    ));
    assert_eq!(
        dual.shadow_response,
        AgentResponse::ShadowObserved {
            verdict: ShadowVerdict::WouldDeny
        }
    );
}

#[test]
fn approval_required_is_identical_across_modes() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let make = factory(
        || allow_policy_for_uid(1000),
        || backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        |mode| {
            AuthorizationConfig::new(Duration::from_secs(300))
                .unwrap()
                .with_approval_store(temp_approval_store_path("shadow-approval-required"))
                .with_enforcement_mode(mode)
        },
    );

    let dual = run_dual(&make, |_| {}, &peer.context(), &lease_request());

    assert_outcomes_equal(&dual, "ApprovalRequired");
    assert!(matches!(
        dual.enforce_outcome,
        AuthorizationOutcome::ApprovalRequired
    ));
    assert_eq!(
        dual.shadow_response,
        AgentResponse::ShadowObserved {
            verdict: ShadowVerdict::WouldDeny
        }
    );
}

#[test]
fn approval_denied_is_identical_across_modes() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let make = factory(
        || allow_policy_for_uid(1000),
        || backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        |mode| {
            AuthorizationConfig::new(Duration::from_secs(300))
                .unwrap()
                .with_approval_store(temp_approval_store_path("shadow-approval-denied"))
                .with_enforcement_mode(mode)
        },
    );

    let dual = run_dual(
        &make,
        |handler| {
            let response =
                handler.handle(&approve_request(ApprovalDisposition::Deny), &peer.context());
            assert!(matches!(response, AgentResponse::ApprovalRecorded { .. }));
        },
        &peer.context(),
        &lease_request(),
    );

    assert_outcomes_equal(&dual, "ApprovalDenied");
    assert!(matches!(
        dual.enforce_outcome,
        AuthorizationOutcome::ApprovalDenied
    ));
    assert_eq!(
        dual.shadow_response,
        AgentResponse::ShadowObserved {
            verdict: ShadowVerdict::WouldDeny
        }
    );
}

#[test]
fn step_up_required_is_identical_across_modes() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let make = factory(
        || allow_policy_for_uid(1000),
        || backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        |mode| {
            AuthorizationConfig::new(Duration::from_secs(300))
                .unwrap()
                .with_step_up(
                    temp_approval_store_path("shadow-step-up"),
                    step_up_policy(&[(
                        RiskSignal::LauncherIdentityChanged,
                        SignalDisposition::StepUp,
                    )]),
                )
                .with_enforcement_mode(mode)
        },
    );

    let dual = run_dual(
        &make,
        |handler| {
            let response = handler.handle(
                &approve_request(ApprovalDisposition::Remember),
                &peer.context(),
            );
            assert!(matches!(response, AgentResponse::ApprovalRecorded { .. }));
        },
        &{
            let mut replaced = peer.clone();
            replaced.executable_hash = "sha256:replaced-binary";
            replaced.context()
        },
        &lease_request(),
    );

    assert_outcomes_equal(&dual, "StepUpRequired");
    assert!(matches!(
        dual.enforce_outcome,
        AuthorizationOutcome::StepUpRequired { .. }
    ));
    assert_eq!(
        dual.shadow_response,
        AgentResponse::ShadowObserved {
            verdict: ShadowVerdict::WouldStepUp
        }
    );
}

#[test]
fn risk_denied_is_identical_across_modes() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let make = factory(
        || allow_policy_for_uid(1000),
        || backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        |mode| {
            AuthorizationConfig::new(Duration::from_secs(300))
                .unwrap()
                .with_step_up(
                    temp_approval_store_path("shadow-risk-denied"),
                    step_up_policy(&[
                        (RiskSignal::PrivilegeTransition, SignalDisposition::StepUp),
                        (
                            RiskSignal::PrivilegeEscalationToRoot,
                            SignalDisposition::Deny,
                        ),
                    ]),
                )
                .with_enforcement_mode(mode)
        },
    );

    let root_peer = TestPeer::fresh(0, peer.executable_hash);

    let dual = run_dual(
        &make,
        |handler| {
            let response = handler.handle(
                &approve_request(ApprovalDisposition::Remember),
                &peer.context(),
            );
            assert!(matches!(response, AgentResponse::ApprovalRecorded { .. }));
        },
        &root_peer.context(),
        &lease_request(),
    );

    assert_outcomes_equal(&dual, "RiskDenied");
    assert!(matches!(
        dual.enforce_outcome,
        AuthorizationOutcome::RiskDenied { .. }
    ));
    assert_eq!(
        dual.shadow_response,
        AgentResponse::ShadowObserved {
            verdict: ShadowVerdict::WouldDeny
        }
    );
}

#[test]
fn policy_denied_explicit_deny_is_identical_across_modes() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let make = factory(
        || deny_uid_policy(1000),
        || backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        |mode| {
            AuthorizationConfig::new(Duration::from_secs(300))
                .unwrap()
                .with_enforcement_mode(mode)
        },
    );

    let dual = run_dual(&make, |_| {}, &peer.context(), &lease_request());

    assert_outcomes_equal(&dual, "PolicyDenied(explicit)");
    match &dual.enforce_outcome {
        AuthorizationOutcome::PolicyDenied { decision } => {
            assert_eq!(decision.effect(), Effect::Deny);
        }
        other => panic!("expected PolicyDenied, got {other:?}"),
    }
    assert_eq!(
        dual.shadow_response,
        AgentResponse::ShadowObserved {
            verdict: ShadowVerdict::WouldDeny
        }
    );
}

#[test]
fn policy_denied_no_matching_rule_is_identical_across_modes() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let make = factory(
        deny_all_policy,
        || backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        |mode| {
            AuthorizationConfig::new(Duration::from_secs(300))
                .unwrap()
                .with_enforcement_mode(mode)
        },
    );

    let dual = run_dual(&make, |_| {}, &peer.context(), &lease_request());

    assert_outcomes_equal(&dual, "PolicyDenied(no matching rule)");
    assert!(matches!(
        dual.enforce_outcome,
        AuthorizationOutcome::PolicyDenied { .. }
    ));
    assert_eq!(
        dual.shadow_response,
        AgentResponse::ShadowObserved {
            verdict: ShadowVerdict::WouldDeny
        }
    );
}

#[test]
fn enforcement_refused_revocation_capability_gate_is_identical_across_modes() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let make = factory(
        || allow_policy_for_uid(1000),
        // No `Capability::DeviceRevoke` — the revocation-capability gate
        // must refuse before capacity is ever reserved.
        || backend_with_resource(&[Capability::DeviceEnforce]),
        |mode| {
            AuthorizationConfig::new(Duration::from_secs(300))
                .unwrap()
                .with_revocation_requirement(RevocationRequirement::Required)
                .with_enforcement_mode(mode)
        },
    );

    let dual = run_dual(&make, |_| {}, &peer.context(), &lease_request());

    assert_outcomes_equal(&dual, "EnforcementRefused{Unsupported{DeviceRevoke}}");
    assert!(matches!(
        dual.enforce_outcome,
        AuthorizationOutcome::EnforcementRefused { .. }
    ));
    assert_eq!(
        dual.shadow_response,
        AgentResponse::ShadowObserved {
            verdict: ShadowVerdict::WouldDeny
        }
    );
}

// ---------------------------------------------------------------------
// Delegation bucket. A fresh handler's `DelegationState` holds zero
// grants, so `delegation_admission` never enters its candidate loop at
// all — this reaches `AuthorizationOutcome::DelegationRefused{exceeded:
// {}}` with no need to first establish a real chain (which would itself
// require a real, observable holder process — see `authz_delegation.rs`'s
// own module docs on why — and, more fundamentally, could never be
// established on the *shadow* handler being compared here: shadow mode
// never mints a `DelegationGrant`, since minting is
// `enforce_and_finalize`'s own real-grant side effect, conditioned on a
// real `backend.enforce()` success it never reaches — see
// `AuthorizationHandler::shadow_would_grant`'s own doc. `DelegationIndeterminate`
// is reachable only via a candidate already in the loop, i.e. only after
// a real chain exists, so it is not covered by this differential suite
// for that same structural reason — noted honestly rather than
// papered over with a same-mode setup that would silently test something
// other than what its name claims).
// ---------------------------------------------------------------------

#[test]
fn delegation_refused_is_identical_across_modes() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let make = factory(
        || allow_policy_for_uid(1000),
        || backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        |mode| {
            AuthorizationConfig::new(Duration::from_secs(300))
                .unwrap()
                .with_delegation(
                    temp_approval_store_path("shadow-delegation-refused"),
                    DelegationBounds::new(
                        1,
                        Duration::from_secs(300),
                        Duration::from_secs(1),
                        [Action::Compute],
                        std::collections::BTreeSet::new(),
                        false,
                        false,
                    )
                    .unwrap(),
                )
                .with_enforcement_mode(mode)
        },
    );

    let dual = run_dual(&make, |_| {}, &peer.context(), &lease_request());

    assert_outcomes_equal(&dual, "DelegationRefused");
    match &dual.enforce_outcome {
        AuthorizationOutcome::DelegationRefused { exceeded } => {
            assert!(
                exceeded.is_empty(),
                "a fresh handler has no delegation candidates to exceed any bound of: \
                 {exceeded:?}"
            );
        }
        other => panic!("expected DelegationRefused, got {other:?}"),
    }
    assert_eq!(
        dual.shadow_response,
        AgentResponse::ShadowObserved {
            verdict: ShadowVerdict::WouldDeny
        }
    );
}

// ---------------------------------------------------------------------
// The successful-admission case: Granted vs WouldGrant, zero backend
// enforce() calls, and capacity is not permanently consumed.
// ---------------------------------------------------------------------

#[test]
fn successful_admission_produces_would_grant_with_zero_backend_enforce_calls() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    // Enforce mode: an ordinary grant, for the outcome-shape contrast.
    let enforce_sink = Arc::new(CapturingSink::default());
    let enforce_backend =
        backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]);
    let enforce_handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        enforce_backend.clone(),
        FixedClock::new(),
        enforce_sink.clone(),
        &AuthorizationConfig::new(Duration::from_secs(300)).unwrap(),
    );
    let enforce_response = enforce_handler.handle(&lease_request(), &peer.context());
    assert!(matches!(
        enforce_response,
        AgentResponse::LeaseGranted { .. }
    ));
    assert!(matches!(
        enforce_sink.last(),
        AuthorizationOutcome::Granted { .. }
    ));
    assert_eq!(enforce_backend.enforce_call_count(&resource_identity()), 1);

    // Shadow mode: same policy/backend shape, a fresh handler. Capacity
    // is capped at 1 so a leaked reservation from the first shadow call
    // would make the second one fail with `CapacityExhausted` instead of
    // also succeeding — the only externally-observable proxy for "the
    // lease store is left empty" this crate's public surface allows
    // (`LeaseState` itself is private to `crate::authz`).
    let shadow_sink = Arc::new(CapturingSink::default());
    let shadow_backend =
        backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]);
    let shadow_handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        shadow_backend.clone(),
        FixedClock::new(),
        shadow_sink.clone(),
        &AuthorizationConfig::new(Duration::from_secs(300))
            .unwrap()
            .with_max_outstanding_leases(1)
            .with_enforcement_mode(EnforcementMode::Shadow),
    );

    let first = shadow_handler.handle(&lease_request(), &peer.context());
    assert_eq!(
        first,
        AgentResponse::ShadowObserved {
            verdict: ShadowVerdict::WouldAllow
        }
    );
    match shadow_sink.last() {
        AuthorizationOutcome::WouldGrant { .. } => {}
        other => panic!("expected WouldGrant, got {other:?}"),
    }

    let second = shadow_handler.handle(&lease_request(), &peer.context());
    assert_eq!(
        second,
        AgentResponse::ShadowObserved {
            verdict: ShadowVerdict::WouldAllow
        },
        "a leaked capacity reservation from the first shadow call would make this \
         CapacityExhausted instead"
    );

    assert_eq!(
        shadow_backend.enforce_call_count(&resource_identity()),
        0,
        "shadow mode must never call ComputeBackend::enforce"
    );
    assert_eq!(
        shadow_backend.revoke_call_count(&resource_identity()),
        0,
        "shadow mode must never call ComputeBackend::revoke either — it never touches the \
         backend at all"
    );
}

// ---------------------------------------------------------------------
// Scope boundary: shadow mode applies only to `RequestLease`.
// `CreateSession`/`Approve`/`ReleaseLease` behave identically in both
// modes.
// ---------------------------------------------------------------------

#[test]
fn approve_behaves_identically_regardless_of_enforcement_mode() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let make = factory(
        || allow_policy_for_uid(1000),
        || backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        |mode| {
            AuthorizationConfig::new(Duration::from_secs(300))
                .unwrap()
                .with_approval_store(temp_approval_store_path("shadow-scope-approve"))
                .with_enforcement_mode(mode)
        },
    );

    let (enforce_handler, _enforce_sink, _b1) = make(EnforcementMode::Enforce);
    let enforce_response = enforce_handler.handle(
        &approve_request(ApprovalDisposition::Remember),
        &peer.context(),
    );

    let (shadow_handler, _shadow_sink, _b2) = make(EnforcementMode::Shadow);
    let shadow_response = shadow_handler.handle(
        &approve_request(ApprovalDisposition::Remember),
        &peer.context(),
    );

    assert_eq!(
        enforce_response, shadow_response,
        "Approve must behave identically regardless of enforcement_mode — it is an input to a \
         decision, not a decision itself"
    );
}

/// `CreateSession` binds its anchor to a real, kernel-observed session
/// key (`session_establish_inputs` re-collects it straight through the
/// real platform collector) — mirrors `authz_session.rs`'s own module
/// docs on why a synthetic `TestPeer` pid cannot honestly exercise this
/// path; this test binary's own real pid is used instead.
fn self_peer_context() -> PeerContext {
    let pid = std::process::id();
    let workload = platform::collect_workload_identity(pid);
    let uid = match workload.uid {
        Evidence::Present { value, .. } => value,
        other => {
            panic!("expected this test process's own uid to be kernel-observed, got {other:?}")
        }
    };
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

#[test]
fn create_session_and_release_lease_behave_identically_regardless_of_enforcement_mode() {
    let peer = self_peer_context();
    let make = factory(
        move || allow_policy_for_uid(1000),
        || backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
        |mode| {
            AuthorizationConfig::new(Duration::from_secs(300))
                .unwrap()
                .with_enforcement_mode(mode)
        },
    );

    let create_session =
        ClientRequest::CreateSession(eltanin_protocol::request::CreateSessionRequest {
            resources: vec![resource_identity()],
            ttl: Duration::from_secs(60),
        });

    let (enforce_handler, _enforce_sink, _b1) = make(EnforcementMode::Enforce);
    let enforce_create = enforce_handler.handle(&create_session, &peer);
    assert!(matches!(
        enforce_create,
        AgentResponse::SessionEstablished { .. }
    ));

    let (shadow_handler, _shadow_sink, _b2) = make(EnforcementMode::Shadow);
    let shadow_create = shadow_handler.handle(&create_session, &peer);
    assert!(matches!(
        shadow_create,
        AgentResponse::SessionEstablished { .. }
    ));

    // A `ReleaseLease` against an unknown id refuses identically in both
    // modes too — `handle_release_lease` has no `enforcement_mode`
    // branch at all.
    let release = ClientRequest::ReleaseLease(eltanin_protocol::request::ReleaseRequest {
        lease_id: eltanin_core::lease::LeaseId {
            issuer: IssuerInstanceId::new("test-instance"),
            sequence: 9999,
        },
    });
    let enforce_release = enforce_handler.handle(&release, &peer);
    let shadow_release = shadow_handler.handle(&release, &peer);
    assert_eq!(enforce_release, shadow_release);
}

// ---------------------------------------------------------------------
// `eltanin_status` reports the configured enforcement mode.
// ---------------------------------------------------------------------

#[test]
fn agent_status_reports_the_configured_enforcement_mode() {
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    let peer = TestPeer::fresh(1000, "sha256:trusted");

    let default_handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        backend.clone(),
        FixedClock::new(),
        Arc::new(CapturingSink::default()),
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    );
    let status = default_handler.handle(&ClientRequest::AgentStatus {}, &peer.context());
    match status {
        AgentResponse::Status { status } => {
            assert_eq!(status.enforcement_mode, EnforcementMode::Enforce);
        }
        other => panic!("expected Status, got {other:?}"),
    }

    let shadow_handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        backend,
        FixedClock::new(),
        Arc::new(CapturingSink::default()),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_enforcement_mode(EnforcementMode::Shadow),
    );
    let status = shadow_handler.handle(&ClientRequest::AgentStatus {}, &peer.context());
    match status {
        AgentResponse::Status { status } => {
            assert_eq!(status.enforcement_mode, EnforcementMode::Shadow);
        }
        other => panic!("expected Status, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Non-negotiable regression: default config (no `with_enforcement_mode`
// call) behaves byte-identically to pre-subtask-3 — every existing
// `authz_*.rs` test file continues to pass unchanged (verified by
// `cargo test --workspace`, not restated here).
// ---------------------------------------------------------------------

#[test]
fn default_config_has_enforce_mode() {
    let config = AuthorizationConfig::new(Duration::from_secs(60)).unwrap();
    assert_eq!(config.enforcement_mode(), EnforcementMode::Enforce);
}
