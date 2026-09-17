//! Remembered-authorization admission gate coverage (F-M2-002,
//! HORO-792). Exercises every acceptance criterion through the same
//! public `RequestHandler` interface a real client uses — never by
//! reaching into `authz::approval_state` directly, which is
//! intentionally private.

mod support;

use std::sync::Arc;
use std::time::Duration;

use eltanin_agent::authz::approval::ApprovalRequirement;
use eltanin_agent::authz::event::NullSink;
use eltanin_agent::authz::session::SessionRequirement;
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler};
use eltanin_agent::handler::RequestHandler;
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::resource::{Action, Capability};
use eltanin_protocol::request::{
    ApproveRequest, ClientRequest, ForgetApprovalRequest, LeaseRequest,
};
use eltanin_protocol::response::{AgentResponse, DenialReason};
use support::authz::{
    allow_policy_for_uid, backend_with_resource, resource_identity, FixedClock, TestPeer,
};
use support::temp_approval_store_path;

fn handler_not_required(
    policy: eltanin_core::policy::PolicySet,
    backend: Arc<eltanin_backend::fake::FakeBackend>,
) -> AuthorizationHandler {
    AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        policy,
        backend,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60)).unwrap(),
    )
}

fn handler_required(
    policy: eltanin_core::policy::PolicySet,
    backend: Arc<eltanin_backend::fake::FakeBackend>,
    store_path: std::path::PathBuf,
) -> AuthorizationHandler {
    AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        policy,
        backend,
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_approval_store(store_path),
    )
}

fn lease_request() -> ClientRequest {
    ClientRequest::RequestLease(LeaseRequest {
        resource: resource_identity(),
        action: Action::Compute,
    })
}

fn approve_request(disposition: eltanin_core::approval::ApprovalDisposition) -> ClientRequest {
    ClientRequest::Approve(ApproveRequest {
        resource: resource_identity(),
        action: Action::Compute,
        disposition,
    })
}

/// Default `AuthorizationConfig` never sets `ApprovalRequirement`, and
/// its default is `NotRequired` — this proves that default is a
/// complete no-op, byte-identical to pre-HORO-792 behavior: an
/// otherwise-authorized request is granted with zero approvals ever
/// recorded, and the config's own getters confirm no store path was
/// ever configured (so `AuthorizationHandler::new` never touched the
/// filesystem for this feature at all).
#[test]
fn default_config_has_approval_not_required_and_no_store_path() {
    let config = AuthorizationConfig::new(Duration::from_secs(60)).unwrap();
    assert_eq!(
        config.approval_requirement(),
        ApprovalRequirement::NotRequired
    );
    assert_eq!(config.approval_store_path(), None);
}

#[test]
fn not_required_grants_an_authorized_request_with_zero_approvals_ever_recorded() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let handler = handler_not_required(
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce, Capability::DeviceRevoke]),
    );

    let response = handler.handle(&lease_request(), &peer.context());

    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "expected LeaseGranted (approval gate must be a no-op when NotRequired), got {response:?}"
    );
}

#[test]
fn required_with_no_recorded_approval_denies_with_approval_required() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let handler = handler_required(
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
        temp_approval_store_path("no-approval"),
    );

    let response = handler.handle(&lease_request(), &peer.context());

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired
        }
    );
}

#[test]
fn remember_admits_a_restarted_workload_without_reprompting() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let backend = backend_with_resource(&[Capability::DeviceEnforce]);
    let handler = handler_required(
        allow_policy_for_uid(1000),
        Arc::clone(&backend),
        temp_approval_store_path("remember"),
    );

    let approve_response = handler.handle(
        &approve_request(eltanin_core::approval::ApprovalDisposition::Remember),
        &peer.context(),
    );
    assert!(
        matches!(approve_response, AgentResponse::ApprovalRecorded { .. }),
        "expected ApprovalRecorded, got {approve_response:?}"
    );

    // AC1: a "restarted" instance of the exact same workload (same
    // uid/path/digest) obtains a fresh lease without prompting again —
    // no second `eltanin approve` call.
    let restarted = TestPeer::fresh(peer.uid, peer.executable_hash);
    let response = handler.handle(&lease_request(), &restarted.context());
    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "expected LeaseGranted for the restarted workload, got {response:?}"
    );
}

#[test]
fn once_is_consumed_after_a_single_successful_use() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let handler = handler_required(
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
        temp_approval_store_path("once"),
    );

    handler.handle(
        &approve_request(eltanin_core::approval::ApprovalDisposition::Once),
        &peer.context(),
    );

    let first = handler.handle(&lease_request(), &peer.context());
    assert!(
        matches!(first, AgentResponse::LeaseGranted { .. }),
        "expected the Once approval to admit the first request, got {first:?}"
    );

    let second = handler.handle(&lease_request(), &peer.context());
    assert_eq!(
        second,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired
        },
        "a consumed Once approval must not admit a second request"
    );
}

/// AC2: copied/stolen old approval material cannot authorize a new,
/// unrelated workload — a different uid produces a different
/// `ApprovalBinding`, so `recall` reports `NotMatched`/`Indeterminate`
/// and the gate refuses, never `Matched`.
#[test]
fn a_different_workload_cannot_reuse_another_workloads_approval() {
    let owner = TestPeer::fresh(1000, "sha256:trusted");
    let handler = handler_required(
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
        temp_approval_store_path("stolen"),
    );
    handler.handle(
        &approve_request(eltanin_core::approval::ApprovalDisposition::Remember),
        &owner.context(),
    );

    let unrelated = TestPeer::fresh(1000, "sha256:different-binary");
    let response = handler.handle(&lease_request(), &unrelated.context());

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired
        },
        "a different executable's identity must not admit under someone else's approval"
    );
}

/// AC3: a material identity/context change (here: the executable digest
/// changed — a same-path binary replacement) causes re-evaluation and
/// denial, never a silent re-admission.
#[test]
fn a_changed_executable_digest_is_reevaluated_and_denied() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let handler = handler_required(
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
        temp_approval_store_path("digest-change"),
    );
    handler.handle(
        &approve_request(eltanin_core::approval::ApprovalDisposition::Remember),
        &peer.context(),
    );

    let mut replaced = peer.clone();
    replaced.executable_hash = "sha256:replaced-binary";
    let response = handler.handle(&lease_request(), &replaced.context());

    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired
        }
    );
}

/// AC5 (part 1): deny-overrides — a `Deny` approval wins even when a
/// `Remember` approval for the same launcher also exists.
#[test]
fn deny_overrides_a_remember_for_the_same_launcher() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let handler = handler_required(
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
        temp_approval_store_path("deny-overrides"),
    );
    handler.handle(
        &approve_request(eltanin_core::approval::ApprovalDisposition::Remember),
        &peer.context(),
    );
    handler.handle(
        &approve_request(eltanin_core::approval::ApprovalDisposition::Deny),
        &peer.context(),
    );

    let response = handler.handle(&lease_request(), &peer.context());
    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalDenied
        }
    );
}

/// AC5 (part 2): cached-policy behavior is deterministic — recording
/// and listing an approval is idempotent from the calling peer's own
/// point of view, and `forget` removes it durably (a subsequent
/// `RequestLease` from the exact same launcher is refused again).
#[test]
fn forget_removes_a_durable_approval() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let handler = handler_required(
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
        temp_approval_store_path("forget"),
    );
    let recorded = handler.handle(
        &approve_request(eltanin_core::approval::ApprovalDisposition::Remember),
        &peer.context(),
    );
    let AgentResponse::ApprovalRecorded { approval } = recorded else {
        panic!("expected ApprovalRecorded, got {recorded:?}");
    };

    assert!(matches!(
        handler.handle(&lease_request(), &peer.context()),
        AgentResponse::LeaseGranted { .. }
    ));

    let forgotten = handler.handle(
        &ClientRequest::ForgetApproval(ForgetApprovalRequest { id: approval.id }),
        &peer.context(),
    );
    assert_eq!(
        forgotten,
        AgentResponse::ApprovalForgotten {
            outcome: eltanin_protocol::response::ForgetOutcome::Forgotten
        }
    );

    let response = handler.handle(&lease_request(), &peer.context());
    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::ApprovalRequired
        }
    );
}

/// `ListApprovals` returns only the calling peer's own approvals, never
/// another owner's.
#[test]
fn list_approvals_returns_only_the_calling_peers_own() {
    let owner_a = TestPeer::fresh(1000, "sha256:a");
    let owner_b = TestPeer::fresh(2000, "sha256:b");
    let handler = handler_required(
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
        temp_approval_store_path("list-isolation"),
    );
    handler.handle(
        &approve_request(eltanin_core::approval::ApprovalDisposition::Remember),
        &owner_a.context(),
    );
    handler.handle(
        &approve_request(eltanin_core::approval::ApprovalDisposition::Remember),
        &owner_b.context(),
    );

    let AgentResponse::ApprovalList { approvals } =
        handler.handle(&ClientRequest::ListApprovals {}, &owner_a.context())
    else {
        panic!("expected ApprovalList");
    };
    assert_eq!(approvals.len(), 1);
}

/// S5 (HORO-797 adversarial matrix) — `PINS_LIMITATION`, no prior
/// coverage: approving an interpreter launcher once and later invoking
/// that same launcher with a different script/argument is admitted
/// silently, with no re-prompt, because the argument is never part of
/// what is checked or even observable.
///
/// ADR 0010's AC4 section states three independently sufficient
/// structural reasons this cannot be fixed at this layer — each
/// re-verified against current source for this test:
/// 1. `crates/eltanin-cli/src/sequence.rs` fixes stage S4 (`RequestLease`)
///    strictly before stage S6 (`SpawnWorkload`) — there is no stage
///    where an interpreter's argv could be observed before the lease
///    decision is made.
/// 2. `eltanin-protocol`'s wire types carry no client-declared-identity
///    field anywhere (`crates/eltanin-protocol/src/request.rs`'s own
///    module docs: "no producer of `Evidence`/`WorkloadIdentity`/
///    `ExecutionContext`") — a client cannot declare "I am running
///    script X" even if it wanted to.
/// 3. `crates/eltanin-audit/tests/redaction.rs` mechanically forbids any
///    collector from ever reading `/proc/<pid>/cmdline` — the one
///    kernel source that could in principle reveal an interpreter's
///    argv.
///
/// This test demonstrates the consequence directly: `TestPeer` (this
/// suite's `PeerContext`/`WorkloadIdentity` builder, mirroring what the
/// real platform collectors produce) has no argv/script field to vary at
/// all — two "different invocations" of the same interpreter are, by
/// construction, indistinguishable identities. `eltanin approve` binds
/// only to the launcher (uid/path/digest/cgroup), never to the
/// argument, so the second invocation is admitted with zero new
/// `eltanin approve` calls.
#[test]
fn s5_approving_an_interpreter_admits_a_later_invocation_with_a_different_script() {
    // Stands in for `python script_a.py`: this launcher's identity is
    // uid + path + digest only, per `ApprovalBinding` — there is no
    // script argument dimension for `TestPeer`/`WorkloadIdentity` to
    // even carry.
    let interpreter_invocation_a = TestPeer::fresh(1000, "sha256:python-3.11-trusted");
    let handler = handler_required(
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
        temp_approval_store_path("interpreter-reuse"),
    );

    let approve_response = handler.handle(
        &approve_request(eltanin_core::approval::ApprovalDisposition::Remember),
        &interpreter_invocation_a.context(),
    );
    assert!(
        matches!(approve_response, AgentResponse::ApprovalRecorded { .. }),
        "expected ApprovalRecorded, got {approve_response:?}"
    );

    // Stands in for a *later*, different `python script_b.py` through
    // the exact same interpreter binary — same uid/path/digest, which is
    // the only identity this mechanism can ever observe.
    let interpreter_invocation_b = TestPeer::fresh(
        interpreter_invocation_a.uid,
        interpreter_invocation_a.executable_hash,
    );
    let response = handler.handle(&lease_request(), &interpreter_invocation_b.context());

    assert!(
        matches!(response, AgentResponse::LeaseGranted { .. }),
        "a different script run through an already-approved interpreter must be admitted \
         with no re-prompt — the script/argv dimension is structurally invisible to this \
         mechanism (ADR 0010 AC4 section), got {response:?}"
    );
}

/// A remembered approval and a Trusted Compute Session (HORO-791) are
/// independent, conjunctive gates: both must pass. A recorded approval
/// alone does not satisfy a `SessionRequirement::Required` deployment.
#[test]
fn approval_and_session_requirements_are_independent_both_must_pass() {
    let peer = TestPeer::fresh(1000, "sha256:trusted");
    let handler = AuthorizationHandler::new(
        IssuerInstanceId::new("test-instance"),
        allow_policy_for_uid(1000),
        backend_with_resource(&[Capability::DeviceEnforce]),
        FixedClock::new(),
        Arc::new(NullSink),
        &AuthorizationConfig::new(Duration::from_secs(60))
            .unwrap()
            .with_approval_store(temp_approval_store_path("both-gates"))
            .with_session_requirement(SessionRequirement::Required),
    );

    handler.handle(
        &approve_request(eltanin_core::approval::ApprovalDisposition::Remember),
        &peer.context(),
    );

    // No Trusted Compute Session established — the approval alone must
    // not be sufficient.
    let response = handler.handle(&lease_request(), &peer.context());
    assert_eq!(
        response,
        AgentResponse::LeaseDenied {
            reason: DenialReason::NoTrustedSession
        }
    );
}
