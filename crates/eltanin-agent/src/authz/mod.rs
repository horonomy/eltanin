//! Policy evaluation, lease issue/release, and backend coordination
//! (F-M1-006, HORO-840).
//!
//! [`AuthorizationHandler`] implements [`crate::handler::RequestHandler`]
//! by wiring `eltanin-core`'s policy (F-M1-004) and lease (F-M1-005)
//! contracts to an `eltanin-backend::ComputeBackend` (F-M1-001). This is
//! the one module in this crate permitted to name `PolicySet`,
//! `LeaseIssuer`, `ComputeLease`, or call `.evaluate(`/`.issue(`/
//! `.revoke(` — see `tests/agent_architecture_guard.rs`. It never
//! touches a socket or a wire frame directly.
//!
//! # Request path: issue, then enforce
//!
//! `RequestLease` issues a lease (re-evaluating policy over the exact
//! [`eltanin_core::provenance::ProvenanceRecord`] the lease is bound to,
//! per `LeaseIssuer::issue`'s own contract) *before* calling
//! `ComputeBackend::enforce` — `enforce`'s own docs are explicit that it
//! "does not decide authorization... that decision has already been
//! made by the time this is called." If `enforce` does not report
//! `EnforcementResult::Allowed`, the just-issued lease is compensated
//! with `LeaseIssuer::revoke` and never inserted into the store — a
//! lease is only ever visible to a later `ReleaseLease` call once a real
//! backend has confirmed it can act on it.
//!
//! # Wire mapping rule
//!
//! Once policy is actually consulted, `LeaseDenied` if and only if
//! `PolicySet::evaluate` itself produced `Effect::Deny` — every other
//! *post-policy* non-grant condition (backend failure, enforcement
//! refusal, capacity exhaustion, a structurally-unreachable lease error)
//! maps to `Error { Internal }`, continuing `handler.rs`'s
//! `StatusOnlyHandler` reasoning that "no policy backend decided this"
//! must never be reported as if policy had denied it. The one exception,
//! *before* policy is ever consulted: a non-`authorizable()` peer is
//! reported as `LeaseDenied { IndeterminateEvidence }` per
//! [`crate::handler::RequestHandler`]'s own established contract
//! (HORO-839) — this predates policy evaluation entirely and is not
//! itself a policy decision, but shares that wire shape because
//! "evidence about the requester couldn't be confirmed" is the same
//! client-facing fact in both cases.
//!
//! # `ReleaseLease` discharges the `SECURITY_MODEL` named obligation
//!
//! `LeaseIssuer::validate` performs exactly the mandated
//! `compare_process` + `compare_executable` pair (both required `Same`)
//! plus issuer/revocation/resource/action/expiry checks, in an order
//! already merged and QA-verified in `eltanin-core`. Anything but
//! `LeaseValidity::Valid` is reported to the client as
//! `ReleaseOutcome::Refused` — identically, regardless of *which*
//! non-`Valid` case occurred, so a client can never use the wire
//! response to enumerate whether a lease id exists, belongs to another
//! client, or has already expired.
//!
//! # Clock discipline
//!
//! Every `now` reading that feeds `issue`/`validate`/`prune` is taken
//! from [`Clock`] after the lock is already held, never before — this is
//! how `eltanin_core::lease`'s named obligation ("monotonicity across
//! successive `issue` calls is F-M1-006's obligation as sole owner of
//! the clock") is discharged: two concurrent `RequestLease` calls cannot
//! observe `now` out of order relative to the sequence their `issue`
//! calls actually execute in, because both the clock read and the
//! `issue` call happen under the same [`std::sync::Mutex`]. A display-
//! only `now` reading computed for the client-facing `remaining:
//! Duration` after a successful `enforce()` call is *not* under the
//! lock — it feeds nothing `eltanin_core::lease` requires monotonicity
//! for, only the value shown to the client, so this exception does not
//! weaken the guarantee above.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eltanin_backend::contract::{BackendError, ComputeBackend};
use eltanin_core::approval::{recall, Approval, ApprovalDisposition, ApprovalId, RecallVerdict};
use eltanin_core::envelope::Versioned;
use eltanin_core::identity::{Evidence, EvidenceSource};
use eltanin_core::lease::{
    IssuerInstanceId, LeaseError, LeaseId, LeaseIssuer, LeaseValidity, MonotonicTime,
};
use eltanin_core::peer::PeerContext;
use eltanin_core::policy::{DecisionReason, PolicyDocument, PolicyError, PolicySet};
use eltanin_core::provenance::ProvenanceRecord;
use eltanin_core::resource::{Capability, ComputeRequest, EnforcementResult};
use eltanin_core::session::{
    membership, IntentProof, LocalSessionAnchor, MembershipVerdict, SessionAssurance,
    SessionAuthority, SessionId, SessionScope,
};
use eltanin_protocol::request::{
    provenance_for, ApproveRequest, ClientRequest, CreateSessionRequest, ForgetApprovalRequest,
    LeaseRequest, ReleaseRequest,
};
use eltanin_protocol::response::{
    AgentResponse, AgentStatusView, ApprovalView, DenialReason, EnforcementMode, ErrorCode,
    ForgetOutcome, LeaseView, ReleaseOutcome, SessionView, ShadowVerdict, TerminationOutcome,
};

use crate::handler::RequestHandler;
use crate::runtime::AgentClock;

pub mod approval;
mod approval_state;
pub mod audit;
mod delegation;
mod delegation_state;
pub mod event;
mod risk;
pub mod session;
mod session_state;
mod state;

use approval::ApprovalRequirement;
use approval_state::ApprovalState;
use delegation_state::DelegationState;
use event::{AuthorizationEvent, AuthorizationOutcome, EventSink, Operation};
use session::{SessionAdmissionError, SessionRequirement};
use session_state::SessionState;
use state::LeaseState;

/// A source of [`MonotonicTime`] readings. Exists so tests can advance
/// time deterministically and so the monotonicity obligation
/// `eltanin_core::lease`'s own docs assign to "whichever crate actually
/// owns a clock" has exactly one owner in this crate:
/// [`AuthorizationHandler`] reads `now` from this trait, never from
/// [`std::time::Instant::now`] directly.
pub trait Clock: Send + Sync {
    fn now(&self) -> MonotonicTime;
}

impl Clock for AgentClock {
    fn now(&self) -> MonotonicTime {
        AgentClock::now(self)
    }
}

/// Why [`AuthorizationConfig::new`] refused a configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("lease ttl must be greater than zero")]
    NonPositiveLeaseTtl,
}

/// Agent deployment configuration (F-M2-005, HORO-795): whether
/// `RequestLease` requires the resource to support
/// [`Capability::DeviceRevoke`] before a lease is ever granted for it.
/// Mirrors [`session::SessionRequirement`]/[`approval::ApprovalRequirement`]'s
/// exact shape and the same blast-radius discipline: `NotRequired` is
/// the default, and every pre-HORO-795 deployment/test harness that
/// never heard of this gate must keep behaving exactly as before —
/// today, only `enforce() == Allowed` gates whether a lease is granted;
/// `Capability::DeviceRevoke` is never consulted at grant time at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RevocationRequirement {
    Required,
    #[default]
    NotRequired,
}

/// Configuration for one [`AuthorizationHandler`]. `lease_ttl` has no
/// default — mirroring [`crate::config::AgentConfig`]'s `socket_mode`,
/// there is no safe default for a security-relevant duration; the
/// deployment supplies it.
#[derive(Debug, Clone)]
pub struct AuthorizationConfig {
    lease_ttl: Duration,
    max_outstanding_leases: usize,
    session_requirement: SessionRequirement,
    max_session_ttl: Duration,
    approval_requirement: ApprovalRequirement,
    approval_store_path: Option<PathBuf>,
    once_approval_ttl: Duration,
    /// `Some` only via [`Self::with_delegation`], which sets this
    /// alongside `approval_requirement`/`approval_store_path` in one
    /// call — see that method's doc for why delegation cannot be enabled
    /// without approvals also being required.
    delegation: Option<eltanin_core::delegation::DelegationBounds>,
    /// `Some` only via [`Self::with_step_up`], which sets this alongside
    /// `approval_requirement`/`approval_store_path` in one call, mirroring
    /// [`Self::with_delegation`]'s identical coupling. `None` (the
    /// default) means the risk layer is never consulted at all — every
    /// refusal path's behavior is then byte-identical to before this
    /// ticket (HORO-794).
    step_up: Option<eltanin_core::risk::StepUpPolicy>,
    /// F-M2-005, HORO-795. Defaults to [`RevocationRequirement::NotRequired`]
    /// — see [`RevocationRequirement`]'s own doc for the blast-radius
    /// rationale.
    revocation_requirement: RevocationRequirement,
    /// F-M2-006, HORO-796 subtask 3. Defaults to
    /// [`EnforcementMode::Enforce`] via its own `#[default]` — every
    /// pre-HORO-796-subtask-3 deployment/test harness that never heard
    /// of shadow mode must keep behaving exactly as before, same
    /// blast-radius discipline as every requirement above.
    enforcement_mode: EnforcementMode,
}

const DEFAULT_MAX_OUTSTANDING_LEASES: usize = 1024;

/// Default maximum Trusted Compute Session TTL when a deployment does
/// not opt into a narrower one via [`AuthorizationConfig::with_max_session_ttl`].
/// A heavy developer session is meant to last "hours," per the ticket's
/// own user outcome statement — eight hours is a generous single
/// working day, not an attempt to guess an exact number.
const DEFAULT_MAX_SESSION_TTL: Duration = Duration::from_hours(8);

/// Default `AllowOnce` approval TTL (F-M2-002, HORO-792) when a
/// deployment does not opt into a narrower one via
/// [`AuthorizationConfig::with_once_approval_ttl`]. Lives entirely in
/// agent memory (see `eltanin_core::approval`'s module docs on why only
/// `Once` gets a TTL at all) — two minutes is long enough to cover the
/// gap between running `eltanin approve --once` and the immediately
/// following `eltanin run`, short enough that a stale, un-consumed
/// `Once` grant does not linger.
const DEFAULT_ONCE_APPROVAL_TTL: Duration = Duration::from_secs(120);

impl AuthorizationConfig {
    /// # Errors
    ///
    /// Returns [`ConfigError::NonPositiveLeaseTtl`] if `lease_ttl` is
    /// zero.
    pub fn new(lease_ttl: Duration) -> Result<Self, ConfigError> {
        if lease_ttl.is_zero() {
            return Err(ConfigError::NonPositiveLeaseTtl);
        }
        Ok(Self {
            lease_ttl,
            max_outstanding_leases: DEFAULT_MAX_OUTSTANDING_LEASES,
            // Defaults every existing/new construction to `NotRequired`
            // — HORO-791's own blast-radius obligation: every MVP 1.0
            // test harness and deployment that never heard of Trusted
            // Compute Sessions must keep behaving exactly as before
            // without being touched.
            // Defaults every existing/new construction to `NotRequired`
            // with no store path — HORO-792's own blast-radius
            // obligation, mirroring HORO-791's identical one just above:
            // every MVP 1.0/MVP 2.0-pre-HORO-792 test harness and
            // deployment that never heard of remembered approvals must
            // keep behaving exactly as before, untouched, including
            // never touching the filesystem for this feature at all.
            session_requirement: SessionRequirement::NotRequired,
            max_session_ttl: DEFAULT_MAX_SESSION_TTL,
            approval_requirement: ApprovalRequirement::NotRequired,
            approval_store_path: None,
            once_approval_ttl: DEFAULT_ONCE_APPROVAL_TTL,
            // HORO-793's own blast-radius obligation, mirroring
            // HORO-791/HORO-792's identical ones just above: every
            // pre-HORO-793 test harness and deployment that never heard
            // of delegation must keep behaving exactly as before.
            delegation: None,
            // HORO-794's own blast-radius obligation, mirroring
            // HORO-791/792/793's identical ones above: every
            // pre-HORO-794 test harness and deployment that never heard
            // of risk-based step-up must keep behaving exactly as
            // before — the risk layer is never consulted at all.
            step_up: None,
            // HORO-795's own blast-radius obligation, mirroring every
            // ticket above: every pre-HORO-795 test harness and
            // deployment that never heard of revocation-capability
            // gating must keep behaving exactly as before — a resource
            // lacking Capability::DeviceRevoke remains leasable.
            revocation_requirement: RevocationRequirement::NotRequired,
            // HORO-796 subtask 3's own blast-radius obligation, mirroring
            // every ticket above: every pre-subtask-3 test harness and
            // deployment that never heard of shadow mode must keep
            // behaving exactly as before — every granted `RequestLease`
            // actually reaches the backend and is inserted.
            enforcement_mode: EnforcementMode::default(),
        })
    }

    #[must_use]
    pub fn with_max_outstanding_leases(mut self, max: usize) -> Self {
        self.max_outstanding_leases = max;
        self
    }

    #[must_use]
    pub fn with_session_requirement(mut self, requirement: SessionRequirement) -> Self {
        self.session_requirement = requirement;
        self
    }

    #[must_use]
    pub fn with_max_session_ttl(mut self, max: Duration) -> Self {
        self.max_session_ttl = max;
        self
    }

    /// Require a matching remembered approval before `RequestLease` ever
    /// reaches policy, storing/loading the durable approval set at
    /// `path`. There is deliberately no way to set
    /// [`ApprovalRequirement::Required`] without also supplying a store
    /// path — correct-by-construction, rather than a runtime check for
    /// "no default value for a security-relevant choice" (this repo's
    /// own established convention — see [`AuthorizationConfig::new`]'s
    /// identical `lease_ttl` rationale).
    #[must_use]
    pub fn with_approval_store(mut self, path: PathBuf) -> Self {
        self.approval_requirement = ApprovalRequirement::Required;
        self.approval_store_path = Some(path);
        self
    }

    #[must_use]
    pub fn with_once_approval_ttl(mut self, ttl: Duration) -> Self {
        self.once_approval_ttl = ttl;
        self
    }

    /// Enable bounded compute delegation (F-M2-003, HORO-793): a
    /// descendant of an already-admitted requester may be silently
    /// admitted under a matching [`eltanin_core::delegation::DelegationGrant`]
    /// when the ordinary approval gate would otherwise refuse it.
    ///
    /// There is deliberately no way to set `delegation` without also
    /// requiring approvals — this call sets `approval_requirement` to
    /// [`ApprovalRequirement::Required`] and `approval_store_path` to
    /// `path` in the same step, mirroring
    /// [`Self::with_approval_store`]'s identical
    /// "no default value for a security-relevant choice, made
    /// correct-by-construction" convention. Delegation is consulted only
    /// on the approval gate's own refusal path (see `crate::authz`'s
    /// module docs) — it would be meaningless, and misleadingly
    /// configurable, without approvals also being required.
    #[must_use]
    pub fn with_delegation(
        mut self,
        approval_store: PathBuf,
        bounds: eltanin_core::delegation::DelegationBounds,
    ) -> Self {
        self.approval_requirement = ApprovalRequirement::Required;
        self.approval_store_path = Some(approval_store);
        self.delegation = Some(bounds);
        self
    }

    /// Enable risk-based step-up classification (F-M2-004, HORO-794):
    /// an approval/delegation refusal is classified by
    /// [`eltanin_core::risk::assess`] into `NoStepUp`/`StepUpRequired`/
    /// `RiskDenied` per `policy`, naming the trust change(s) that caused
    /// it. This never loosens any gate — `assess` is only ever consulted
    /// from a refusal path (see `crate::authz::risk`'s module docs).
    ///
    /// Mirrors [`Self::with_delegation`]'s identical coupling
    /// discipline: there is deliberately no way to enable the risk layer
    /// without also requiring approvals — this call sets
    /// `approval_requirement` to [`ApprovalRequirement::Required`] and
    /// `approval_store_path` to `approval_store` in the same step.
    #[must_use]
    pub fn with_step_up(
        mut self,
        approval_store: PathBuf,
        policy: eltanin_core::risk::StepUpPolicy,
    ) -> Self {
        self.approval_requirement = ApprovalRequirement::Required;
        self.approval_store_path = Some(approval_store);
        self.step_up = Some(policy);
        self
    }

    /// Require the resource to support [`Capability::DeviceRevoke`]
    /// before `RequestLease` grants a lease for it (F-M2-005, HORO-795).
    /// See [`RevocationRequirement`]'s own doc for the default and its
    /// blast-radius rationale.
    #[must_use]
    pub fn with_revocation_requirement(mut self, requirement: RevocationRequirement) -> Self {
        self.revocation_requirement = requirement;
        self
    }

    #[must_use]
    pub fn revocation_requirement(&self) -> RevocationRequirement {
        self.revocation_requirement
    }

    /// Set the agent's enforcement posture (F-M2-006, HORO-796 subtask
    /// 3). See [`EnforcementMode`]'s own doc and `crate::authz`'s module
    /// docs for the full shadow-mode contract.
    #[must_use]
    pub fn with_enforcement_mode(mut self, mode: EnforcementMode) -> Self {
        self.enforcement_mode = mode;
        self
    }

    #[must_use]
    pub fn enforcement_mode(&self) -> EnforcementMode {
        self.enforcement_mode
    }

    #[must_use]
    pub fn lease_ttl(&self) -> Duration {
        self.lease_ttl
    }

    #[must_use]
    pub fn max_outstanding_leases(&self) -> usize {
        self.max_outstanding_leases
    }

    #[must_use]
    pub fn session_requirement(&self) -> SessionRequirement {
        self.session_requirement
    }

    #[must_use]
    pub fn max_session_ttl(&self) -> Duration {
        self.max_session_ttl
    }

    #[must_use]
    pub fn approval_requirement(&self) -> ApprovalRequirement {
        self.approval_requirement
    }

    #[must_use]
    pub fn approval_store_path(&self) -> Option<&Path> {
        self.approval_store_path.as_deref()
    }

    #[must_use]
    pub fn delegation(&self) -> Option<&eltanin_core::delegation::DelegationBounds> {
        self.delegation.as_ref()
    }

    #[must_use]
    pub fn step_up(&self) -> Option<&eltanin_core::risk::StepUpPolicy> {
        self.step_up.as_ref()
    }

    #[must_use]
    pub fn once_approval_ttl(&self) -> Duration {
        self.once_approval_ttl
    }
}

/// Why [`load_policy`] could not produce a [`PolicySet`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyLoadError {
    #[error("failed to read policy file: {reason}")]
    Io { reason: String },
    #[error("failed to parse policy file as JSON: {reason}")]
    Json { reason: String },
    #[error(transparent)]
    Invalid(#[from] PolicyError),
}

/// Load and validate a `Versioned<PolicyDocument>` JSON file from `path`.
///
/// # Errors
///
/// Returns [`PolicyLoadError::Io`] if `path` cannot be read,
/// [`PolicyLoadError::Json`] if its contents are not a well-formed
/// `Versioned<PolicyDocument>`, or [`PolicyLoadError::Invalid`] if the
/// decoded document fails [`PolicySet::from_document`]'s validation.
pub fn load_policy(path: &Path) -> Result<PolicySet, PolicyLoadError> {
    let contents = std::fs::read_to_string(path).map_err(|e| PolicyLoadError::Io {
        reason: e.to_string(),
    })?;
    let envelope: Versioned<PolicyDocument> =
        serde_json::from_str(&contents).map_err(|e| PolicyLoadError::Json {
            reason: e.to_string(),
        })?;
    Ok(PolicySet::from_versioned(envelope)?)
}

/// Project a [`DecisionReason`] onto the wire's lossy [`DenialReason`].
fn denial_reason_for(reason: &DecisionReason) -> DenialReason {
    match reason {
        DecisionReason::ExplicitDeny { .. } => DenialReason::ExplicitDeny,
        DecisionReason::IndeterminateEvidence { .. } => DenialReason::IndeterminateEvidence,
        // `LeaseIssuer::issue` only returns `LeaseError::Denied` when the
        // policy's effect is `Deny`, which `DecisionReason::ExplicitAllow`
        // can never accompany — structurally unreachable, but matched
        // explicitly (never a wildcard) so a future `DecisionReason`
        // variant fails to compile here instead of silently mapping to a
        // wrong wire reason. Both this and `NoMatchingRule` project onto
        // the same wire reason, so they're merged into one arm.
        DecisionReason::NoMatchingRule | DecisionReason::ExplicitAllow { .. } => {
            DenialReason::NoMatchingRule
        }
    }
}

/// The result of [`AuthorizationHandler::approval_admission`] — the
/// approval-gate counterpart to `IssueFailure`/`MembershipVerdict`.
enum ApprovalAdmission {
    /// A non-`Deny` candidate matched. `once_id` is `Some` when the
    /// matching candidate was `Once` — the caller must consume it.
    Admitted { once_id: Option<ApprovalId> },
    /// A `Deny` candidate matched (deny-overrides).
    Denied,
    /// No candidate matched — includes every `NotMatched`/`Indeterminate`
    /// verdict, fail-closed. `recall` carries every candidate's own
    /// [`RecallVerdict`] from the scan (never a `Matched` one — the loop
    /// returns immediately on the first match), so the risk-gate glue
    /// (F-M2-004, HORO-794) can classify *why* every candidate missed
    /// without re-deriving evidence.
    Refused { recall: Vec<RecallVerdict> },
    /// The backend capability re-check failed — an internal error, not
    /// an approval decision.
    ObserveFailed(BackendError),
}

/// The result of [`AuthorizationHandler::delegation_admission`] — the
/// delegation-gate counterpart to [`ApprovalAdmission`]. Consulted only
/// from the approval gate's own `Refused` arm (see this module's docs).
enum DelegationAdmission {
    Admitted {
        not_after: MonotonicTime,
        parent_lease: LeaseId,
        depth: u8,
        holder_pid: u32,
    },
    Refused {
        exceeded: BTreeSet<eltanin_core::delegation::ExceededBound>,
        /// Bug fix (F-M2-004, HORO-794): `exceeded` above is a union
        /// across every stored grant, unfiltered by
        /// [`delegation_state::DelegationState::candidates`] — with more
        /// than one grant in the store, `Resource`/`Action` in that
        /// union can come from a grant totally unrelated to this
        /// request (a lookup miss on an unfiltered candidate list, not a
        /// scope-expansion attempt). `linked_exceeded` is the same union
        /// restricted to grants whose own `exceeded` set contains
        /// neither `ExceededBound::AncestryLinkage` nor
        /// `ExceededBound::HolderLiveness` — i.e. grants a fresh
        /// ancestry/liveness check actually confirmed belong to this
        /// requester. This is what the risk-gate glue consumes for
        /// `RiskSignal::DelegationScopeExpanded`; the existing
        /// `exceeded` union's meaning and consumers are unchanged.
        linked_exceeded: BTreeSet<eltanin_core::delegation::ExceededBound>,
    },
    Indeterminate {
        reason: String,
    },
}

/// Context threaded from a successful [`DelegationAdmission::Admitted`]
/// through `handle_request_lease`'s common issue/enforce path to
/// [`AuthorizationHandler::enforce_and_finalize`] — everything needed to
/// cap the lease's expiry, mint the child grant, and report
/// [`AuthorizationOutcome::GrantedByDelegation`] instead of the plain
/// `Granted` variant.
struct DelegatedGrantContext {
    not_after: MonotonicTime,
    parent_lease: LeaseId,
    depth: u8,
    holder_pid: u32,
}

/// Everything [`AuthorizationHandler::enforce_and_finalize`] (real
/// enforcement) or [`AuthorizationHandler::shadow_would_grant`] (shadow
/// mode) needs to act on an already-computed grant verdict — the bundle
/// [`AuthorizationHandler::request_lease_verdict`] produces on its `Ok`
/// path. `lease` has already been minted by
/// [`AuthorizationHandler::issue_reserving_capacity`] (a real capacity
/// reservation is held for it) and had its expiry narrowed for a
/// delegated grant, if any — a real [`eltanin_core::lease::ComputeLease`],
/// never a preview, which is exactly why shadow mode can still report a
/// real, correlatable `lease_id` even though it never keeps the lease
/// (F-M2-006, HORO-796 subtask 3).
struct PreparedGrant {
    lease: eltanin_core::lease::ComputeLease,
    matched_session: Option<SessionId>,
    observed: eltanin_core::identity::ExecutionContext,
    peer_session_key: Evidence<eltanin_core::session::SessionKey>,
    delegated: Option<DelegatedGrantContext>,
}

/// Why [`AuthorizationHandler::issue_reserving_capacity`] did not
/// produce a lease.
enum IssueFailure {
    CapacityExhausted { outstanding: usize },
    Denied(eltanin_core::policy::PolicyDecision),
    Other(LeaseError),
}

/// Implements [`RequestHandler`] by wiring policy evaluation, lease
/// issue/release, and backend enforcement together. Shared across
/// concurrently-served connections (`Arc<dyn RequestHandler>`); internal
/// mutable state is a single `Mutex<LeaseState>`, recovered rather than
/// propagated on poison — see `state::lock`'s own doc comment.
pub struct AuthorizationHandler {
    state: Mutex<LeaseState>,
    sessions: Mutex<SessionState>,
    approvals: Mutex<ApprovalState>,
    delegations: Mutex<DelegationState>,
    policy: PolicySet,
    backend: Arc<dyn ComputeBackend>,
    clock: Arc<dyn Clock>,
    sink: Arc<dyn EventSink>,
    lease_ttl: Duration,
    max_outstanding_leases: usize,
    session_requirement: SessionRequirement,
    approval_requirement: ApprovalRequirement,
    approval_store_path: Option<PathBuf>,
    once_approval_ttl: Duration,
    delegation: Option<eltanin_core::delegation::DelegationBounds>,
    step_up: Option<eltanin_core::risk::StepUpPolicy>,
    revocation_requirement: RevocationRequirement,
    enforcement_mode: EnforcementMode,
}

impl AuthorizationHandler {
    /// # Panics
    ///
    /// When `config.approval_requirement()` is
    /// [`ApprovalRequirement::Required`], this eagerly loads the durable
    /// approval store from `config.approval_store_path()` (always
    /// `Some` in that state — see [`AuthorizationConfig::with_approval_store`])
    /// and panics if it cannot be loaded safely (unsafe file/parent
    /// permissions, corrupt JSON, a failed validation). This is
    /// deliberate fail-closed startup behavior, not an oversight: an
    /// agent that cannot trust its own durable approval store must not
    /// start up silently permissive. When `approval_requirement()` is
    /// [`ApprovalRequirement::NotRequired`] (the default), this
    /// constructor never touches the filesystem for approvals at all —
    /// see the regression test proving this in `tests/`.
    #[must_use]
    pub fn new(
        instance: IssuerInstanceId,
        policy: PolicySet,
        backend: Arc<dyn ComputeBackend>,
        clock: Arc<dyn Clock>,
        sink: Arc<dyn EventSink>,
        config: &AuthorizationConfig,
    ) -> Self {
        // The issuer's own max_ttl bound is set to exactly this config's
        // lease_ttl: every `issue` call below reuses `self.lease_ttl`
        // unmodified, so there is no second, independently-settable ttl
        // anywhere in this handler (module docs: "one TTL value, not
        // two").
        let issuer = LeaseIssuer::new(instance.clone(), config.lease_ttl);
        let session_authority = SessionAuthority::new(instance, config.max_session_ttl);
        let approvals = match config.approval_requirement {
            ApprovalRequirement::NotRequired => ApprovalState::new(),
            ApprovalRequirement::Required => {
                let path = config
                    .approval_store_path
                    .as_deref()
                    .expect("ApprovalRequirement::Required always carries a store path — see AuthorizationConfig::with_approval_store");
                ApprovalState::load(path).unwrap_or_else(|error| {
                    panic!("failed to load approval store {}: {error}", path.display())
                })
            }
        };
        Self {
            state: Mutex::new(LeaseState::new(issuer, config.max_outstanding_leases)),
            sessions: Mutex::new(SessionState::new(session_authority)),
            approvals: Mutex::new(approvals),
            delegations: Mutex::new(DelegationState::new()),
            policy,
            backend,
            clock,
            sink,
            lease_ttl: config.lease_ttl,
            max_outstanding_leases: config.max_outstanding_leases,
            session_requirement: config.session_requirement,
            approval_requirement: config.approval_requirement,
            approval_store_path: config.approval_store_path.clone(),
            once_approval_ttl: config.once_approval_ttl,
            delegation: config.delegation.clone(),
            step_up: config.step_up.clone(),
            revocation_requirement: config.revocation_requirement,
            enforcement_mode: config.enforcement_mode,
        }
    }

    /// Prune, capacity-check, issue, and reserve the resulting lease's
    /// capacity slot — all under one lock acquisition. Reserving here
    /// (rather than only checking capacity) closes a race
    /// `is_at_capacity` alone would leave open: `enforce()` runs
    /// unlocked after this returns, so without a reservation held across
    /// that window, concurrent callers could all observe capacity as
    /// free before any of them reaches `insert`. Every caller of this
    /// method must release exactly one reservation on every path
    /// (`LeaseState::insert` does so on success;
    /// `LeaseState::release_reservation` on every failure path after a
    /// successful issue).
    fn issue_reserving_capacity(
        &self,
        provenance: ProvenanceRecord,
    ) -> Result<eltanin_core::lease::ComputeLease, IssueFailure> {
        let mut guard = state::lock(&self.state);
        let now = self.clock.now();
        guard.prune(now);
        if guard.is_at_capacity() {
            return Err(IssueFailure::CapacityExhausted {
                outstanding: self.max_outstanding_leases,
            });
        }
        let issued = guard
            .issuer_mut()
            .issue(&self.policy, provenance, now, self.lease_ttl);
        match issued {
            Ok(lease) => {
                guard.reserve();
                Ok(lease)
            }
            Err(LeaseError::Denied { decision }) => Err(IssueFailure::Denied(decision)),
            Err(error) => Err(IssueFailure::Other(error)),
        }
    }

    /// Bug fix (HORO-795): tear down backend enforcement for any lease
    /// that has expired since it was granted. `LeaseState::prune` (called
    /// by `issue_reserving_capacity` and `handle_release_lease` below)
    /// removes an expired lease's *lease-state* record but owns no
    /// [`ComputeBackend`] reference and cannot itself call
    /// `backend.revoke()` — without this sweep, a workload whose
    /// controlling `eltanin run` process was killed (so `ReleaseLease` is
    /// never called) keeps live backend-side enforcement indefinitely
    /// after its lease has silently expired and been pruned. Called at
    /// the top of both `handle_request_lease` and `handle_release_lease`
    /// — a separate step, run *before* either of those functions' own
    /// existing `prune` call, never threaded through
    /// `issue_reserving_capacity`'s signature (a different function with
    /// a different job).
    ///
    /// No `enforcement_mode` branch needed here (F-M2-006, HORO-796
    /// subtask 3): a lease minted under [`EnforcementMode::Shadow`] is
    /// always reversed (revoked, never inserted) before this method's
    /// caller returns — see [`Self::shadow_would_grant`] — so
    /// `LeaseState` structurally never holds a shadow-minted lease for
    /// this sweep to find. This sweep needs no awareness of shadow mode
    /// at all.
    ///
    /// Mirrors [`Self::membership_for_peer`]'s reap-then-cascade shape,
    /// and `LeaseState::sweep_expired`'s own "compute what to do under
    /// the lock, drop the lock, then act" discipline: the state lock is
    /// released before any `backend.revoke()` call, exactly like every
    /// other backend call this handler makes outside `handle_release_lease`'s
    /// own deliberate exception (see that method's doc comment on why it
    /// alone holds the lock across its `backend.revoke()` call).
    fn sweep_expired_leases(&self) {
        let now = self.clock.now();
        let mut guard = state::lock(&self.state);
        let sweep = guard.sweep_expired(now);
        drop(guard);

        // HORO-795's dedup rule, unchanged: revoke at most once per
        // distinct resource. The result is kept (not discarded with
        // `let _`) so every expired lease named by this resource can
        // report the actual backend outcome below.
        let mut backend_results = std::collections::BTreeMap::new();
        for (_, resource) in &sweep.teardown {
            let result = match self.backend.revoke(resource) {
                Ok(result) => result,
                Err(error) => EnforcementResult::Error {
                    message: error.to_string(),
                },
            };
            backend_results.insert(resource.clone(), result);
        }

        // Audit fidelity (HORO-796 subtask 2): every expired lease gets
        // its own `LeaseExpired` event, regardless of whether its
        // resource was in `teardown` — `backend` is `None` exactly when
        // this resource's teardown was skipped because another live
        // lease still names it.
        for (lease_id, resource, expired_at) in sweep.expired {
            let backend = backend_results.get(&resource).cloned();
            self.sink
                .record_agent_event(eltanin_audit::record::RecordedAgentEvent::LeaseExpired {
                    lease_id,
                    resource,
                    expired_at,
                    backend,
                });
        }
    }

    fn handle_status(&self) -> (AuthorizationOutcome, AgentResponse) {
        (
            AuthorizationOutcome::StatusReported,
            AgentResponse::Status {
                status: AgentStatusView {
                    protocol_version: eltanin_core::envelope::DOMAIN_SCHEMA_VERSION,
                    enforcement_mode: self.enforcement_mode,
                    session_required: matches!(
                        self.session_requirement,
                        SessionRequirement::Required
                    ),
                    approval_required: matches!(
                        self.approval_requirement,
                        ApprovalRequirement::Required
                    ),
                    revocation_required: matches!(
                        self.revocation_requirement,
                        RevocationRequirement::Required
                    ),
                },
            },
        )
    }

    /// Freshly determine whether `peer` verifies as a member of any
    /// currently stored session, reaping stale sessions first (the
    /// lazy-reaping touch point for every session-touching operation).
    /// Returns the matched session's id (only when the verdict is
    /// exactly [`MembershipVerdict::Member`]) alongside the full
    /// verdict, so a caller needing only the pass/fail gate and a
    /// caller needing to associate a freshly granted lease with a
    /// session can both use this one evaluation. Also returns the
    /// [`Evidence<SessionKey>`] collected for `peer` along the way (HORO-793)
    /// — the delegation gate needs this same evidence for its own
    /// `require_same_session` check and must reuse it rather than
    /// collecting it a second time (see `authz::delegation`'s module
    /// docs on why re-collection would reopen a closed TOCTOU window).
    fn membership_for_peer(
        &self,
        peer: &PeerContext,
    ) -> (
        Option<SessionId>,
        MembershipVerdict,
        Evidence<eltanin_core::session::SessionKey>,
    ) {
        let now = self.clock.now();
        let mut sessions = session_state::lock(&self.sessions);
        let reaped = sessions.reap(now, session::collect_workload_identity);

        let pid = peer.observed().workload.pid;
        let peer_key = session::collect_session_key(pid);
        let matched_and_verdict = match &peer_key {
            Evidence::Present { value, .. } => sessions.find_by_key(*value),
            Evidence::Missing { .. } | Evidence::Unsupported => None,
        }
        .map(|candidate| {
            let leader = session::collect_workload_identity(candidate.anchor().leader.pid);
            let verdict = membership(candidate, &peer_key, &leader);
            let matched =
                matches!(verdict, MembershipVerdict::Member).then(|| candidate.id().clone());
            (matched, verdict)
        });
        drop(sessions);

        // Bug fix (HORO-795): a session reaped just above — by EXPIRY or
        // ANCHOR-LEADER DEATH, as opposed to an explicit
        // `TerminateSession` (whose own cascade already handled this
        // correctly) — must cascade-revoke its leases at the
        // backend/lease-state layer the same way, or a killed
        // `eltanin run` process's device-level access outlives its own
        // now-dead session indefinitely. See `SessionState::reap`'s doc
        // comment.
        for (_, lease_ids) in reaped {
            self.cascade_revoke_leases(lease_ids);
        }

        match matched_and_verdict {
            Some((matched, verdict)) => (matched, verdict, peer_key),
            None => (
                None,
                MembershipVerdict::Indeterminate {
                    reason: "no session found for this peer's session key".to_string(),
                },
                peer_key,
            ),
        }
    }

    /// Cascade-revoke every lease id in `lease_ids` at the lease-state/
    /// backend layer, reusing exactly the mechanism
    /// `handle_terminate_session`'s explicit-termination cascade already
    /// established: [`Self::revoke_lease_for_session_teardown`] for each
    /// id. Shared by every lazy-reaping call site (Bug fix, HORO-795) so
    /// a session dying by EXPIRY or ANCHOR-LEADER DEATH is cascaded
    /// identically to one dying by explicit `TerminateSession`.
    fn cascade_revoke_leases(&self, lease_ids: BTreeSet<LeaseId>) {
        for lease_id in lease_ids {
            self.revoke_lease_for_session_teardown(&lease_id);
        }
    }

    /// The result of [`AuthorizationHandler::approval_admission`].
    fn approval_admission(
        &self,
        request: &LeaseRequest,
        observed: &eltanin_core::identity::ExecutionContext,
    ) -> ApprovalAdmission {
        let now = self.clock.now();
        let mut approvals = approval_state::lock(&self.approvals);
        approvals.reap_once(now);

        let capabilities = match self.backend.observe(&request.resource) {
            Ok(resource) => resource.capabilities,
            Err(error) => return ApprovalAdmission::ObserveFailed(error),
        };
        let current_policy = self.policy.provenance();
        let compute_request = ComputeRequest {
            resource: request.resource.clone(),
            action: request.action,
        };

        let mut recall_verdicts = Vec::new();
        for approval in approvals.candidates(&request.resource, request.action) {
            let verdict = recall(
                approval,
                observed,
                &capabilities,
                &current_policy,
                &compute_request,
            );
            if let RecallVerdict::Matched { id } = verdict {
                return match approval.disposition() {
                    ApprovalDisposition::Deny => ApprovalAdmission::Denied,
                    ApprovalDisposition::Once => ApprovalAdmission::Admitted { once_id: Some(id) },
                    ApprovalDisposition::Remember => ApprovalAdmission::Admitted { once_id: None },
                };
            }
            recall_verdicts.push(verdict);
        }
        ApprovalAdmission::Refused {
            recall: recall_verdicts,
        }
    }

    /// The result of [`AuthorizationHandler::delegation_admission`].
    /// Consulted **only** from `handle_request_lease`'s
    /// `ApprovalAdmission::Refused` arm — see this module's docs. Scans
    /// every currently stored [`eltanin_core::delegation::DelegationGrant`]
    /// and returns the first that admits (mirroring
    /// `approval_admission`'s identical "first matching candidate wins"
    /// loop). If none admits: any `Indeterminate` verdict wins over a
    /// `NotAdmitted` one (fail-closed — an unresolved candidate must
    /// never be silently treated as a clean refusal), otherwise every
    /// `NotAdmitted` candidate's `exceeded` set is unioned for the audit
    /// trail.
    fn delegation_admission(
        &self,
        request: &LeaseRequest,
        observed: &eltanin_core::identity::ExecutionContext,
        peer_session_key: &Evidence<eltanin_core::session::SessionKey>,
        bounds: &eltanin_core::delegation::DelegationBounds,
    ) -> DelegationAdmission {
        let now = self.clock.now();
        let mut delegations = delegation_state::lock(&self.delegations);
        delegations.reap(now, session::collect_workload_identity);

        let compute_request = ComputeRequest {
            resource: request.resource.clone(),
            action: request.action,
        };

        let mut union_exceeded = BTreeSet::new();
        let mut linked_exceeded = BTreeSet::new();
        let mut indeterminate_reason: Option<String> = None;
        for grant in delegations.candidates() {
            let observed_holder = session::collect_workload_identity(grant.holder().pid);
            match eltanin_core::delegation::delegated_admission(
                grant,
                bounds,
                observed,
                peer_session_key,
                &observed_holder,
                &compute_request,
                now,
            ) {
                eltanin_core::delegation::DelegationVerdict::Admitted {
                    depth,
                    not_after,
                    parent_lease,
                } => {
                    return DelegationAdmission::Admitted {
                        not_after,
                        parent_lease,
                        depth,
                        holder_pid: grant.holder().pid,
                    };
                }
                eltanin_core::delegation::DelegationVerdict::NotAdmitted { exceeded } => {
                    // Bug fix (HORO-794): only a grant that passed
                    // ancestry linkage and holder liveness is actually
                    // about this requester — see `linked_exceeded`'s own
                    // doc comment on `DelegationAdmission::Refused`.
                    if risk::is_linked_grant_failure(&exceeded) {
                        linked_exceeded.extend(exceeded.iter().copied());
                    }
                    union_exceeded.extend(exceeded);
                }
                eltanin_core::delegation::DelegationVerdict::Indeterminate { reason } => {
                    indeterminate_reason.get_or_insert(reason);
                }
            }
        }
        drop(delegations);
        if let Some(reason) = indeterminate_reason {
            return DelegationAdmission::Indeterminate { reason };
        }
        DelegationAdmission::Refused {
            exceeded: union_exceeded,
            linked_exceeded,
        }
    }

    /// The approval-admission gate (F-M2-002, HORO-792) extended by the
    /// delegation gate (F-M2-003, HORO-793). Runs *after* the session
    /// gate and *before* policy is ever consulted — same structural
    /// placement as both. A complete no-op when `approval_requirement`
    /// is `NotRequired` (the default): no lock is even acquired.
    ///
    /// `Ok(delegated)` means `handle_request_lease` should proceed to
    /// `issue_reserving_capacity`/`enforce_and_finalize`; `delegated` is
    /// `Some` only when this particular request was admitted via the
    /// delegation gate rather than an ordinary matching approval.
    /// `Err(response)` is the exact `(outcome, response)` pair
    /// `handle_request_lease` should return immediately.
    ///
    /// The delegation gate is consulted **only** from the approval
    /// gate's own `Refused` arm below, and can only turn that refusal
    /// into a bounded admission — never turn an admission or an
    /// explicit `Deny` into a refusal. Deny-overrides is inherited by
    /// construction: `ApprovalAdmission::Denied` returns before
    /// delegation is ever consulted.
    ///
    /// The risk layer (F-M2-004, HORO-794) is consulted from every
    /// refusal arm below via [`Self::refuse_with_risk`] — never from
    /// `Denied`/`Admitted`/`ObserveFailed` — so it can only ever
    /// classify a refusal already produced here, never loosen or
    /// independently produce one.
    // `(AuthorizationOutcome, AgentResponse)` is the exact pair
    // `handle_request_lease` already returns from every other early-exit
    // branch in this file; boxing it here to satisfy `result_large_err`
    // would just move the allocation, not remove it, and this method is
    // called at most once per `RequestLease`, never in a hot loop.
    #[allow(clippy::result_large_err)]
    fn approval_and_delegation_gate(
        &self,
        request: &LeaseRequest,
        observed: &eltanin_core::identity::ExecutionContext,
        peer_session_key: &Evidence<eltanin_core::session::SessionKey>,
        membership: &MembershipVerdict,
    ) -> Result<Option<DelegatedGrantContext>, (AuthorizationOutcome, AgentResponse)> {
        if self.approval_requirement != ApprovalRequirement::Required {
            return Ok(None);
        }
        match self.approval_admission(request, observed) {
            ApprovalAdmission::Denied => Err((
                AuthorizationOutcome::ApprovalDenied,
                AgentResponse::LeaseDenied {
                    reason: DenialReason::ApprovalDenied,
                },
            )),
            ApprovalAdmission::Refused { recall } => {
                let Some(bounds) = &self.delegation else {
                    return Err(self.refuse_with_risk(
                        membership,
                        &recall,
                        None,
                        observed,
                        AuthorizationOutcome::ApprovalRequired,
                        DenialReason::ApprovalRequired,
                    ));
                };
                match self.delegation_admission(request, observed, peer_session_key, bounds) {
                    DelegationAdmission::Admitted {
                        not_after,
                        parent_lease,
                        depth,
                        holder_pid,
                    } => Ok(Some(DelegatedGrantContext {
                        not_after,
                        parent_lease,
                        depth,
                        holder_pid,
                    })),
                    DelegationAdmission::Refused {
                        exceeded,
                        linked_exceeded,
                    } => {
                        let delegation_verdict =
                            eltanin_core::delegation::DelegationVerdict::NotAdmitted {
                                exceeded: linked_exceeded,
                            };
                        Err(self.refuse_with_risk(
                            membership,
                            &recall,
                            Some(&delegation_verdict),
                            observed,
                            AuthorizationOutcome::DelegationRefused { exceeded },
                            DenialReason::ApprovalRequired,
                        ))
                    }
                    DelegationAdmission::Indeterminate { reason } => {
                        let delegation_verdict =
                            eltanin_core::delegation::DelegationVerdict::Indeterminate {
                                reason: reason.clone(),
                            };
                        Err(self.refuse_with_risk(
                            membership,
                            &recall,
                            Some(&delegation_verdict),
                            observed,
                            AuthorizationOutcome::DelegationIndeterminate { reason },
                            DenialReason::ApprovalRequired,
                        ))
                    }
                }
            }
            ApprovalAdmission::ObserveFailed(error) => Err((
                AuthorizationOutcome::ApprovalGateObserveFailed { error },
                AgentResponse::Error {
                    code: ErrorCode::Internal,
                },
            )),
            ApprovalAdmission::Admitted { once_id: Some(id) } => {
                approval_state::lock(&self.approvals).consume_once(&id);
                Ok(None)
            }
            ApprovalAdmission::Admitted { once_id: None } => Ok(None),
        }
    }

    /// Classify an already-produced refusal via the risk layer
    /// (F-M2-004, HORO-794), falling back to `(fallback_outcome,
    /// fallback_reason)` unchanged when `self.step_up` is not
    /// configured, or when the classification comes back `NoStepUp` —
    /// in both cases this is byte-identical to pre-HORO-794 behavior.
    /// Only called from `approval_and_delegation_gate`'s refusal arms —
    /// never from an admission or the approval gate's own `Denied`
    /// (deny-overrides) arm, and never from `ObserveFailed` (an internal
    /// error, not a decision to classify).
    fn refuse_with_risk(
        &self,
        membership: &MembershipVerdict,
        recall: &[RecallVerdict],
        delegation: Option<&eltanin_core::delegation::DelegationVerdict>,
        observed: &eltanin_core::identity::ExecutionContext,
        fallback_outcome: AuthorizationOutcome,
        fallback_reason: DenialReason,
    ) -> (AuthorizationOutcome, AgentResponse) {
        let Some(policy) = &self.step_up else {
            return (
                fallback_outcome,
                AgentResponse::LeaseDenied {
                    reason: fallback_reason,
                },
            );
        };
        match risk::assess_refusal(membership, recall, delegation, observed, policy) {
            eltanin_core::risk::StepUpVerdict::NoStepUp { .. } => (
                fallback_outcome,
                AgentResponse::LeaseDenied {
                    reason: fallback_reason,
                },
            ),
            eltanin_core::risk::StepUpVerdict::StepUpRequired { signals } => (
                AuthorizationOutcome::StepUpRequired { signals },
                AgentResponse::LeaseDenied {
                    reason: DenialReason::StepUpRequired,
                },
            ),
            eltanin_core::risk::StepUpVerdict::RiskDenied { signals } => (
                AuthorizationOutcome::RiskDenied { signals },
                AgentResponse::LeaseDenied {
                    reason: DenialReason::RiskDenied,
                },
            ),
        }
    }

    /// Revocation-capability gate (F-M2-005, HORO-795): a no-op returning
    /// `None` whenever `revocation_requirement` is `NotRequired` (the
    /// default) — no backend call is made in that case, so the default
    /// configuration path stays byte-identical to pre-HORO-795. When
    /// `Required`, re-observes the resource (mirroring
    /// `approval_admission`'s identical `ComputeBackend::observe`
    /// re-check) and refuses the grant if it does not support
    /// `Capability::DeviceRevoke` — reusing the existing
    /// `AuthorizationOutcome::EnforcementRefused` variant/`Error{Internal}`
    /// wire mapping already established for "internal/capability-level
    /// refusal, not a policy decision," rather than introducing a new
    /// wire `DenialReason` variant. An `observe` failure itself reuses
    /// the existing `AuthorizationOutcome::BackendFailed` variant
    /// (a real backend call failed, not a gate decision) rather than a
    /// new one — deliberately, so this ticket's audit-event surface
    /// stays within `crate::authz`'s own three in-scope files and never
    /// has to touch `eltanin-audit`'s `RecordedOutcome` mirror.
    #[allow(clippy::result_large_err)]
    fn revocation_capability_gate(
        &self,
        request: &LeaseRequest,
    ) -> Option<(AuthorizationOutcome, AgentResponse)> {
        if self.revocation_requirement != RevocationRequirement::Required {
            return None;
        }
        match self.backend.observe(&request.resource) {
            Ok(resource) => {
                if resource.capabilities.supports(Capability::DeviceRevoke) {
                    None
                } else {
                    Some((
                        AuthorizationOutcome::EnforcementRefused {
                            result: EnforcementResult::Unsupported {
                                capability: Capability::DeviceRevoke,
                            },
                        },
                        AgentResponse::Error {
                            code: ErrorCode::Internal,
                        },
                    ))
                }
            }
            Err(error) => Some((
                AuthorizationOutcome::BackendFailed { error },
                AgentResponse::Error {
                    code: ErrorCode::Internal,
                },
            )),
        }
    }

    /// Compute what a `RequestLease` should do, without acting on it —
    /// everything through lease issuance and delegated-expiry narrowing
    /// (F-M2-006, HORO-796 subtask 3). Extracted from
    /// `handle_request_lease` so both the real-enforcement path
    /// ([`Self::enforce_and_finalize`]) and the shadow-mode path
    /// ([`Self::shadow_would_grant`]/[`Self::shadow_project_refusal`])
    /// reach `PolicySet::evaluate` and every gate through this exact
    /// same call chain — the ticket's own explicit warning is that
    /// shadow mode "must use the same decision engine... not become a
    /// separate fake path," and this is the structural guarantee of
    /// that: there is only ever one function that decides.
    ///
    /// A mechanical extraction, not a behavior change: every `Err` arm
    /// below produces the exact `(AuthorizationOutcome, AgentResponse,
    /// Option<SessionId>)` triple `handle_request_lease` itself used to
    /// return directly for that same condition.
    // `(AuthorizationOutcome, AgentResponse, Option<SessionId>)` is the
    // exact triple `handle_request_lease` already returned from every
    // refusal branch before this extraction; boxing it here would just
    // move the allocation, not remove it, mirroring
    // `approval_and_delegation_gate`'s identical existing suppression
    // just above.
    #[allow(clippy::result_large_err, clippy::type_complexity)]
    fn request_lease_verdict(
        &self,
        request: &LeaseRequest,
        peer: &PeerContext,
    ) -> Result<PreparedGrant, (AuthorizationOutcome, AgentResponse, Option<SessionId>)> {
        // Bug fix (HORO-795): sweep any lease that has expired since it
        // was granted, tearing down its backend enforcement — see
        // `sweep_expired_leases`'s own doc comment. Runs before every
        // other check below, same as `LeaseState::prune`'s existing
        // touch-point discipline.
        self.sweep_expired_leases();

        let Some(observed) = peer.authorizable() else {
            // Genuinely runs before session resolution below — `None`
            // is the honest value here (HORO-796 subtask 2), not a
            // placeholder.
            return Err((
                AuthorizationOutcome::PeerNotAuthorizable,
                AgentResponse::LeaseDenied {
                    reason: DenialReason::IndeterminateEvidence,
                },
                None,
            ));
        };

        // Pre-policy session-admission gate (F-M2-001, HORO-791): runs
        // *before* policy is ever consulted, so a session-membership
        // denial is never reported as a policy decision — same
        // structural placement as the `peer.authorizable()` gate just
        // above. `matched_session` is threaded through to the grant
        // path below regardless of `session_requirement`, so a lease
        // issued while a session happens to be active gets associated
        // with it (for session-termination revocation) even when that
        // session was not required for admission. Every return point
        // from here on carries `matched_session` on the audit record too
        // (HORO-796 subtask 2) — it is the resolved session for this
        // request, whether or not that request was ultimately admitted.
        let (matched_session, verdict, peer_session_key) = self.membership_for_peer(peer);
        if self.session_requirement == SessionRequirement::Required
            && !matches!(verdict, MembershipVerdict::Member)
        {
            return Err((
                AuthorizationOutcome::SessionRequired,
                AgentResponse::LeaseDenied {
                    reason: DenialReason::NoTrustedSession,
                },
                matched_session,
            ));
        }

        // Pre-policy approval-admission gate (F-M2-002, HORO-792),
        // extended by the delegation gate (F-M2-003, HORO-793) — see
        // `approval_and_delegation_gate`'s own doc comment. Split out
        // only to stay under this crate's line-count lint.
        let delegated =
            match self.approval_and_delegation_gate(request, observed, &peer_session_key, &verdict)
            {
                Ok(delegated) => delegated,
                Err((outcome, response)) => return Err((outcome, response, matched_session)),
            };

        // Revocation-capability gate (F-M2-005, HORO-795): checked
        // before capacity is ever reserved, so a request refused here
        // never wastes/holds a capacity slot for a lease that would
        // just be revoked immediately after.
        if let Some((outcome, response)) = self.revocation_capability_gate(request) {
            return Err((outcome, response, matched_session));
        }

        let provenance = provenance_for(request, observed.clone());

        let lease = match self.issue_reserving_capacity(provenance) {
            Ok(lease) => lease,
            Err(IssueFailure::CapacityExhausted { outstanding }) => {
                return Err((
                    AuthorizationOutcome::CapacityExhausted { outstanding },
                    AgentResponse::Error {
                        code: ErrorCode::Internal,
                    },
                    matched_session,
                ))
            }
            Err(IssueFailure::Denied(decision)) => {
                let reason = denial_reason_for(decision.reason());
                return Err((
                    AuthorizationOutcome::PolicyDenied { decision },
                    AgentResponse::LeaseDenied { reason },
                    matched_session,
                ));
            }
            Err(IssueFailure::Other(error)) => {
                return Err((
                    AuthorizationOutcome::LeaseIssueFailed { error },
                    AgentResponse::Error {
                        code: ErrorCode::Internal,
                    },
                    matched_session,
                ))
            }
        };

        // `narrow_expiry` here — before either action path ever runs —
        // is what makes a delegated grant's TTL bound structural rather
        // than merely checked: the lease this call produces can never
        // carry an expiry later than the delegation verdict's own
        // `not_after`.
        let lease = match &delegated {
            Some(ctx) => lease.narrow_expiry(ctx.not_after),
            None => lease,
        };

        Ok(PreparedGrant {
            lease,
            matched_session,
            observed: observed.clone(),
            peer_session_key,
            delegated,
        })
    }

    fn handle_request_lease(
        &self,
        request: &LeaseRequest,
        peer: &PeerContext,
    ) -> (AuthorizationOutcome, AgentResponse, Option<SessionId>) {
        match self.request_lease_verdict(request, peer) {
            Ok(prepared) => {
                let matched_session = prepared.matched_session.clone();
                let (outcome, response) = match self.enforcement_mode {
                    EnforcementMode::Enforce => {
                        let PreparedGrant {
                            lease,
                            matched_session,
                            observed,
                            peer_session_key,
                            delegated,
                        } = prepared;
                        self.enforce_and_finalize(
                            lease,
                            matched_session.as_ref(),
                            &observed,
                            &peer_session_key,
                            delegated,
                        )
                    }
                    EnforcementMode::Shadow => self.shadow_would_grant(&prepared),
                };
                (outcome, response, matched_session)
            }
            Err((outcome, response, matched_session)) => match self.enforcement_mode {
                EnforcementMode::Enforce => (outcome, response, matched_session),
                EnforcementMode::Shadow => {
                    let (outcome, response) = Self::shadow_project_refusal(outcome, response);
                    (outcome, response, matched_session)
                }
            },
        }
    }

    /// Shadow-mode counterpart to [`Self::enforce_and_finalize`]
    /// (F-M2-006, HORO-796 subtask 3): `prepared.lease` reached here
    /// through the exact same `PolicySet::evaluate`/gate call chain
    /// `enforce_and_finalize` itself uses — both are fed by
    /// [`Self::request_lease_verdict`]. This method's only job is to
    /// report what *would* have happened, without ever calling
    /// [`ComputeBackend::enforce`]: verified by
    /// `crates/eltanin-agent/tests/authz_shadow.rs`'s call-count
    /// assertions, not merely by this comment.
    ///
    /// `prepared.lease` was already minted by `issue_reserving_capacity`
    /// (a real `LeaseId`, a real capacity reservation) — reversed here
    /// the exact same way `enforce_and_finalize`'s own non-`Allowed` arms
    /// already do (`issuer_mut().revoke` + `release_reservation`), never
    /// a new compensating mechanism.
    ///
    /// Deliberately does **not** mint a
    /// [`eltanin_core::delegation::DelegationGrant`], even when
    /// `prepared.delegated` is `Some`/`self.delegation` is configured:
    /// minting one is `enforce_and_finalize`'s own real-grant side
    /// effect, conditioned on `backend.enforce()` actually returning
    /// `Allowed` — shadow mode never reaches that call at all, so there
    /// is no real grant for a future delegated admission to chain from.
    /// Likewise never associates the lease with a session (`insert`,
    /// `associate_lease`) — nothing was actually granted.
    fn shadow_would_grant(
        &self,
        prepared: &PreparedGrant,
    ) -> (AuthorizationOutcome, AgentResponse) {
        let expires_at = prepared.lease.expires_at();
        let lease_id = prepared.lease.id().clone();

        // Reverse the mint: the exact same compensating path
        // `enforce_and_finalize`'s non-`Allowed` arms already use.
        // Deliberately never `backend.enforce()`/`backend.revoke()` —
        // shadow mode must not touch the backend at all.
        let mut guard = state::lock(&self.state);
        guard.issuer_mut().revoke(&lease_id);
        guard.release_reservation();
        drop(guard);

        (
            AuthorizationOutcome::WouldGrant {
                lease_id,
                expires_at,
            },
            AgentResponse::ShadowObserved {
                verdict: ShadowVerdict::WouldAllow,
            },
        )
    }

    /// Shadow-mode counterpart to a refusal
    /// [`Self::request_lease_verdict`] already produced (F-M2-006,
    /// HORO-796 subtask 3): `outcome` — the value recorded to audit — is
    /// returned byte-identical to what `Enforce` mode would have
    /// recorded for the same input; this is the differential-equivalence
    /// property `authz_shadow.rs` verifies. Only the *wire* response
    /// changes: from whichever concrete `AgentResponse::LeaseDenied`/
    /// `Error` variant `Enforce` mode would have sent, to the coarse
    /// [`AgentResponse::ShadowObserved`] projection — the specific gate/
    /// policy reason stays in the audit trail only, same "lossy wire,
    /// rich audit" discipline `DenialReason` already establishes.
    ///
    /// A gate/policy refusal — a genuine authorization verdict — projects
    /// to `WouldDeny`/`WouldStepUp`. A refusal that is not itself a
    /// decision (a backend-observe failure, capacity exhaustion, a
    /// structurally-unreachable lease error) has no verdict to shadow and
    /// keeps its existing `AgentResponse::Error` response unchanged in
    /// both modes — it would be identically undecidable in `Enforce`
    /// mode too, so there is nothing honest to report as "would deny."
    ///
    /// Matched explicitly over every `AuthorizationOutcome` variant,
    /// never a wildcard, mirroring `denial_reason_for`'s own discipline —
    /// a future variant added to this crate fails to compile here
    /// instead of silently landing in the wrong bucket. The two `None`
    /// groups below both return the same value today, which is why
    /// clippy's `match_same_arms` is suppressed for this function — they
    /// are kept structurally separate (reachable-but-not-a-decision vs.
    /// genuinely unreachable from this call site) because that
    /// distinction is exactly what a reviewer needs to verify this match
    /// is honest, not because clippy can't see a difference that matters.
    #[allow(clippy::match_same_arms)]
    fn shadow_project_refusal(
        outcome: AuthorizationOutcome,
        response: AgentResponse,
    ) -> (AuthorizationOutcome, AgentResponse) {
        let verdict = match &outcome {
            AuthorizationOutcome::StepUpRequired { .. } => Some(ShadowVerdict::WouldStepUp),
            AuthorizationOutcome::PeerNotAuthorizable
            | AuthorizationOutcome::SessionRequired
            | AuthorizationOutcome::ApprovalRequired
            | AuthorizationOutcome::ApprovalDenied
            | AuthorizationOutcome::DelegationRefused { .. }
            | AuthorizationOutcome::DelegationIndeterminate { .. }
            | AuthorizationOutcome::RiskDenied { .. }
            | AuthorizationOutcome::PolicyDenied { .. }
            | AuthorizationOutcome::EnforcementRefused { .. } => Some(ShadowVerdict::WouldDeny),
            // Not decisions — internal/infrastructure failures that
            // would be identically undecidable in `Enforce` mode, so
            // there is no verdict to project. Only
            // `CapacityExhausted`/`LeaseIssueFailed`/`ApprovalGateObserveFailed`
            // are actually reachable from `request_lease_verdict`'s
            // refusal path; `BackendFailed` is listed alongside them for
            // the same reason (an `observe`/`enforce` failure is never a
            // decision), even though its only current producer
            // (`revocation_capability_gate`'s `observe` failure) already
            // sits inside the refusal path too.
            AuthorizationOutcome::CapacityExhausted { .. }
            | AuthorizationOutcome::LeaseIssueFailed { .. }
            | AuthorizationOutcome::BackendFailed { .. }
            | AuthorizationOutcome::ApprovalGateObserveFailed { .. } => None,
            // Structurally unreachable from `request_lease_verdict`'s
            // `Err` arm — listed explicitly (never wildcarded) so a
            // future `AuthorizationOutcome` variant fails to compile
            // here rather than silently falling into either bucket
            // above.
            AuthorizationOutcome::Granted { .. }
            | AuthorizationOutcome::WouldGrant { .. }
            | AuthorizationOutcome::Released { .. }
            | AuthorizationOutcome::ReleaseRefused { .. }
            | AuthorizationOutcome::ReleaseUnknownLease
            | AuthorizationOutcome::StatusReported
            | AuthorizationOutcome::SessionEstablished { .. }
            | AuthorizationOutcome::SessionEstablishFailed { .. }
            | AuthorizationOutcome::SessionListed { .. }
            | AuthorizationOutcome::SessionTerminated { .. }
            | AuthorizationOutcome::SessionNotFound
            | AuthorizationOutcome::ApprovalRecorded { .. }
            | AuthorizationOutcome::ApprovalListed { .. }
            | AuthorizationOutcome::ApprovalForgotten { .. }
            | AuthorizationOutcome::ApprovalInternalError { .. }
            | AuthorizationOutcome::GrantedByDelegation { .. } => None,
        };
        match verdict {
            Some(verdict) => (outcome, AgentResponse::ShadowObserved { verdict }),
            None => (outcome, response),
        }
    }

    /// The grant-path tail of `handle_request_lease`, split out only to
    /// stay under this crate's line-count lint — no behavioral seam.
    /// `matched_session`, when present, is the session this lease
    /// should be associated with for later termination-triggered
    /// revocation (see `handle_request_lease`'s own doc comment on why
    /// this happens regardless of `session_requirement`). `observed`/
    /// `peer_session_key` are the same already-observed evidence
    /// `handle_request_lease` collected — reused (never re-collected)
    /// to derive the [`eltanin_core::delegation::DelegationGrant`] minted
    /// for every successful grant (HORO-793). `delegated`, when `Some`,
    /// means this grant itself was admitted via the delegation gate:
    /// [`AuthorizationOutcome::GrantedByDelegation`] is reported instead
    /// of the plain `Granted`, and the newly minted grant's `depth`/
    /// `parent` come from it instead of being `0`/`None`.
    fn enforce_and_finalize(
        &self,
        lease: eltanin_core::lease::ComputeLease,
        matched_session: Option<&SessionId>,
        observed: &eltanin_core::identity::ExecutionContext,
        peer_session_key: &Evidence<eltanin_core::session::SessionKey>,
        delegated: Option<DelegatedGrantContext>,
    ) -> (AuthorizationOutcome, AgentResponse) {
        match self.backend.enforce(&lease.origin().request) {
            Ok(EnforcementResult::Allowed) => {
                let expires_at = lease.expires_at();
                let remaining = expires_at.saturating_duration_since(self.clock.now());
                let lease_id = lease.id().clone();
                if remaining.is_zero() {
                    let mut guard = state::lock(&self.state);
                    guard.issuer_mut().revoke(&lease_id);
                    guard.release_reservation();
                    return (
                        AuthorizationOutcome::LeaseIssueFailed {
                            error: LeaseError::ExpiryOverflow,
                        },
                        AgentResponse::Error {
                            code: ErrorCode::Internal,
                        },
                    );
                }
                // Mint a DelegationGrant for *every* successful grant
                // (HORO-793) — depth 0/no parent for an ordinary grant,
                // or the delegation verdict's own depth/parent for a
                // delegated one — before `lease` is moved into `insert`
                // below. A no-op when delegation isn't configured, when
                // the peer's owner-uid evidence isn't usable, or when
                // this lease's action isn't delegable under these
                // bounds (`mint` itself returns `None` in that last
                // case).
                if let Some(bounds) = &self.delegation {
                    if let Some(binding) =
                        delegation::grant_binding_from_observed(observed, peer_session_key)
                    {
                        let (depth, parent) = match &delegated {
                            Some(ctx) => (ctx.depth, Some(ctx.parent_lease.clone())),
                            None => (0, None),
                        };
                        if let Some(grant) = eltanin_core::delegation::DelegationGrant::mint(
                            &lease,
                            bounds,
                            observed.workload.clone(),
                            binding.owner_uid,
                            binding.session_key,
                            binding.cgroup_path,
                            depth,
                            parent,
                        ) {
                            delegation_state::lock(&self.delegations).insert(grant);
                        }
                    }
                }
                // `insert` itself releases the reservation this lease
                // was issued under, in the same lock acquisition.
                state::lock(&self.state).insert(lease);
                if let Some(session_id) = matched_session {
                    session_state::lock(&self.sessions)
                        .associate_lease(session_id, lease_id.clone());
                }
                let outcome = match delegated {
                    Some(ctx) => AuthorizationOutcome::GrantedByDelegation {
                        lease_id: lease_id.clone(),
                        expires_at,
                        parent_lease: ctx.parent_lease,
                        depth: ctx.depth,
                        holder_pid: ctx.holder_pid,
                    },
                    None => AuthorizationOutcome::Granted {
                        lease_id: lease_id.clone(),
                        expires_at,
                    },
                };
                (
                    outcome,
                    AgentResponse::LeaseGranted {
                        lease: LeaseView {
                            lease_id,
                            remaining,
                        },
                    },
                )
            }
            Ok(result) => {
                let mut guard = state::lock(&self.state);
                guard.issuer_mut().revoke(lease.id());
                guard.release_reservation();
                (
                    AuthorizationOutcome::EnforcementRefused { result },
                    AgentResponse::Error {
                        code: ErrorCode::Internal,
                    },
                )
            }
            Err(error) => {
                let mut guard = state::lock(&self.state);
                guard.issuer_mut().revoke(lease.id());
                guard.release_reservation();
                (
                    AuthorizationOutcome::BackendFailed { error },
                    AgentResponse::Error {
                        code: ErrorCode::Internal,
                    },
                )
            }
        }
    }

    fn handle_release_lease(
        &self,
        request: &ReleaseRequest,
        peer: &PeerContext,
    ) -> (AuthorizationOutcome, AgentResponse) {
        // Bug fix (HORO-795): see `sweep_expired_leases`'s own doc
        // comment and `handle_request_lease`'s identical call above.
        self.sweep_expired_leases();

        let Some(observed) = peer.authorizable() else {
            return (
                AuthorizationOutcome::PeerNotAuthorizable,
                AgentResponse::LeaseReleased {
                    outcome: ReleaseOutcome::Refused,
                },
            );
        };

        let mut guard = state::lock(&self.state);
        let now = self.clock.now();
        guard.prune(now);

        let Some(stored) = guard.get(&request.lease_id) else {
            drop(guard);
            return (
                AuthorizationOutcome::ReleaseUnknownLease,
                AgentResponse::LeaseReleased {
                    outcome: ReleaseOutcome::Refused,
                },
            );
        };

        let presented = ProvenanceRecord::new(observed.clone(), stored.origin().request.clone());
        let validity = guard.issuer().validate(stored, &presented, now);

        if !matches!(validity, LeaseValidity::Valid { .. }) {
            drop(guard);
            return (
                AuthorizationOutcome::ReleaseRefused { validity },
                AgentResponse::LeaseReleased {
                    outcome: ReleaseOutcome::Refused,
                },
            );
        }

        let id = request.lease_id.clone();
        let resource = stored.origin().request.resource.clone();
        // Checked before removal: this lease is still "live" from the
        // store's point of view until `remove` below.
        let revoke_backend = !guard.any_other_live_lease_for_same_resource(&id);
        let revocation = guard.issuer_mut().revoke(&id);
        guard.remove(&id);

        // The state lock is held across this backend call, deliberately
        // (unlike the grant path's `enforce()`, which runs unlocked):
        // dropping the lock first would open a release-then-acquire
        // race — another thread's concurrent RequestLease for the same
        // resource could pass capacity, issue, enforce, and insert
        // entirely between this release's revoke_backend decision and
        // the actual backend.revoke() call below, and this call would
        // then tear down that thread's freshly-granted, still-live
        // lease's enforcement. Holding the lock here serializes this
        // decide-and-execute sequence against every insert, which also
        // requires this same lock (see state::LeaseState::insert).
        // Bug fix (HORO-795): a real `Err` here used to be `.ok()`'d into
        // `None`, indistinguishable from the legitimate `None` produced
        // by `revoke_backend` being `false` above (another live lease on
        // the same resource, so no teardown was ever attempted). Mapping
        // it to the existing `EnforcementResult::Error` variant instead
        // makes the plumbing honest: this proves nothing about whether a
        // real backend can actually invalidate an already-open device
        // handle, only that a real failure to try is now recorded rather
        // than silently discarded.
        let backend_result = if revoke_backend {
            match self.backend.revoke(&resource) {
                Ok(result) => Some(result),
                Err(error) => Some(EnforcementResult::Error {
                    message: error.to_string(),
                }),
            }
        } else {
            None
        };
        drop(guard);

        // Cascade to every descendant delegated lease (HORO-793) —
        // *after* `guard` is dropped, since this recurses into
        // `revoke_lease_for_session_teardown`, which acquires the same
        // `state` lock itself.
        self.revoke_delegation_descendants(&id);

        (
            AuthorizationOutcome::Released {
                revocation,
                backend: backend_result,
            },
            AgentResponse::LeaseReleased {
                outcome: ReleaseOutcome::Released,
            },
        )
    }

    /// Revoke one lease at the lease-state/backend layer, reusing
    /// exactly `handle_release_lease`'s own
    /// `any_other_live_lease_for_same_resource` rule — called when a
    /// Trusted Compute Session is terminated (explicitly or reaped) and
    /// every lease issued under it must be torn down with it, and
    /// (HORO-793) recursively by [`Self::revoke_delegation_descendants`]
    /// for every lease chained under a revoked delegation grant.
    fn revoke_lease_for_session_teardown(&self, id: &eltanin_core::lease::LeaseId) {
        let mut guard = state::lock(&self.state);
        if guard.get(id).is_none() {
            return;
        }
        let resource = guard
            .get(id)
            .map(|lease| lease.origin().request.resource.clone());
        let Some(resource) = resource else {
            return;
        };
        let revoke_backend = !guard.any_other_live_lease_for_same_resource(id);
        guard.issuer_mut().revoke(id);
        guard.remove(id);
        if revoke_backend {
            let _ = self.backend.revoke(&resource);
        }
        drop(guard);
        self.revoke_delegation_descendants(id);
    }

    /// Remove `id`'s own [`eltanin_core::delegation::DelegationGrant`]
    /// (if any) and recursively cascade-revoke every descendant grant's
    /// lease (F-M2-003, HORO-793, AC4: "revoking parent/session authority
    /// invalidates future delegated lease issue"). Called after `id`'s
    /// own lease has already been revoked/removed at the lease-state
    /// layer — never while `state`'s lock is held, since this recurses
    /// into [`Self::revoke_lease_for_session_teardown`], which acquires
    /// it itself. A no-op when `id` names no stored grant (delegation
    /// not configured, or this lease was never eligible to seed one).
    fn revoke_delegation_descendants(&self, id: &eltanin_core::lease::LeaseId) {
        let removed = delegation_state::lock(&self.delegations).remove_cascade(id);
        for descendant in removed {
            if &descendant != id {
                self.revoke_lease_for_session_teardown(&descendant);
            }
        }
    }

    /// Derive the anchor key / owner uid / scope `handle_create_session`
    /// needs to call `establish`, or the exact early-refusal `(outcome,
    /// response)` pair it should return immediately. Split out only to
    /// stay under this crate's line-count lint — no behavioral seam.
    #[allow(clippy::result_large_err)]
    fn session_establish_inputs(
        observed: &eltanin_core::identity::ExecutionContext,
        resources: &[eltanin_core::resource::ResourceIdentity],
    ) -> Result<
        (eltanin_core::session::SessionKey, u32, SessionScope),
        (AuthorizationOutcome, AgentResponse),
    > {
        // Intent proof (F-M2-001, HORO-791): the requester is the
        // authorizable local peer of this very request — no additional
        // hardware-backed step. See `eltanin_core::session::IntentProof`'s
        // docs for why this is the whole of MVP 2.0's intent model.
        let leader_pid = observed.workload.pid;
        let peer_key = session::collect_session_key(leader_pid);
        let key = match &peer_key {
            Evidence::Present {
                value,
                source: EvidenceSource::SelfAsserted,
            } => {
                let _ = value;
                None
            }
            Evidence::Present { value, .. } => Some(*value),
            Evidence::Missing { .. } | Evidence::Unsupported => None,
        };
        let Some(key) = key else {
            // No usable (kernel-observed, non-self-asserted) session-key
            // evidence for the requesting peer at all — there is no
            // session to anchor. Reported identically to the
            // `peer.authorizable()` gate above: evidence about the
            // requester could not be confirmed, not a policy or session
            // decision.
            return Err((
                AuthorizationOutcome::PeerNotAuthorizable,
                AgentResponse::Error {
                    code: ErrorCode::Internal,
                },
            ));
        };
        let Evidence::Present {
            value: owner_uid, ..
        } = &observed.workload.uid
        else {
            return Err((
                AuthorizationOutcome::PeerNotAuthorizable,
                AgentResponse::Error {
                    code: ErrorCode::Internal,
                },
            ));
        };

        let scope = match SessionScope::new(resources.iter().cloned()) {
            Ok(scope) => scope,
            Err(error) => {
                return Err((
                    AuthorizationOutcome::SessionEstablishFailed {
                        error: SessionAdmissionError::EmptyScope(error),
                    },
                    AgentResponse::Error {
                        code: ErrorCode::Internal,
                    },
                ))
            }
        };

        Ok((key, *owner_uid, scope))
    }

    fn handle_create_session(
        &self,
        request: &CreateSessionRequest,
        peer: &PeerContext,
    ) -> (AuthorizationOutcome, AgentResponse) {
        let Some(observed) = peer.authorizable() else {
            return (
                AuthorizationOutcome::PeerNotAuthorizable,
                AgentResponse::Error {
                    code: ErrorCode::Internal,
                },
            );
        };

        let (key, owner_uid, scope) =
            match Self::session_establish_inputs(observed, &request.resources) {
                Ok(inputs) => inputs,
                Err(response) => return response,
            };

        let anchor = LocalSessionAnchor {
            key,
            leader: observed.workload.clone(),
        };
        let now = self.clock.now();
        let mut sessions = session_state::lock(&self.sessions);
        let reaped = sessions.reap(now, session::collect_workload_identity);
        let established = sessions.authority_mut().establish(
            owner_uid,
            anchor,
            scope,
            IntentProof::LocalPeerPresence,
            SessionAssurance::LocalKernelSession,
            now,
            request.ttl,
        );
        let result = match established {
            Ok(established) => {
                let session_id = established.id().clone();
                let expires_at = established.expires_at();
                let remaining = expires_at.saturating_duration_since(now);
                let resources = established.scope().resources().iter().cloned().collect();
                sessions.insert(established);
                (
                    AuthorizationOutcome::SessionEstablished {
                        session_id: session_id.clone(),
                        expires_at,
                    },
                    AgentResponse::SessionEstablished {
                        session: SessionView {
                            session_id,
                            remaining,
                            resources,
                        },
                    },
                )
            }
            Err(error) => (
                AuthorizationOutcome::SessionEstablishFailed {
                    error: SessionAdmissionError::Authority(error),
                },
                AgentResponse::Error {
                    code: ErrorCode::Internal,
                },
            ),
        };
        drop(sessions);

        // Bug fix (HORO-795): see `membership_for_peer`'s identical
        // cascade — this lazy-reaping call site discarded `reap`'s
        // return value entirely before this fix.
        for (_, lease_ids) in reaped {
            self.cascade_revoke_leases(lease_ids);
        }

        result
    }

    fn handle_list_sessions(
        &self,
        peer: &PeerContext,
    ) -> (AuthorizationOutcome, AgentResponse, Option<SessionId>) {
        let (matched_session, _verdict, _peer_key) = self.membership_for_peer(peer);
        let sessions_guard = session_state::lock(&self.sessions);
        let now = self.clock.now();
        let views: Vec<SessionView> = matched_session
            .as_ref()
            .and_then(|id| sessions_guard.get(id))
            .map(|session| {
                vec![SessionView {
                    session_id: session.id().clone(),
                    remaining: session.expires_at().saturating_duration_since(now),
                    resources: session.scope().resources().iter().cloned().collect(),
                }]
            })
            .unwrap_or_default();
        let ids: Vec<SessionId> = views.iter().map(|v| v.session_id.clone()).collect();
        drop(sessions_guard);
        (
            AuthorizationOutcome::SessionListed { sessions: ids },
            AgentResponse::SessionList { sessions: views },
            matched_session,
        )
    }

    fn handle_terminate_session(
        &self,
        peer: &PeerContext,
    ) -> (AuthorizationOutcome, AgentResponse, Option<SessionId>) {
        let (matched_session, _verdict, _peer_key) = self.membership_for_peer(peer);
        let Some(session_id) = matched_session else {
            return (
                AuthorizationOutcome::SessionNotFound,
                AgentResponse::SessionTerminated {
                    outcome: TerminationOutcome::Refused,
                },
                None,
            );
        };

        let mut sessions = session_state::lock(&self.sessions);
        let removed = sessions.remove(&session_id);
        let outcome = sessions.authority_mut().terminate(&session_id);
        drop(sessions);

        if let Some((_, lease_ids)) = removed {
            self.cascade_revoke_leases(lease_ids);
        }

        let wire_outcome = if matches!(
            outcome,
            eltanin_core::session::SessionTerminationOutcome::Terminated
        ) {
            TerminationOutcome::Terminated
        } else {
            TerminationOutcome::Refused
        };

        (
            AuthorizationOutcome::SessionTerminated { outcome },
            AgentResponse::SessionTerminated {
                outcome: wire_outcome,
            },
            Some(session_id),
        )
    }

    /// Record a remembered-authorization intent (F-M2-002, HORO-792).
    /// Every [`eltanin_core::approval::ApprovalBinding`] dimension is
    /// derived server-side from the peer's own freshly-observed kernel
    /// state — mirroring exactly how `handle_create_session` derives a
    /// session's anchor, never from anything the client sends beyond
    /// `resource`/`action`/`disposition`.
    fn handle_approve(
        &self,
        request: &ApproveRequest,
        peer: &PeerContext,
    ) -> (AuthorizationOutcome, AgentResponse) {
        let Some(observed) = peer.authorizable() else {
            return (
                AuthorizationOutcome::PeerNotAuthorizable,
                AgentResponse::Error {
                    code: ErrorCode::Internal,
                },
            );
        };

        let capabilities = match self.backend.observe(&request.resource) {
            Ok(resource) => resource.capabilities,
            Err(error) => {
                return (
                    AuthorizationOutcome::ApprovalGateObserveFailed { error },
                    AgentResponse::Error {
                        code: ErrorCode::Internal,
                    },
                )
            }
        };
        let policy = self.policy.provenance();

        let Some(binding) = approval::binding_from_observed(observed, capabilities, policy) else {
            return (
                AuthorizationOutcome::PeerNotAuthorizable,
                AgentResponse::Error {
                    code: ErrorCode::Internal,
                },
            );
        };

        let approval = Approval::new(
            binding,
            request.resource.clone(),
            request.action,
            request.disposition,
        );
        let id = approval.id().clone();
        let resource = approval.resource().clone();
        let action = approval.action();
        let disposition = approval.disposition();

        match disposition {
            ApprovalDisposition::Once => {
                let now = self.clock.now();
                let Some(expires_at) = now.checked_add(self.once_approval_ttl) else {
                    return (
                        AuthorizationOutcome::ApprovalInternalError {
                            reason: "monotonic clock overflow computing Once expiry".to_string(),
                        },
                        AgentResponse::Error {
                            code: ErrorCode::Internal,
                        },
                    );
                };
                approval_state::lock(&self.approvals).insert_once(approval, expires_at);
            }
            ApprovalDisposition::Remember | ApprovalDisposition::Deny => {
                let mut guard = approval_state::lock(&self.approvals);
                guard.insert_durable(approval);
                if let Some(path) = &self.approval_store_path {
                    if let Err(save_error) = guard.save(path) {
                        // Roll back: a durable approval that could not
                        // actually be persisted must not be reported as
                        // recorded — a restart would silently lose it.
                        guard.remove(&id);
                        drop(guard);
                        eprintln!(
                            "eltanin-agent: failed to persist approval store {}: {save_error}",
                            path.display()
                        );
                        return (
                            AuthorizationOutcome::ApprovalInternalError {
                                reason: save_error.to_string(),
                            },
                            AgentResponse::Error {
                                code: ErrorCode::Internal,
                            },
                        );
                    }
                }
            }
        }

        (
            AuthorizationOutcome::ApprovalRecorded {
                id: id.clone(),
                resource: resource.clone(),
                action,
                disposition,
            },
            AgentResponse::ApprovalRecorded {
                approval: ApprovalView {
                    id,
                    resource,
                    action,
                    disposition,
                },
            },
        )
    }

    /// List the calling peer's **own** recorded approvals — never
    /// another owner's.
    fn handle_list_approvals(&self, peer: &PeerContext) -> (AuthorizationOutcome, AgentResponse) {
        let Some(observed) = peer.authorizable() else {
            return (
                AuthorizationOutcome::PeerNotAuthorizable,
                AgentResponse::Error {
                    code: ErrorCode::Internal,
                },
            );
        };
        let Evidence::Present { value: uid, .. } = &observed.workload.uid else {
            return (
                AuthorizationOutcome::PeerNotAuthorizable,
                AgentResponse::Error {
                    code: ErrorCode::Internal,
                },
            );
        };

        let now = self.clock.now();
        let mut guard = approval_state::lock(&self.approvals);
        guard.reap_once(now);
        let views: Vec<ApprovalView> = guard
            .owned_by(*uid)
            .into_iter()
            .map(|approval| ApprovalView {
                id: approval.id().clone(),
                resource: approval.resource().clone(),
                action: approval.action(),
                disposition: approval.disposition(),
            })
            .collect();
        drop(guard);
        let ids: Vec<ApprovalId> = views.iter().map(|v| v.id.clone()).collect();

        (
            AuthorizationOutcome::ApprovalListed { approvals: ids },
            AgentResponse::ApprovalList { approvals: views },
        )
    }

    fn handle_forget_approval(
        &self,
        request: &ForgetApprovalRequest,
        peer: &PeerContext,
    ) -> (AuthorizationOutcome, AgentResponse) {
        let refused = (
            AuthorizationOutcome::ApprovalForgotten { forgotten: false },
            AgentResponse::ApprovalForgotten {
                outcome: ForgetOutcome::Refused,
            },
        );

        let Some(observed) = peer.authorizable() else {
            return refused;
        };
        let Evidence::Present { value: uid, .. } = &observed.workload.uid else {
            return refused;
        };

        let mut guard = approval_state::lock(&self.approvals);
        let Some(existing) = guard.get(&request.id) else {
            drop(guard);
            return refused;
        };
        if existing.binding().owner_uid != *uid {
            drop(guard);
            return refused;
        }
        let was_durable = !matches!(existing.disposition(), ApprovalDisposition::Once);
        let removed = guard.remove(&request.id);
        if removed && was_durable {
            if let Some(path) = &self.approval_store_path {
                if let Err(save_error) = guard.save(path) {
                    eprintln!(
                        "eltanin-agent: failed to persist approval store {} after forget: \
                         {save_error}",
                        path.display()
                    );
                }
            }
        }
        drop(guard);

        (
            AuthorizationOutcome::ApprovalForgotten { forgotten: removed },
            AgentResponse::ApprovalForgotten {
                outcome: if removed {
                    ForgetOutcome::Forgotten
                } else {
                    ForgetOutcome::Refused
                },
            },
        )
    }
}

impl RequestHandler for AuthorizationHandler {
    fn handle(&self, request: &ClientRequest, peer: &PeerContext) -> AgentResponse {
        let (operation, outcome, response, session) = match request {
            ClientRequest::AgentStatus {} => {
                let (outcome, response) = self.handle_status();
                (Operation::AgentStatus, outcome, response, None)
            }
            ClientRequest::RequestLease(lease_request) => {
                let (outcome, response, session) = self.handle_request_lease(lease_request, peer);
                (Operation::RequestLease, outcome, response, session)
            }
            ClientRequest::ReleaseLease(release_request) => {
                let (outcome, response) = self.handle_release_lease(release_request, peer);
                (Operation::ReleaseLease, outcome, response, None)
            }
            ClientRequest::CreateSession(create_request) => {
                let (outcome, response) = self.handle_create_session(create_request, peer);
                (Operation::CreateSession, outcome, response, None)
            }
            ClientRequest::ListSessions {} => {
                let (outcome, response, session) = self.handle_list_sessions(peer);
                (Operation::ListSessions, outcome, response, session)
            }
            ClientRequest::TerminateSession {} => {
                let (outcome, response, session) = self.handle_terminate_session(peer);
                (Operation::TerminateSession, outcome, response, session)
            }
            ClientRequest::Approve(approve_request) => {
                let (outcome, response) = self.handle_approve(approve_request, peer);
                (Operation::Approve, outcome, response, None)
            }
            ClientRequest::ListApprovals {} => {
                let (outcome, response) = self.handle_list_approvals(peer);
                (Operation::ListApprovals, outcome, response, None)
            }
            ClientRequest::ForgetApproval(forget_request) => {
                let (outcome, response) = self.handle_forget_approval(forget_request, peer);
                (Operation::ForgetApproval, outcome, response, None)
            }
        };

        self.sink.record(&AuthorizationEvent {
            operation,
            request,
            peer,
            outcome: &outcome,
            response: &response,
            session,
            mode: self.enforcement_mode,
        });

        response
    }
}
