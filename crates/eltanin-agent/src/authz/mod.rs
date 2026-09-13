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

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eltanin_backend::contract::ComputeBackend;
use eltanin_core::envelope::Versioned;
use eltanin_core::identity::{Evidence, EvidenceSource};
use eltanin_core::lease::{
    IssuerInstanceId, LeaseError, LeaseIssuer, LeaseValidity, MonotonicTime,
};
use eltanin_core::peer::PeerContext;
use eltanin_core::policy::{DecisionReason, PolicyDocument, PolicyError, PolicySet};
use eltanin_core::provenance::ProvenanceRecord;
use eltanin_core::resource::EnforcementResult;
use eltanin_core::session::{
    membership, IntentProof, LocalSessionAnchor, MembershipVerdict, SessionAssurance,
    SessionAuthority, SessionId, SessionScope,
};
use eltanin_protocol::request::{
    provenance_for, ClientRequest, CreateSessionRequest, LeaseRequest, ReleaseRequest,
};
use eltanin_protocol::response::{
    AgentResponse, AgentStatusView, DenialReason, ErrorCode, LeaseView, ReleaseOutcome,
    SessionView, TerminationOutcome,
};

use crate::handler::RequestHandler;
use crate::runtime::AgentClock;

pub mod audit;
pub mod event;
pub mod session;
mod session_state;
mod state;

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
}

const DEFAULT_MAX_OUTSTANDING_LEASES: usize = 1024;

/// Default maximum Trusted Compute Session TTL when a deployment does
/// not opt into a narrower one via [`AuthorizationConfig::with_max_session_ttl`].
/// A heavy developer session is meant to last "hours," per the ticket's
/// own user outcome statement — eight hours is a generous single
/// working day, not an attempt to guess an exact number.
const DEFAULT_MAX_SESSION_TTL: Duration = Duration::from_hours(8);

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
            session_requirement: SessionRequirement::NotRequired,
            max_session_ttl: DEFAULT_MAX_SESSION_TTL,
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
    policy: PolicySet,
    backend: Arc<dyn ComputeBackend>,
    clock: Arc<dyn Clock>,
    sink: Arc<dyn EventSink>,
    lease_ttl: Duration,
    max_outstanding_leases: usize,
    session_requirement: SessionRequirement,
}

impl AuthorizationHandler {
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
        Self {
            state: Mutex::new(LeaseState::new(issuer, config.max_outstanding_leases)),
            sessions: Mutex::new(SessionState::new(session_authority)),
            policy,
            backend,
            clock,
            sink,
            lease_ttl: config.lease_ttl,
            max_outstanding_leases: config.max_outstanding_leases,
            session_requirement: config.session_requirement,
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

    fn handle_status() -> (AuthorizationOutcome, AgentResponse) {
        (
            AuthorizationOutcome::StatusReported,
            AgentResponse::Status {
                status: AgentStatusView {
                    protocol_version: eltanin_core::envelope::DOMAIN_SCHEMA_VERSION,
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
    /// session can both use this one evaluation.
    fn membership_for_peer(&self, peer: &PeerContext) -> (Option<SessionId>, MembershipVerdict) {
        let now = self.clock.now();
        let mut sessions = session_state::lock(&self.sessions);
        sessions.reap(now, session::collect_workload_identity);

        let pid = peer.observed().workload.pid;
        let peer_key = session::collect_session_key(pid);
        let Some(candidate) = (match &peer_key {
            Evidence::Present { value, .. } => sessions.find_by_key(*value),
            Evidence::Missing { .. } | Evidence::Unsupported => None,
        }) else {
            return (
                None,
                MembershipVerdict::Indeterminate {
                    reason: "no session found for this peer's session key".to_string(),
                },
            );
        };

        let leader = session::collect_workload_identity(candidate.anchor().leader.pid);
        let verdict = membership(candidate, &peer_key, &leader);
        let matched = matches!(verdict, MembershipVerdict::Member).then(|| candidate.id().clone());
        (matched, verdict)
    }

    fn handle_request_lease(
        &self,
        request: &LeaseRequest,
        peer: &PeerContext,
    ) -> (AuthorizationOutcome, AgentResponse) {
        let Some(observed) = peer.authorizable() else {
            return (
                AuthorizationOutcome::PeerNotAuthorizable,
                AgentResponse::LeaseDenied {
                    reason: DenialReason::IndeterminateEvidence,
                },
            );
        };

        // Pre-policy session-admission gate (F-M2-001, HORO-791): runs
        // *before* policy is ever consulted, so a session-membership
        // denial is never reported as a policy decision — same
        // structural placement as the `peer.authorizable()` gate just
        // above. `matched_session` is threaded through to the grant
        // path below regardless of `session_requirement`, so a lease
        // issued while a session happens to be active gets associated
        // with it (for session-termination revocation) even when that
        // session was not required for admission.
        let (matched_session, verdict) = self.membership_for_peer(peer);
        if self.session_requirement == SessionRequirement::Required
            && !matches!(verdict, MembershipVerdict::Member)
        {
            return (
                AuthorizationOutcome::SessionRequired,
                AgentResponse::LeaseDenied {
                    reason: DenialReason::NoTrustedSession,
                },
            );
        }

        let provenance = provenance_for(request, observed.clone());

        let lease = match self.issue_reserving_capacity(provenance) {
            Ok(lease) => lease,
            Err(IssueFailure::CapacityExhausted { outstanding }) => {
                return (
                    AuthorizationOutcome::CapacityExhausted { outstanding },
                    AgentResponse::Error {
                        code: ErrorCode::Internal,
                    },
                )
            }
            Err(IssueFailure::Denied(decision)) => {
                let reason = denial_reason_for(decision.reason());
                return (
                    AuthorizationOutcome::PolicyDenied { decision },
                    AgentResponse::LeaseDenied { reason },
                );
            }
            Err(IssueFailure::Other(error)) => {
                return (
                    AuthorizationOutcome::LeaseIssueFailed { error },
                    AgentResponse::Error {
                        code: ErrorCode::Internal,
                    },
                )
            }
        };

        self.enforce_and_finalize(lease, matched_session.as_ref())
    }

    /// The grant-path tail of `handle_request_lease`, split out only to
    /// stay under this crate's line-count lint — no behavioral seam.
    /// `matched_session`, when present, is the session this lease
    /// should be associated with for later termination-triggered
    /// revocation (see `handle_request_lease`'s own doc comment on why
    /// this happens regardless of `session_requirement`).
    fn enforce_and_finalize(
        &self,
        lease: eltanin_core::lease::ComputeLease,
        matched_session: Option<&SessionId>,
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
                // `insert` itself releases the reservation this lease
                // was issued under, in the same lock acquisition.
                state::lock(&self.state).insert(lease);
                if let Some(session_id) = matched_session {
                    session_state::lock(&self.sessions)
                        .associate_lease(session_id, lease_id.clone());
                }
                (
                    AuthorizationOutcome::Granted {
                        lease_id: lease_id.clone(),
                        expires_at,
                    },
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
        let backend_result = if revoke_backend {
            self.backend.revoke(&resource).ok()
        } else {
            None
        };
        drop(guard);

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
    /// every lease issued under it must be torn down with it.
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
            return (
                AuthorizationOutcome::PeerNotAuthorizable,
                AgentResponse::Error {
                    code: ErrorCode::Internal,
                },
            );
        };
        let Evidence::Present {
            value: owner_uid, ..
        } = &observed.workload.uid
        else {
            return (
                AuthorizationOutcome::PeerNotAuthorizable,
                AgentResponse::Error {
                    code: ErrorCode::Internal,
                },
            );
        };

        let scope = match SessionScope::new(request.resources.iter().cloned()) {
            Ok(scope) => scope,
            Err(error) => {
                return (
                    AuthorizationOutcome::SessionEstablishFailed {
                        error: SessionAdmissionError::EmptyScope(error),
                    },
                    AgentResponse::Error {
                        code: ErrorCode::Internal,
                    },
                )
            }
        };

        let anchor = LocalSessionAnchor {
            key,
            leader: observed.workload.clone(),
        };
        let now = self.clock.now();
        let mut sessions = session_state::lock(&self.sessions);
        sessions.reap(now, session::collect_workload_identity);
        let established = sessions.authority_mut().establish(
            *owner_uid,
            anchor,
            scope,
            IntentProof::LocalPeerPresence,
            SessionAssurance::LocalKernelSession,
            now,
            request.ttl,
        );
        match established {
            Ok(established) => {
                let session_id = established.id().clone();
                let expires_at = established.expires_at();
                let remaining = expires_at.saturating_duration_since(now);
                let resources = established.scope().resources().iter().cloned().collect();
                sessions.insert(established);
                drop(sessions);
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
        }
    }

    fn handle_list_sessions(&self, peer: &PeerContext) -> (AuthorizationOutcome, AgentResponse) {
        let (matched_session, _verdict) = self.membership_for_peer(peer);
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
        )
    }

    fn handle_terminate_session(
        &self,
        peer: &PeerContext,
    ) -> (AuthorizationOutcome, AgentResponse) {
        let (matched_session, _verdict) = self.membership_for_peer(peer);
        let Some(session_id) = matched_session else {
            return (
                AuthorizationOutcome::SessionNotFound,
                AgentResponse::SessionTerminated {
                    outcome: TerminationOutcome::Refused,
                },
            );
        };

        let mut sessions = session_state::lock(&self.sessions);
        let removed = sessions.remove(&session_id);
        let outcome = sessions.authority_mut().terminate(&session_id);
        drop(sessions);

        if let Some((_, lease_ids)) = removed {
            for lease_id in lease_ids {
                self.revoke_lease_for_session_teardown(&lease_id);
            }
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
        )
    }
}

impl RequestHandler for AuthorizationHandler {
    fn handle(&self, request: &ClientRequest, peer: &PeerContext) -> AgentResponse {
        let (operation, outcome, response) = match request {
            ClientRequest::AgentStatus {} => {
                let (outcome, response) = Self::handle_status();
                (Operation::AgentStatus, outcome, response)
            }
            ClientRequest::RequestLease(lease_request) => {
                let (outcome, response) = self.handle_request_lease(lease_request, peer);
                (Operation::RequestLease, outcome, response)
            }
            ClientRequest::ReleaseLease(release_request) => {
                let (outcome, response) = self.handle_release_lease(release_request, peer);
                (Operation::ReleaseLease, outcome, response)
            }
            ClientRequest::CreateSession(create_request) => {
                let (outcome, response) = self.handle_create_session(create_request, peer);
                (Operation::CreateSession, outcome, response)
            }
            ClientRequest::ListSessions {} => {
                let (outcome, response) = self.handle_list_sessions(peer);
                (Operation::ListSessions, outcome, response)
            }
            ClientRequest::TerminateSession {} => {
                let (outcome, response) = self.handle_terminate_session(peer);
                (Operation::TerminateSession, outcome, response)
            }
        };

        self.sink.record(&AuthorizationEvent {
            operation,
            request,
            peer,
            outcome: &outcome,
            response: &response,
        });

        response
    }
}
