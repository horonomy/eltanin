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
//! `LeaseDenied` if and only if `PolicySet::evaluate` itself produced
//! `Effect::Deny`. Every other non-grant condition (backend failure,
//! enforcement refusal, capacity exhaustion, a structurally-unreachable
//! lease error) maps to `Error { Internal }` — "no policy backend
//! decided this" must never be reported as if policy had denied it,
//! continuing the same reasoning `handler.rs`'s `StatusOnlyHandler` docs
//! already state for "no policy backend in this build."
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
//! `now` is read from [`Clock`] exactly once per lock acquisition, after
//! the lock is held, never before — this is how `eltanin_core::lease`'s
//! named obligation ("monotonicity across successive `issue` calls is
//! F-M1-006's obligation as sole owner of the clock") is discharged: two
//! concurrent `RequestLease` calls cannot observe `now` out of order
//! relative to the sequence their `issue` calls actually execute in,
//! because both the clock read and the `issue` call happen under the
//! same [`std::sync::Mutex`].

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eltanin_backend::contract::ComputeBackend;
use eltanin_core::envelope::Versioned;
use eltanin_core::lease::{
    IssuerInstanceId, LeaseError, LeaseIssuer, LeaseValidity, MonotonicTime,
};
use eltanin_core::policy::{DecisionReason, PolicyDocument, PolicyError, PolicySet};
use eltanin_core::provenance::ProvenanceRecord;
use eltanin_core::resource::EnforcementResult;
use eltanin_linux::peer::PeerContext;
use eltanin_protocol::request::{provenance_for, ClientRequest, LeaseRequest, ReleaseRequest};
use eltanin_protocol::response::{
    AgentResponse, AgentStatusView, DenialReason, ErrorCode, LeaseView, ReleaseOutcome,
};

use crate::handler::RequestHandler;
use crate::runtime::AgentClock;

pub mod event;
mod state;

use event::{AuthorizationEvent, AuthorizationOutcome, EventSink, Operation};
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
}

const DEFAULT_MAX_OUTSTANDING_LEASES: usize = 1024;

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
        })
    }

    #[must_use]
    pub fn with_max_outstanding_leases(mut self, max: usize) -> Self {
        self.max_outstanding_leases = max;
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

/// Implements [`RequestHandler`] by wiring policy evaluation, lease
/// issue/release, and backend enforcement together. Shared across
/// concurrently-served connections (`Arc<dyn RequestHandler>`); internal
/// mutable state is a single `Mutex<LeaseState>`, recovered rather than
/// propagated on poison — see `state::lock`'s own doc comment.
pub struct AuthorizationHandler {
    state: Mutex<LeaseState>,
    policy: PolicySet,
    backend: Arc<dyn ComputeBackend>,
    clock: Arc<dyn Clock>,
    sink: Arc<dyn EventSink>,
    lease_ttl: Duration,
    max_outstanding_leases: usize,
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
        let issuer = LeaseIssuer::new(instance, config.lease_ttl);
        Self {
            state: Mutex::new(LeaseState::new(issuer, config.max_outstanding_leases)),
            policy,
            backend,
            clock,
            sink,
            lease_ttl: config.lease_ttl,
            max_outstanding_leases: config.max_outstanding_leases,
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
        let provenance = provenance_for(request, observed.clone());

        let issued = {
            let mut guard = state::lock(&self.state);
            let now = self.clock.now();
            guard.prune(now);
            if guard.is_at_capacity() {
                drop(guard);
                return (
                    AuthorizationOutcome::CapacityExhausted {
                        outstanding: self.max_outstanding_leases,
                    },
                    AgentResponse::Error {
                        code: ErrorCode::Internal,
                    },
                );
            }
            guard
                .issuer_mut()
                .issue(&self.policy, provenance, now, self.lease_ttl)
        };

        let lease = match issued {
            Ok(lease) => lease,
            Err(LeaseError::Denied { decision }) => {
                let reason = denial_reason_for(decision.reason());
                return (
                    AuthorizationOutcome::PolicyDenied { decision },
                    AgentResponse::LeaseDenied { reason },
                );
            }
            Err(error) => {
                return (
                    AuthorizationOutcome::LeaseIssueFailed { error },
                    AgentResponse::Error {
                        code: ErrorCode::Internal,
                    },
                )
            }
        };

        match self.backend.enforce(&lease.origin().request) {
            Ok(EnforcementResult::Allowed) => {
                let expires_at = lease.expires_at();
                let remaining = expires_at.saturating_duration_since(self.clock.now());
                let lease_id = lease.id().clone();
                if remaining.is_zero() {
                    state::lock(&self.state).issuer_mut().revoke(&lease_id);
                    return (
                        AuthorizationOutcome::LeaseIssueFailed {
                            error: LeaseError::ExpiryOverflow,
                        },
                        AgentResponse::Error {
                            code: ErrorCode::Internal,
                        },
                    );
                }
                state::lock(&self.state).insert(lease);
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
                state::lock(&self.state).issuer_mut().revoke(lease.id());
                (
                    AuthorizationOutcome::EnforcementRefused { result },
                    AgentResponse::Error {
                        code: ErrorCode::Internal,
                    },
                )
            }
            Err(error) => {
                state::lock(&self.state).issuer_mut().revoke(lease.id());
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
        drop(guard);

        let backend_result = if revoke_backend {
            self.backend.revoke(&resource).ok()
        } else {
            None
        };

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
        };

        self.sink.record(&AuthorizationEvent {
            operation,
            peer,
            outcome: &outcome,
            response: &response,
        });

        response
    }
}
