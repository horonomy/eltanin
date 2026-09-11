//! [`EventSink`] adapter writing to a real, persistent audit log
//! (F-M1-009, HORO-824).
//!
//! Converts this crate's [`AuthorizationEvent`] and
//! `eltanin_linux::peer` types into `eltanin-audit`'s plain,
//! `Deserialize`-safe `Recorded*` mirrors — `eltanin-audit` cannot
//! depend on `eltanin-linux` or `eltanin-agent` (see its own crate
//! docs), so this conversion lives here, agent-side.
//!
//! # Durability is best-effort — by explicit founder decision
//!
//! [`AuditEventSink::record`] never changes the response
//! [`crate::handler::RequestHandler::handle`] has already computed:
//! a write failure is logged to stderr (captured by `journald`/systemd)
//! and [`AuditFileSink::failed_writes`] is incremented, but the
//! already-decided ALLOW/DENY/release outcome is unaffected. Reopening
//! `EventSink::record`'s `-> ()` signature to make audit I/O
//! authoritative was explicitly rejected — "audit is evidence, not
//! authority" (HORO-824's own AC) forbids exactly that coupling. See
//! `eltanin-audit`'s `sink` module docs for how a write failure still
//! leaves a detectable, honest trace (a sequence gap) rather than a
//! silently reused id.

use std::path::Path;

use eltanin_audit::record::{
    AuditClock, RecordedDecisionReason, RecordedLeaseError, RecordedLeaseValidity,
    RecordedOperation, RecordedOutcome, RecordedPeer, RecordedPeerConsistency,
    RecordedPeerCredential, RecordedPolicyDecision, RecordedPolicyProvenance, RecordedRequest,
};
use eltanin_audit::sink::{AuditEntry, AuditFileSink, AuditSinkError};
use eltanin_core::lease::{IssuerInstanceId, LeaseError, LeaseValidity};
use eltanin_core::policy::{DecisionReason, PolicyDecision, PolicyProvenance};
use eltanin_linux::peer::{PeerConsistency, PeerContext, PeerCredential};
use eltanin_protocol::request::ClientRequest;

use super::event::{AuthorizationEvent, AuthorizationOutcome, EventSink, Operation};

fn recorded_operation(operation: Operation) -> RecordedOperation {
    match operation {
        Operation::RequestLease => RecordedOperation::RequestLease,
        Operation::ReleaseLease => RecordedOperation::ReleaseLease,
        Operation::AgentStatus => RecordedOperation::AgentStatus,
    }
}

fn recorded_request(request: &ClientRequest) -> RecordedRequest {
    match request {
        ClientRequest::RequestLease(r) => RecordedRequest::RequestLease {
            resource: r.resource.clone(),
            action: r.action,
        },
        ClientRequest::ReleaseLease(r) => RecordedRequest::ReleaseLease {
            lease_id: r.lease_id.clone(),
        },
        ClientRequest::AgentStatus {} => RecordedRequest::AgentStatus,
    }
}

fn recorded_peer_credential(credential: &PeerCredential) -> RecordedPeerCredential {
    RecordedPeerCredential {
        pid: credential.pid(),
        effective_uid: credential.effective_uid(),
        effective_gid: credential.effective_gid(),
    }
}

fn recorded_peer_consistency(consistency: &PeerConsistency) -> RecordedPeerConsistency {
    match consistency.clone() {
        PeerConsistency::Consistent => RecordedPeerConsistency::Consistent,
        PeerConsistency::CredentialDivergence {
            peer_effective_uid,
            observed_real_uid,
            observed_effective_uid,
        } => RecordedPeerConsistency::CredentialDivergence {
            peer_effective_uid,
            observed_real_uid,
            observed_effective_uid,
        },
        PeerConsistency::PeerUnmapped => RecordedPeerConsistency::PeerUnmapped,
        PeerConsistency::Indeterminate { reason } => {
            RecordedPeerConsistency::Indeterminate { reason }
        }
    }
}

fn recorded_peer(peer: &PeerContext) -> RecordedPeer {
    RecordedPeer {
        credential: recorded_peer_credential(peer.credential()),
        consistency: recorded_peer_consistency(peer.consistency()),
        observed: peer.observed().clone(),
    }
}

fn recorded_policy_provenance(policy: &PolicyProvenance) -> RecordedPolicyProvenance {
    RecordedPolicyProvenance {
        policy_id: policy.policy_id.clone(),
        policy_revision: policy.policy_revision,
        schema_version: policy.schema_version,
    }
}

fn recorded_decision_reason(reason: &DecisionReason) -> RecordedDecisionReason {
    match reason.clone() {
        DecisionReason::NoMatchingRule => RecordedDecisionReason::NoMatchingRule,
        DecisionReason::ExplicitAllow { matched_rules } => {
            RecordedDecisionReason::ExplicitAllow { matched_rules }
        }
        DecisionReason::ExplicitDeny {
            matched_rules,
            overridden_allow_rules,
        } => RecordedDecisionReason::ExplicitDeny {
            matched_rules,
            overridden_allow_rules,
        },
        DecisionReason::IndeterminateEvidence { rules } => {
            RecordedDecisionReason::IndeterminateEvidence { rules }
        }
    }
}

fn recorded_policy_decision(decision: &PolicyDecision) -> RecordedPolicyDecision {
    RecordedPolicyDecision {
        effect: decision.effect(),
        reason: recorded_decision_reason(decision.reason()),
        policy: recorded_policy_provenance(decision.policy()),
    }
}

fn recorded_lease_error(error: &LeaseError) -> RecordedLeaseError {
    match error.clone() {
        LeaseError::Denied { decision } => RecordedLeaseError::Denied {
            decision: recorded_policy_decision(&decision),
        },
        LeaseError::NonPositiveTtl => RecordedLeaseError::NonPositiveTtl,
        LeaseError::TtlExceedsMaximum { requested, maximum } => {
            RecordedLeaseError::TtlExceedsMaximum { requested, maximum }
        }
        LeaseError::ExpiryOverflow => RecordedLeaseError::ExpiryOverflow,
    }
}

fn recorded_lease_validity(validity: &LeaseValidity) -> RecordedLeaseValidity {
    match validity.clone() {
        LeaseValidity::Valid { remaining } => RecordedLeaseValidity::Valid { remaining },
        LeaseValidity::ForeignIssuer { issued_by } => {
            RecordedLeaseValidity::ForeignIssuer { issued_by }
        }
        LeaseValidity::Revoked => RecordedLeaseValidity::Revoked,
        LeaseValidity::ResourceMismatch => RecordedLeaseValidity::ResourceMismatch,
        LeaseValidity::ActionMismatch => RecordedLeaseValidity::ActionMismatch,
        LeaseValidity::WorkloadMismatch => RecordedLeaseValidity::WorkloadMismatch,
        LeaseValidity::WorkloadIndeterminate => RecordedLeaseValidity::WorkloadIndeterminate,
        LeaseValidity::ExecutableMismatch => RecordedLeaseValidity::ExecutableMismatch,
        LeaseValidity::Expired { expired_at } => RecordedLeaseValidity::Expired { expired_at },
    }
}

fn recorded_outcome(outcome: &AuthorizationOutcome) -> RecordedOutcome {
    match outcome.clone() {
        AuthorizationOutcome::Granted {
            lease_id,
            expires_at,
        } => RecordedOutcome::Granted {
            lease_id,
            expires_at,
        },
        AuthorizationOutcome::PolicyDenied { decision } => RecordedOutcome::PolicyDenied {
            decision: recorded_policy_decision(&decision),
        },
        AuthorizationOutcome::PeerNotAuthorizable => RecordedOutcome::PeerNotAuthorizable,
        AuthorizationOutcome::LeaseIssueFailed { error } => RecordedOutcome::LeaseIssueFailed {
            error: recorded_lease_error(&error),
        },
        AuthorizationOutcome::EnforcementRefused { result } => {
            RecordedOutcome::EnforcementRefused { result }
        }
        AuthorizationOutcome::BackendFailed { error } => RecordedOutcome::BackendFailed { error },
        AuthorizationOutcome::CapacityExhausted { outstanding } => {
            RecordedOutcome::CapacityExhausted { outstanding }
        }
        AuthorizationOutcome::Released {
            revocation,
            backend,
        } => RecordedOutcome::Released {
            revocation,
            backend,
        },
        AuthorizationOutcome::ReleaseRefused { validity } => RecordedOutcome::ReleaseRefused {
            validity: recorded_lease_validity(&validity),
        },
        AuthorizationOutcome::ReleaseUnknownLease => RecordedOutcome::ReleaseUnknownLease,
        AuthorizationOutcome::StatusReported => RecordedOutcome::StatusReported,
    }
}

/// An [`EventSink`] backed by a real, append-only audit log.
pub struct AuditEventSink {
    inner: AuditFileSink,
}

impl AuditEventSink {
    /// Open (creating if absent) the audit log at `path` for `instance`.
    ///
    /// # Errors
    ///
    /// Returns [`AuditSinkError`] if `path` cannot be opened.
    pub fn open(path: &Path, instance: IssuerInstanceId) -> Result<Self, AuditSinkError> {
        Ok(Self {
            inner: AuditFileSink::open(path, instance)?,
        })
    }

    /// Override the audit clock — tests only.
    #[must_use]
    pub fn with_clock(mut self, clock: std::sync::Arc<dyn AuditClock>) -> Self {
        self.inner = self.inner.with_clock(clock);
        self
    }

    /// Build a sink over an arbitrary [`std::io::Write`] — tests only,
    /// e.g. to inject a writer that reliably fails, proving best-effort
    /// durability without relying on a filesystem race.
    #[must_use]
    pub fn from_writer(
        writer: impl std::io::Write + Send + 'static,
        instance: IssuerInstanceId,
    ) -> Self {
        Self {
            inner: AuditFileSink::from_writer(writer, instance),
        }
    }

    /// How many audit writes have failed so far — see this module's
    /// docs on best-effort durability.
    #[must_use]
    pub fn failed_writes(&self) -> u64 {
        self.inner.failed_writes()
    }
}

impl EventSink for AuditEventSink {
    fn record(&self, event: &AuthorizationEvent<'_>) {
        let entry = AuditEntry {
            operation: recorded_operation(event.operation),
            requested: recorded_request(event.request),
            peer: recorded_peer(event.peer),
            outcome: recorded_outcome(event.outcome),
            response: event.response.clone(),
        };
        if let Err(error) = self.inner.append(entry) {
            // Best-effort, by explicit founder decision (this module's
            // own docs): logged loudly, never fed back into the
            // already-computed response.
            eprintln!(
                "eltanin-agent: audit write failed (failed_writes={}): {error}",
                self.inner.failed_writes()
            );
        }
    }
}
