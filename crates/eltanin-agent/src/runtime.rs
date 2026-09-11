//! Clock and issuer-identity adapters (F-M1-006, HORO-839).
//!
//! `eltanin-core::lease` explicitly assigns clock ownership to
//! "whichever crate actually owns a clock (F-M1-006's agent)" and
//! `IssuerInstanceId` derivation to "the issuing agent's own
//! kernel-observed pid/`ProcessStartToken`, never a hardcoded
//! constant." This module is where those two named obligations are
//! actually discharged.

use std::time::Instant;

use eltanin_core::identity::Evidence;
use eltanin_core::lease::{IssuerInstanceId, MonotonicTime};

/// Adapts [`Instant`] (cannot be constructed at a chosen value or
/// serialized) to [`MonotonicTime`] (can be both) by capturing one base
/// `Instant` at construction and reporting nanosecond offsets from it —
/// exactly the six-line adapter `lease.rs`'s module docs describe as
/// belonging to "whichever crate actually owns a clock."
pub struct AgentClock {
    base: Instant,
}

impl AgentClock {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
        }
    }

    /// The current instant, as a [`MonotonicTime`] reading meaningful
    /// only to [`crate::runtime::issuer_instance_id`]'s
    /// `IssuerInstanceId` for this process's lifetime — see
    /// `MonotonicTime`'s own docs.
    #[must_use]
    pub fn now(&self) -> MonotonicTime {
        MonotonicTime::from_nanos(u64::try_from(self.base.elapsed().as_nanos()).unwrap_or(u64::MAX))
    }
}

impl Default for AgentClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Why [`issuer_instance_id`] could not derive an instance id.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstanceIdError {
    #[error(
        "this process's own start token is not kernel-observed ({reason}) — refusing to mint \
         a degenerate restart epoch"
    )]
    StartTokenUnavailable { reason: String },
}

/// Derive this agent instance's restart epoch from its own
/// kernel-observed pid + `ProcessStartToken`, per `lease.rs`'s explicit
/// requirement ("never a hardcoded constant" — grounding the restart
/// epoch in kernel-observed state is what prevents leases from silently
/// surviving a restart). Fails closed rather than falling back to a
/// weaker id when the start token itself is `Missing`/`Unsupported`:
/// a degenerate instance id would silently weaken every `ForeignIssuer`
/// check this crate depends on for restart safety.
///
/// # Errors
///
/// Returns [`InstanceIdError::StartTokenUnavailable`] when this
/// process's own `/proc`-observed start token is not
/// [`Evidence::Present`].
pub fn issuer_instance_id() -> Result<IssuerInstanceId, InstanceIdError> {
    let pid = std::process::id();
    let identity = eltanin_linux::collect_workload_identity(pid);
    match identity.process_start {
        Evidence::Present { value, .. } => Ok(IssuerInstanceId::new(format!(
            "agent-pid-{pid}-start-{}",
            value.0
        ))),
        Evidence::Missing { reason } => Err(InstanceIdError::StartTokenUnavailable { reason }),
        Evidence::Unsupported => Err(InstanceIdError::StartTokenUnavailable {
            reason: "process start token collection is unsupported on this platform".into(),
        }),
    }
}
