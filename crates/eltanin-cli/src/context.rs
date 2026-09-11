//! The governed execution context seam (S2/S10, F-M1-008, HORO-846).
//!
//! `ComputeBackend::enforce()` takes no process or cgroup parameter —
//! the only channel by which the agent can learn a workload's governed
//! scope, without a protocol change, is the connecting peer's own
//! observed cgroup path. So the scope must exist, and `eltanin run` must
//! already be inside it, *before* it connects (S2, before S3) — see
//! `docs/product/CLI_CONTRACT.md`'s launch state machine for the full
//! reasoning.
//!
//! MVP 1.0 has no real cgroup mechanics (F-M1-007 is not started; only
//! `eltanin-backend`'s `FakeBackend` exists), so [`NullContext`] is the
//! only implementation: establishing and tearing down the "governed
//! context" are both no-ops. This trait is the seam F-M1-007 fills in
//! later, mirroring this codebase's established trait-plus-null-impl
//! convention (`eltanin_agent::authz::event::NullSink`,
//! `eltanin_agent::peer::PeerContextSource`).

/// Establish and tear down a workload's governed execution context.
pub trait GovernedContext {
    /// Establish the context (S2), before connecting to the agent.
    ///
    /// # Errors
    ///
    /// Returns [`GovernedContextError`] if the context cannot be
    /// established.
    fn establish(&self) -> Result<(), GovernedContextError>;

    /// Tear down the context (S10), after the lease has been released
    /// (S9). A teardown failure is a stderr warning, never a change to
    /// the workload's exit status — the exit-code taxonomy assigns
    /// [`crate::exit::ExitCode::GovernedContextFailed`] only to a
    /// failure to *establish*, mirroring S9's release-failure rule.
    ///
    /// # Errors
    ///
    /// Returns [`GovernedContextError`] if teardown fails.
    fn teardown(&self) -> Result<(), GovernedContextError>;
}

/// Why establishing or tearing down a governed context failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GovernedContextError {
    #[error("{reason}")]
    Failed { reason: String },
}

/// MVP 1.0's only [`GovernedContext`]: the null context, i.e.
/// `eltanin run`'s own inherited cgroup. Infallible — there is nothing
/// to establish or tear down yet.
pub struct NullContext;

impl GovernedContext for NullContext {
    fn establish(&self) -> Result<(), GovernedContextError> {
        Ok(())
    }

    fn teardown(&self) -> Result<(), GovernedContextError> {
        Ok(())
    }
}
