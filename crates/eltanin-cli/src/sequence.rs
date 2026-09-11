//! The canonical `eltanin run` launch sequence (F-M1-008, HORO-845).
//!
//! This enum documents the S0–S11 ordering from
//! `docs/product/CLI_CONTRACT.md`'s "Launch state machine" section. It
//! exists so HORO-846's implementation, and any future tracing/logging
//! it adds, has one canonical, orderable name for each stage rather than
//! re-deriving the sequence from prose. There is deliberately no runtime
//! behavior attached to this type yet — HORO-846 is what actually drives
//! a launch through these stages; this ticket fixes their names and
//! order.

/// One stage of the canonical launch sequence, in the order they must
/// occur. `Ord`/`PartialOrd` follow declaration order, which is
/// definitionally the required order — see
/// `docs/product/CLI_CONTRACT.md` for what each stage does and which
/// exit code a failure at that stage maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LaunchStage {
    /// S0: parse argv.
    ParseArgv,
    /// S1: resolve `--profile` to `(resource, action)` — client-side
    /// only, no agent contact yet.
    ResolveProfile,
    /// S2: establish the governed execution context (the null context
    /// in MVP 1.0; a per-run cgroup v2 scope under F-M1-007) — before
    /// connecting, so the agent's peer-credential collection observes
    /// the governed scope from the first request.
    EstablishGovernedContext,
    /// S3: connect to the agent's Unix Domain Socket.
    ConnectToAgent,
    /// S4: send `RequestLease`; read exactly one response. The workload
    /// is spawned only if this stage completes with `LeaseGranted` — no
    /// [`LaunchStage`] between `RequestLease` and `SpawnWorkload` exists,
    /// which is the structural guarantee behind "no globally-permissive
    /// access window ever opens."
    RequestLease,
    /// S5: install signal handlers, before the workload exists.
    InstallSignalHandlers,
    /// S6: spawn the workload.
    SpawnWorkload,
    /// S7: supervise the workload while maintaining the lease (the
    /// renewal loop lives inside this stage).
    Supervise,
    /// S8: the workload has exited (normally or via signal).
    WorkloadExited,
    /// S9: release the lease — bounded retry; a failure here is a
    /// stderr warning, never a change to the workload's exit status.
    ReleaseLease,
    /// S10: tear down the governed execution context — after
    /// [`Self::ReleaseLease`], never before.
    TeardownGovernedContext,
    /// S11: exit with the workload's own status (or an `eltanin run`
    /// exit code — see `crate::exit::ExitCode`).
    Exit,
}
