//! Exit-code taxonomy for `eltanin run` (F-M1-008, HORO-845).
//!
//! See `docs/product/CLI_CONTRACT.md`'s "Exit codes" section — this
//! enum and that table must stay in sync (guarded by
//! `tests/exit_code_contract.rs`).

/// A non-workload exit outcome. Workload-passthrough exit codes
/// (`0..=125`), 126/127 (spawn failure), and `128+N` (workload
/// terminated by signal `N`) are represented directly as `u8`/`i32`
/// values at the call site, not as variants here — this enum covers
/// only the outcomes `eltanin run` itself decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Malformed argv: missing `--`, empty command, bad `--profile`
    /// usage.
    Usage,
    /// The agent is unavailable — connection or socket error, no
    /// response was ever read.
    AgentUnavailable,
    /// The agent returned `AgentResponse::Error{code}` — a protocol or
    /// internal error, distinct from a policy denial.
    AgentError,
    /// The governed execution context (a future per-run cgroup scope
    /// under F-M1-007; the null context in MVP 1.0) could not be
    /// established.
    GovernedContextFailed,
    /// Authorization lapsed mid-run and `eltanin run` terminated the
    /// workload — fail-closed, never silently continuing an
    /// unauthorized workload.
    AuthorizationLapsed,
    /// The request was denied by policy (`AgentResponse::LeaseDenied`).
    Denied,
    /// `--profile` could not be resolved to a `(resource, action)` pair.
    ProfileUnresolved,
}

impl ExitCode {
    /// The process exit code this variant maps to. Values are chosen to
    /// avoid the `0..=127` range workload-passthrough and
    /// spawn-failure/signal codes already use — see
    /// `docs/product/CLI_CONTRACT.md`'s exit-code table.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Usage => 64,
            Self::AgentUnavailable => 69,
            Self::AgentError => 70,
            Self::GovernedContextFailed => 74,
            Self::AuthorizationLapsed => 76,
            Self::Denied => 77,
            Self::ProfileUnresolved => 78,
        }
    }
}

/// The exit code for a workload terminated by signal `N` (S-suffix
/// convention: `128 + N`, saturating rather than overflowing for an
/// out-of-range signal number).
#[must_use]
pub const fn workload_signal_exit_code(signal: u8) -> u8 {
    128u8.saturating_add(signal)
}
