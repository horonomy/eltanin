//! `eltanin run` — controlled protected launch (F-M1-008, HORO-823).
//!
//! This crate implements the contract in `docs/product/CLI_CONTRACT.md`
//! and the process-topology decision in
//! `docs/adr/0005-eltanin-run-process-topology.md`: `eltanin run` stays
//! alive as the lease-holding supervisor for the workload's entire run —
//! it never `execve()`s into the workload — because that is the only
//! topology under which the already-merged lease-binding mechanism
//! (`compare_process`/`compare_executable` in `eltanin_core::identity`)
//! can ever release the lease again.
//!
//! **Named MVP 1.0 limitation** (not an oversight of this crate): because
//! the connecting peer is always `eltanin` itself, a policy condition on
//! `executable_path`/`executable_hash` cannot discriminate which
//! workload binary is actually run through `eltanin run`. See
//! `docs/product/CLI_CONTRACT.md` and `docs/product/POLICY_EXAMPLES.md`.
//!
//! HORO-845 (this ticket) defines the contract: argv parsing, profile
//! naming, the exit-code taxonomy, and the failure-message taxonomy.
//! HORO-846 implements the launch path itself (agent connection, spawn,
//! signal handling, lease renewal, release) — `main.rs` here is a thin
//! placeholder that honours the argv/exit contract but does not yet
//! connect to an agent.
#![forbid(unsafe_code)]

pub mod args;
pub mod exit;
pub mod failure;
pub mod profile;
pub mod sequence;
