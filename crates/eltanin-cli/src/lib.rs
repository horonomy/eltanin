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
//! HORO-845 defined the contract: argv parsing, profile naming, the
//! exit-code taxonomy, and the failure-message taxonomy. HORO-846 (this
//! ticket) implements the launch path itself: the UDS client
//! ([`client`]), the profile filesystem loader ([`profile`]), the
//! governed-execution-context seam ([`context`]), signal handling
//! ([`signals`]), the spawn/supervise/renew/release driver
//! ([`supervise`]), and the S0-S11 orchestrator ([`launch`]).
#![forbid(unsafe_code)]

pub mod args;
pub mod client;
pub mod context;
pub mod exit;
pub mod failure;
pub mod launch;
pub mod profile;
pub mod sequence;
pub mod session;
pub mod signals;
pub mod supervise;
