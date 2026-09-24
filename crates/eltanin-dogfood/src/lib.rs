//! Eltanin `DogFood` evidence adapter (HORO-1376, sub-scope of the
//! "Local Evidence & Dual-Profile `DogFood` Readiness" campaign,
//! ADR-0012).
//!
//! A thin, **read-only** translation layer projecting Eltanin's existing
//! native audit log (`eltanin_audit::explain::read_log`) into the frozen
//! `schema_version: 1` `DogFood` evidence event (ADR-0012 §3). This crate
//! never writes to the native audit log, never constructs an
//! [`eltanin_audit::sink::AuditFileSink`], and is never wired into
//! [`eltanin_audit`]'s own write path or any live authorization/
//! enforcement path — see `tests/dependency_direction.rs` for the
//! mechanical guard on the latter half of that claim.
//!
//! # Branch qualification (ADR-0012 §11.4, mandatory)
//!
//! Eltanin's observe-mode authorization implementation
//! (`crates/eltanin-agent/src/authz/*`) exists **only** on the
//! `next/mvp-2.0` development branch, not in any shipped `main` build.
//! [`BRANCH_QUALIFICATION_NOTICE`] carries the exact operator-facing
//! string this crate and `eltanin-cli`'s `dogfood-evidence` subcommand
//! print, so this fact is never silently dropped from user-facing output
//! — see `tests/branch_qualification.rs`.
//!
//! # No hardware/GPU claim
//!
//! This adapter makes no device-level enforcement claim of any kind —
//! see `tests/no_gpu_claim.rs` and [`adapter::UNSUPPORTED_DEVICE_LEVEL_GPU_ENFORCEMENT`].
//!
//! # No networking dependency
//!
//! Per ADR-0012 §12's Eltanin row ("Rust; filesystem only, no networking
//! dependency added"), this crate depends only on `eltanin-core`,
//! `eltanin-audit`, `serde`, `serde_json`, and `sha2` — see
//! `tests/no_network_dependency.rs`.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod canon;
pub mod event;
pub mod rfc3339;

/// The exact operator-facing string that must appear in this crate's (and
/// `eltanin-cli dogfood-evidence`'s) help/output text, qualifying observe-mode
/// semantics as available only on the MVP 2.0 development branch — never
/// described as shipped `main` behavior. See ADR-0012 §11.4 and the module
/// docs above.
pub const BRANCH_QUALIFICATION_NOTICE: &str =
    "Observe-mode authorization semantics are available on the MVP 2.0 \
     development branch (next/mvp-2.0), not in a shipped main build.";
