//! `eltanin-core` — vendor-neutral authorization domain.
//!
//! Modules are populated by their owning Feature ticket (see
//! docs/development/campaign-state.md): `resource` (F-M1-001, HORO-825),
//! `identity` (F-M1-003, HORO-831), `provenance` (F-M1-003, HORO-833),
//! `policy` (F-M1-004, HORO-834), `lease` (F-M1-005, HORO-836).
#![forbid(unsafe_code)]

pub mod envelope;
pub mod identity;
pub mod lease;
pub mod peer;
pub mod policy;
pub mod provenance;
pub mod resource;
pub mod session;
