//! `eltanin-backend` — vendor-neutral backend trait contract (F-M1-001,
//! HORO-826) and the deterministic Fake Compute Backend used by tests and
//! CI (HORO-827). The real NVIDIA backend (F-M1-002) implements the same
//! trait from its own crate, added when that ticket starts.
#![forbid(unsafe_code)]

pub mod contract;
pub mod fake;
