//! `eltanin-audit` — local audit & explain evidence (F-M1-009, HORO-824).
//!
//! Every protected-compute decision is reconstructable locally: which
//! resource, which observed workload/context, which policy/version,
//! which lease, which enforcement action, and why ALLOW/DENY happened —
//! without turning the log into a secret-leak channel. This is
//! authorization/provenance evidence, not generic observability.
//!
//! # Crate boundary and dependency direction
//!
//! This crate depends on `eltanin-core`, `eltanin-backend`, and
//! `eltanin-protocol` only — **never** `eltanin-linux` or
//! `eltanin-agent`. `eltanin-agent`'s `[[bin]] eltanin-agentd` needs to
//! select an audit sink, so if this crate depended on `eltanin-agent` to
//! see its `EventSink`/`AuthorizationEvent` types, that would be a
//! dependency cycle. The adapter — converting
//! `eltanin_core::peer::{PeerCredential, PeerConsistency}` into this
//! crate's plain [`record::RecordedPeerCredential`]/
//! [`record::RecordedPeerConsistency`] mirrors, and implementing
//! `eltanin_agent::authz::event::EventSink` — lives agent-side, in
//! `crates/eltanin-agent/src/authz/audit.rs`. This also keeps this
//! crate itself platform-neutral, consistent with HORO-788's own
//! requirement that the protocol/audit layer "remain portable enough for
//! a future Windows named-pipe/process boundary."
//!
//! # Writer and reader are separate, on purpose
//!
//! [`sink`] only writes; [`explain`] only reads. `eltanin-agent`'s own
//! `tests/audit_reader_isolation.rs` mechanically asserts the agent's
//! source never calls into [`explain`] — the agent writes the trail and
//! never reads it, so no edited log line can reach an authorization
//! decision. See [`record`]'s module doc for the structural argument
//! that makes an edited record's *content* harmless even if it were
//! read back somewhere.

#![forbid(unsafe_code)]

pub mod explain;
pub mod record;
pub mod sink;
