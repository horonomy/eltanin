//! `eltanin-agent` — privileged local authorization coordinator
//! (F-M1-006, HORO-839).
//!
//! This crate is transport/runtime only: socket lifecycle, peer
//! credential derivation, and bounded request framing. It contains no
//! policy evaluation, lease issuance, or backend integration logic —
//! see [`handler::RequestHandler`] for the seam HORO-840 implements
//! that logic behind, and `tests/agent_architecture_guard.rs` for the
//! lexical guard making that boundary mechanically checkable rather
//! than a review promise.
//!
//! # Privilege requirements
//!
//! | Deployment | Privilege needed |
//! |---|---|
//! | MVP 1.0 happy path — agent and every workload run as the **same** uid | none — not root, no capability |
//! | Multi-user host — agent must derive executable paths for peers of other uids | `CAP_SYS_PTRACE` only (`readlink /proc/<pid>/exe` requires `PTRACE_MODE_READ_FSCREDS` for a foreign uid; every other `/proc/<pid>/*` entry this crate reads is world-readable) |
//! | Hardened `/proc` (`hidepid=1/2`, systemd `ProtectProc=`) | membership in the mount's `gid=` group, or `CAP_SYS_PTRACE` — otherwise all peer evidence is `Missing` and every request fails closed |
//! | Socket at a root-owned path (e.g. `/run/eltanin`) | root only at install time (or systemd `RuntimeDirectory=`), not at runtime |
//!
//! F-M1-007's cgroup device-BPF attachment will separately need
//! `CAP_BPF`/`CAP_SYS_ADMIN` — not required by this crate; stated so
//! nothing here is assumed to already run privileged.
//!
//! # Trust boundary
//!
//! Peer identity comes solely from `SO_PEERCRED` plus a `/proc` read,
//! both derived by [`eltanin_linux::peer`] — never from anything a
//! client sends. `eltanin-protocol`'s wire types already carry no
//! identity field at all (HORO-838); this crate additionally never
//! constructs a [`eltanin_core::identity::WorkloadIdentity`] or
//! [`eltanin_core::identity::ExecutionContext`] from client-controlled
//! bytes.
//!
//! # Known limitations, named obligations
//!
//! - **No SIGTERM wiring.** This crate ships [`server::ShutdownHandle`]
//!   as a fully testable mechanism, but installs no signal handler and
//!   ships no daemon binary — wiring `SIGTERM` to
//!   `ShutdownHandle::shutdown` is HORO-840's obligation, alongside the
//!   daemon binary itself.
//! - **The `eltanin run` launch-model question is resolved by
//!   construction, not settled by policy.** This transport derives
//!   context for *the connecting peer at connect time*, a fact
//!   identical under fork+exec or exec-in-place — there is no
//!   target-pid field for a launch model to change. What a lease's
//!   *binding subject* should be (pid vs. cgroup) remains an open
//!   architecture question for F-M1-007/HORO-840, not this crate's to
//!   resolve.
//! - **`ErrorCode::UnknownOperation` is unreachable from this crate.**
//!   `eltanin_protocol::framing::decode_request` collapses an
//!   unrecognized operation into `ProtocolError::Malformed`; a client
//!   is never told "your operation name was unrecognized" as distinct
//!   from "your JSON was bad," which would otherwise hand it an oracle
//!   for probing valid operation names — consistent with
//!   `ErrorCode`'s own no-detail-on-the-wire design.
//! - **Connection-cap overflow is a silent close, not an `ErrorCode`.**
//!   `eltanin_protocol::response::ErrorCode` has no `Busy`/`Overloaded`
//!   variant, and adding one would change an already-merged wire
//!   schema. A client at the connection cap sees an immediate close
//!   with no response, which this crate accepts as the correct
//!   MVP 1.0 behavior rather than working around by changing a
//!   different crate's contract.

#![forbid(unsafe_code)]

pub mod config;
pub mod connection;
pub mod handler;
pub mod listener;
pub mod peer;
pub mod runtime;
pub mod server;
