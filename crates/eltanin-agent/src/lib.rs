//! `eltanin-agent` — privileged local authorization coordinator
//! (F-M1-006, HORO-839/HORO-840).
//!
//! This crate has two parts, kept structurally separate and mechanically
//! enforced by `tests/agent_architecture_guard.rs`:
//!
//! - **Transport** (`config`, `connection`, `daemon`, `handler`,
//!   `listener`, `peer`, `runtime`, `server`): socket lifecycle, peer
//!   credential derivation, bounded request framing. Contains no policy
//!   evaluation, lease issuance, or backend integration logic.
//! - **[`authz`]**: the one place in this crate policy/lease evaluation
//!   logic may appear (HORO-840) — implements [`handler::RequestHandler`]
//!   by wiring `eltanin-core`'s policy/lease contracts and an
//!   `eltanin-backend::ComputeBackend` together. Never touches sockets or
//!   framing.
//!
//! # Privilege requirements
//!
//! | Deployment | Privilege needed |
//! |---|---|
//! | MVP 1.0 happy path — agent and every workload run as the **same** uid | none — not root, no capability |
//! | Multi-user host (Linux) — agent must derive executable paths for peers of other uids | `CAP_SYS_PTRACE` only (`readlink /proc/<pid>/exe` requires `PTRACE_MODE_READ_FSCREDS` for a foreign uid; every other `/proc/<pid>/*` entry this crate reads is world-readable) |
//! | Hardened `/proc` (`hidepid=1/2`, systemd `ProtectProc=`) | membership in the mount's `gid=` group, or `CAP_SYS_PTRACE` — otherwise all peer evidence is `Missing` and every request fails closed |
//! | Multi-user host (macOS) — agent must derive `proc_pidpath`/`proc_pidinfo` for peers of other uids (HORO-1013) | root only — macOS's `proc_pidpath`/`proc_pidinfo` refuse a foreign-uid pid for any non-root caller, with no capability-style narrower grant like Linux's `CAP_SYS_PTRACE`; every other field `eltanin-macos` reads is available to any caller |
//! | Socket at a root-owned path (e.g. `/run/eltanin` on Linux, `/var/run/eltanin` on macOS) | root only at install time (or systemd `RuntimeDirectory=`/an equivalent macOS launchd provisioning step), not at runtime |
//!
//! F-M1-007's cgroup device-BPF attachment will separately need
//! `CAP_BPF`/`CAP_SYS_ADMIN` — not required by this crate; stated so
//! nothing here is assumed to already run privileged. This table has no
//! macOS-specific device-enforcement row: F-M1-010/HORO-1013 grants no
//! device-level Metal enforcement privilege of any kind, on any target
//! (see `docs/adr/0008-macos-platform-adapter-and-local-peer-identity.md`).
//!
//! # Trust boundary
//!
//! Peer identity comes solely from a kernel peer-credential mechanism
//! plus independently observed process state, both derived by the
//! platform collector (`eltanin_linux`/`eltanin_macos`) into the
//! shared [`eltanin_core::peer::PeerContext`] contract — never from
//! anything a client sends. `eltanin-protocol`'s wire types already
//! carry no
//! identity field at all (HORO-838); this crate additionally never
//! constructs a [`eltanin_core::identity::WorkloadIdentity`] or
//! [`eltanin_core::identity::ExecutionContext`] from client-controlled
//! bytes.
//!
//! # Known limitations, named obligations
//!
//! - **The `eltanin run` launch-model question is resolved by
//!   construction, not settled by policy.** This transport derives
//!   context for *the connecting peer at connect time*, a fact
//!   identical under fork+exec or exec-in-place — there is no
//!   target-pid field for a launch model to change. **The lease binding
//!   subject is the connecting peer process**, decided in HORO-840: pid
//!   and `ProcessStartToken` and executable, via
//!   [`eltanin_core::lease::LeaseIssuer::validate`]. A cgroup-scoped
//!   enforcement layer (F-M1-007) must reconcile a process-bound lease
//!   with cgroup-scoped device-BPF; see
//!   `docs/architecture/domain-model.md`. **Cross-ticket obligation on
//!   F-M1-008**: because the lease binds to the connecting peer,
//!   `eltanin run` must arrange for the workload process itself to
//!   connect — a CLI that connects and then forks the workload would
//!   bind the lease to the CLI, which then exits.
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

pub mod authz;
pub mod config;
pub mod connection;
pub mod daemon;
pub mod handler;
pub mod listener;
pub mod peer;
pub mod runtime;
pub mod server;
