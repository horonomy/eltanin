//! `eltanin-protocol` — versioned local IPC protocol (F-M1-006, HORO-838).
//!
//! Canonical, platform-neutral wire types for the local authorization
//! agent's IPC channel. This crate defines **what** can be said over the
//! wire and what it means; it does not open a socket, read a peer
//! credential, or own a clock — those belong to the transport/runtime
//! (HORO-839) and its integration with policy/lease/backend (HORO-840).
//!
//! # Trust boundary
//!
//! No wire type in this crate — request or response — carries an
//! identity or evidence field. `WorkloadIdentity`, `ExecutionContext`,
//! and every `Evidence<T>` they're built from are derived by the
//! privileged agent from OS peer credentials and observed process
//! state, never accepted from a client:
//!
//! | Field | Source | On the wire? |
//! |---|---|---|
//! | `pid` | transport peer credential (HORO-839) | no |
//! | `process_start`, `uid`, `gid`, `executable_path`, `executable_hash`, `ancestry` | `eltanin_linux` collector, keyed on the peer pid | no |
//! | `cgroup_path`, `namespace_hint`, `container_hint`, `session_origin` | same collector | no |
//! | `resource`, `action` | **client** — a request parameter; default-deny policy means it can only narrow what's already permitted, never grant it | yes |
//! | `request_id` | **client** — correlation only, no authority | yes |
//! | `lease_id` (release) | **client** — a lookup key, not a capability | yes |
//!
//! [`request::provenance_for`] is the *only* function in this crate that
//! produces a `ProvenanceRecord`, and its `derived: ExecutionContext`
//! parameter must come from the agent's own collector — enforced
//! structurally, since this crate contains no function that returns an
//! `ExecutionContext`, `WorkloadIdentity`, or `Evidence<T>` at all.
//!
//! "Advisory at most" for any client-observable-but-locally-derivable
//! field is therefore not a runtime check this crate performs — it is a
//! category of field this crate's types cannot express receiving from a
//! client in the first place.
//!
//! # No reusable plaintext bearer credential
//!
//! [`response::AgentResponse`] derives `Deserialize`. Every
//! `eltanin-core` type that must never be reconstructed from bytes
//! (`eltanin_core::lease::ComputeLease`, `eltanin_core::policy::PolicyDecision`,
//! `eltanin_core::policy::DecisionReason`,
//! `eltanin_core::policy::PolicyProvenance`,
//! `eltanin_core::lease::LeaseValidity`) is `Serialize`-only by
//! construction, so embedding any of them here would not compile. A
//! client that fabricates a `LeaseGranted` response to itself has
//! fabricated a display string, nothing more — enforcement of a real
//! lease happens agent-side (cgroup device-BPF, F-M1-007), never by a
//! client presenting a response it holds.
//!
//! # Versioning
//!
//! Requests and responses reuse `eltanin_core::envelope::Versioned<T>`
//! rather than minting a separate IPC protocol version number. MVP 1.0
//! ships one release with one schema version; a second, IPC-specific
//! version number would be a compatibility promise this codebase
//! doesn't keep yet (see `envelope.rs`'s own docs on the same point).
//! The day IPC and the domain schema must version independently is the
//! day the protocol earns its own envelope.
//!
//! There is no version handshake: [`request::ClientRequest::AgentStatus`]
//! is the liveness/version probe, and an unsupported version fails
//! closed with [`response::ErrorCode::UnsupportedVersion`], which names
//! the version this build actually expects.
//!
//! # Framing and the oversize bound
//!
//! See [`framing`] for the length-prefixed wire format and the named
//! obligation it places on the transport (HORO-839): the 4-byte length
//! header must be checked *before* the transport allocates a buffer for
//! the body.
//!
//! # Deliberately deferred / out of scope for this ticket
//!
//! - **No `ValidateLease` operation.** No MVP 1.0 caller needs to
//!   independently validate a lease it already holds; adding this later
//!   is additive and version-visible.
//! - **No client-supplied TTL.** The agent owns the clock and the
//!   issuer's `max_ttl` entirely.
//! - **No target-pid field on any request.** The subject of every
//!   request is the connecting peer itself, derived by the transport —
//!   see the crate-level "Flagged" note in the HORO-838 design record on
//!   why the `eltanin run` launch model (fork+exec vs. exec-in-place)
//!   must be resolved by HORO-839/840 before this assumption can be
//!   treated as settled.
//! - **Windows portability.** The sole platform-specific input anywhere
//!   in this design is "a process id for the connected peer, obtained by
//!   the transport." That never appears in a canonical type here, so a
//!   future Windows named-pipe transport supplies its own
//!   `ExecutionContext` collector and reuses this crate unchanged.

#![forbid(unsafe_code)]

pub mod framing;
pub mod request;
pub mod response;
