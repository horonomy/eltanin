# ADR 0004: Local IPC over versioned Unix Domain Sockets; NVML behind a single FFI boundary

## Status

Accepted (MVP 1.0).

## Context

Two boundaries need a concrete decision, not just a principle:

1. How a caller (CLI, a launched workload) talks to the privileged local
   agent (F-M1-006) without a network dependency and without trusting
   whatever the caller claims about its own identity.
2. Where NVIDIA/NVML interaction lives, so unsafe FFI is isolated and
   reviewable rather than scattered.

## Decision

### Local IPC

Use a **versioned Unix Domain Socket (UDS) protocol** for Linux MVP,
implemented in `crates/eltanin-protocol` (message framing/versioning) and
`crates/eltanin-agent` (server side). Caller identity/context is derived
from the kernel's own peer-credential mechanism (`SO_PEERCRED`: verified
PID/UID/GID of the actual connecting process), never from a field the
caller includes in its request payload. This is what North Star invariant
7 ("locally observable caller identity is not overridable by untrusted
caller claims") means concretely for MVP 1.0.

TCP/HTTP is rejected for this boundary: it invites accidental
network-exposure of a privileged local authorization channel, and offers
no peer-credential equivalent as strong as `SO_PEERCRED` without
additional authentication machinery this MVP does not need on a
single-host boundary.

### NVML FFI boundary

All NVIDIA/NVML interaction is isolated to `crates/eltanin-nvidia`
(F-M1-002, not yet in the workspace) behind safe Rust wrapper types. No
other crate — including `crates/eltanin-backend`, whose trait
`eltanin-nvidia` implements — calls NVML directly or depends on an NVML
binding crate. Every `unsafe` block inside `eltanin-nvidia` carries a
`// SAFETY:` comment per
[`docs/product/PRODUCT_CONSTITUTION.md`](../product/PRODUCT_CONSTITUTION.md).

## Consequences

- HORO-838 (define the IPC protocol) implements the UDS framing/version
  negotiation described here, not a generic RPC library chosen
  independently.
- HORO-839 (privileged agent lifecycle) implements `SO_PEERCRED`
  extraction as the trust root for caller identity at the transport
  layer — `crates/eltanin-core`'s `identity`/`provenance` modules (F-M1-003)
  consume this as one input, not the sole one, per North Star invariant 4.
- HORO-828 (NVML loading/device identity) is the only ticket expected to
  introduce `unsafe` code into the workspace's initial crate set.
