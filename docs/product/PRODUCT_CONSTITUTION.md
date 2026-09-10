# Product Constitution

This document turns Eltanin's security philosophy into engineering
constraints a PR reviewer (human or agent) can cite to reject a change.
See [`NORTH_STAR.md`](NORTH_STAR.md) for the locked invariants this
implements, and [`docs/adr/`](../adr/) for the reasoning behind each
architecture decision.

## Language and implementation policy

- **Rust by default.** All domain, backend, agent, protocol, and CLI code
  is Rust unless an ADR documents a specific exception.
- **C only at unavoidable FFI boundaries** (e.g. NVML, eBPF verifier
  interaction where no safe Rust binding exists).
- **No C++** unless a vendor SDK makes it unavoidable, documented in an
  ADR before the dependency is introduced.
- **Unsafe Rust must be isolated, documented, and reviewed.** Vendor-
  neutral domain crates (`crates/domain`, `resource`, `identity`,
  `policy`, `lease`, `provenance`, `protocol`, `backend-api`,
  `agent-core`, `simulator`) `#![forbid(unsafe_code)]`. Unsafe is
  permitted only in platform/vendor crates added for FFI/eBPF boundaries
  (`platform/linux/`, `backends/nvidia-linux/`), and every `unsafe` block
  there must carry a `// SAFETY:` comment.

## Architecture boundaries

- **Vendor-neutral core, vendor-specific adapters.** NVIDIA/CUDA concepts
  must not leak into `crates/domain`, `crates/policy`, `crates/lease`, or
  `crates/agent-core`. Those crates depend on `crates/backend-api`'s
  trait contract, never on a concrete vendor backend. The vendor backend
  (`backends/nvidia-linux`) depends on `backend-api`, never the reverse.
- **Zero-code enforcement is the product requirement.** A protected
  workload must not need to link an Eltanin SDK to be enforced. An SDK
  (`sdk/`) may exist for *richer* integration (e.g. self-reporting
  provenance), but it is optional enrichment, never a requirement for
  the enforcement boundary to function.
- **Local persistence, local IPC.** The agent's local state and its
  protocol boundary (`crates/protocol`) do not require a network call to
  function. Cloud is absent from the per-compute hot path (North Star
  invariant 9).
- **Versioned protocol over unstable ABI.** When the backend boundary is
  externalized (e.g. out-of-process backend), use a versioned
  process/protocol boundary — never rely on Rust's unstable dynamic ABI
  across a process/version boundary.
- **Simulator/conformance strategy.** `crates/simulator` provides a
  deterministic Fake Compute Backend implementing the same
  `backend-api` trait as the real NVIDIA backend, so CI (and most
  development) never requires GPU hardware. Every backend contract test
  in `tests/conformance/` runs against both the fake and (on real
  hardware, as a separate gate) the NVIDIA backend.

## Session, delegation, and step-up (forward-looking — MVP 2.0)

MVP 1.0 does not implement Trusted Compute Sessions, bounded delegation,
or risk-based step-up (those are HORO-773/MVP 2.0 scope). This section
exists so MVP 1.0's data model does not foreclose them: `WorkloadIdentity`
and `ExecutionContext` (F-M1-003) are modeled so a future session/
delegation concept can wrap them without a breaking redesign.

## Why CUDA interception / LD_PRELOAD is rejected as the security root

Both techniques operate in the same privilege domain as the workload they
are meant to constrain, and can be bypassed by a workload that
statically links, calls the driver directly, or unloads/circumvents the
interposed library. They may be acceptable as *defense-in-depth signal
collection* in a later stage, but never as the sole enforcement boundary.
The enforcement boundary for MVP 1.0 is kernel-level: cgroup v2
device-BPF (see [`SECURITY_MODEL.md`](SECURITY_MODEL.md)).

## Enforcing this document

A PR that violates any bullet above without a corresponding ADR
documenting a deliberate, reviewed exception should be rejected in
self-review or independent review, citing the specific bullet.
