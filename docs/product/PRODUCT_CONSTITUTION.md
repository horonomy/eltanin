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
  neutral crates (`crates/eltanin-core`, `eltanin-backend`,
  `eltanin-protocol`, `eltanin-agent`, `eltanin-cli`, `eltanin-audit`)
  `#![forbid(unsafe_code)]`. Unsafe is permitted only in platform/vendor
  crates added for FFI/eBPF boundaries (`crates/eltanin-nvidia`,
  `crates/eltanin-linux`, `ebpf/eltanin-device-guard/`,
  `crates/eltanin-apple` — F-M1-010/HORO-1012, ADR 0007), and every
  `unsafe` block there must carry a `// SAFETY:` comment.
  `crates/eltanin-apple` does not blanket-allow `unsafe_code` or add its
  own `#![forbid(unsafe_code)]` override — it carries a single scoped
  `#[allow(unsafe_code)]` on the one function that dispatches a real
  Metal compute kernel and reads back its result
  (`crate::probe::run_compute_probe`); every other function in that
  crate, including device discovery, uses zero `unsafe` code.
  `crates/eltanin-macos` (F-M1-010/HORO-1013, [ADR 0008](../adr/0008-macos-platform-adapter-and-local-peer-identity.md))
  is the macOS **platform** adapter (process identity, local IPC peer
  credential) — distinct from `crates/eltanin-apple`, the macOS
  **vendor** (accelerator) adapter — and needed no `unsafe` escape hatch
  at all: it keeps `#![forbid(unsafe_code)]`, using `nix`/`libproc`'s
  safe wrappers over `LOCAL_PEERCRED`/`LOCAL_PEERPID`/`proc_pidinfo`/
  `proc_pidpath`, the same "safe wrapper crate" trade-off `eltanin-linux`
  already makes for `SO_PEERCRED` via `rustix`.

## Architecture boundaries

- **Vendor-neutral core, vendor-specific adapters.** NVIDIA/CUDA concepts
  must not leak into `crates/eltanin-core` or `crates/eltanin-agent`.
  Those crates depend on `crates/eltanin-backend`'s trait contract, never
  on a concrete vendor backend. The vendor backend (`crates/eltanin-nvidia`,
  added by F-M1-002) depends on `eltanin-backend`, never the reverse. The
  same rule applies to the Apple Silicon adapter (`crates/eltanin-apple`,
  F-M1-010/HORO-1012) added by the MVP 1.0 scope amendment (HORO-1010+):
  `eltanin-core::resource::Capability`'s
  nine dimensions (HORO-1011,
  [ADR 0006](../adr/0006-cross-accelerator-capability-and-memory-model.md))
  are the vendor-neutral vocabulary every adapter reports itself
  against — no adapter-specific capability name may leak into
  `eltanin-core`, and a unified-memory backend is representable via
  `AcceleratorMemory::Unified` without fabricating a dedicated-VRAM
  byte count.
- **Zero-code enforcement is the product requirement.** A protected
  workload must not need to link an Eltanin SDK to be enforced. An SDK
  (`sdk/`) may exist for *richer* integration (e.g. self-reporting
  provenance), but it is optional enrichment, never a requirement for
  the enforcement boundary to function.
- **Local persistence, local IPC.** The agent's local state does not
  require a network call to function (North Star invariant 9). The IPC
  boundary itself (`crates/eltanin-protocol`) is a **versioned Unix
  Domain Socket protocol**, with caller identity/context derived from OS
  peer credentials (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/
  `LOCAL_PEERPID` on macOS) rather than trusted from anything the caller
  asserts about itself — see HORO-788, [ADR 0004](../adr/0004-local-ipc-and-nvml-ffi-boundary.md),
  and, for the macOS platform adapter (F-M1-010/HORO-1013),
  [ADR 0008](../adr/0008-macos-platform-adapter-and-local-peer-identity.md).
  The shared peer-credential contract
  (`eltanin_core::peer::{PeerCredential, PeerConsistency, PeerContext}`)
  lives in `crates/eltanin-core` so both platform adapters
  (`crates/eltanin-linux`, `crates/eltanin-macos`) produce it without
  either depending on the other.
- **Versioned protocol over unstable ABI.** When the backend boundary is
  externalized (e.g. out-of-process backend), use a versioned
  process/protocol boundary — never rely on Rust's unstable dynamic ABI
  across a process/version boundary.
- **Simulator/conformance strategy.** `crates/eltanin-backend`'s `fake`
  module provides a deterministic Fake Compute Backend implementing the
  same trait as the real NVIDIA backend, so CI (and most development)
  never requires GPU hardware. Every backend contract test in
  `tests/conformance/` runs against both the fake and (on real hardware,
  as a separate gate) the NVIDIA backend.
- **NVML FFI boundary.** All NVIDIA/NVML interaction is isolated to
  `crates/eltanin-nvidia` (F-M1-002) behind safe Rust wrapper types; no
  other crate calls NVML directly. See
  [ADR 0004](../adr/0004-local-ipc-and-nvml-ffi-boundary.md).

## Open enforcement substrate, proprietary governance (forward-looking)

The local enforcement substrate (policy/lease/agent/device-guard —
everything under `crates/eltanin-core`, `eltanin-agent`,
`ebpf/eltanin-device-guard/`) is and stays open source in this
repository; it is what OSS users run today, and remains the trust anchor
a customer can audit. A future enterprise **governance/control-plane**
layer (fleet policy authoring, cross-host reporting, SSO/RBAC — Stage 6,
HORO-777/`horonomy/eltanin-enterprise`) may be proprietary, but it
observes/manages the open substrate — it is never a required dependency
for the open substrate's own per-compute authorization/enforcement
decision (North Star invariant 9). MVP 1.0 does not build any part of
that governance layer; this bullet exists so no future PR quietly makes
local enforcement depend on the proprietary layer to function.

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
