# ADR 0002: Vendor-neutral domain model behind a backend trait boundary

## Status

Accepted (MVP 1.0).

## Context

Eltanin's roadmap (HORO-773..779) extends beyond NVIDIA/Linux to other
vendors and platforms. If domain concepts (protected resource identity,
workload identity, policy, lease) are modeled in terms of NVIDIA/CUDA
primitives, every future backend requires reworking the domain layer
instead of just adding an adapter.

## Decision

- `crates/eltanin-core` models authorization concepts (resource,
  identity, policy, lease, provenance — as submodules) in vendor-neutral
  terms (a "protected resource," not "an NVIDIA GPU"; a "compute lease,"
  not "a CUDA context grant").
- `crates/eltanin-backend` defines the trait contract a compute backend
  must implement (discovery, telemetry, process attribution, enforcement
  hooks) plus the deterministic Fake Compute Backend used by tests/CI. It
  depends on nothing vendor-specific.
- `crates/eltanin-nvidia` (added by F-M1-002, not yet in the workspace)
  implements the same trait for NVIDIA/Linux.
- Dependency direction is one-way: vendor backend → `eltanin-backend` →
  `eltanin-core`. Domain code never depends on a vendor backend crate.

**Naming/layout note:** this supersedes HORO-781's original proposed
finer-grained crate split (`crates/domain`, `resource`, `identity`,
`policy`, `lease`, `provenance`, `backend-api`, `agent-core`,
`simulator`, plus `platform/linux/` and `backends/nvidia-linux/`).
HORO-781 itself flagged that layout as provisional ("the exact
directories may evolve"). The layout actually adopted matches the Jira
Component table on HORO-772/HORO-780 and the literal "Primary
package(s)" paths already committed to in HORO-788, HORO-789, and
HORO-822 (`crates/eltanin-core`, `eltanin-backend`, `eltanin-nvidia`,
`eltanin-linux`, `eltanin-protocol`, `eltanin-agent`, `eltanin-cli`,
`ebpf/eltanin-device-guard`) — the more specific and more repeated
signal, and the one that already drives Jira Component routing.
Reconciled in the same PR pass that discovered the drift; see
`docs/development/campaign-state.md`.

## Consequences

- Every F-M1-* Feature that touches "compute backend" concepts (F-M1-001,
  F-M1-002, F-M1-005, F-M1-006) must express itself through
  `eltanin-backend`'s trait, not NVIDIA-specific types, in any crate other
  than `eltanin-nvidia` itself.
- CI can run the full domain/policy/lease/agent test suite with zero GPU
  hardware, using the Fake Compute Backend (`eltanin-backend::fake`) —
  this is what makes `docs/development/campaign-state.md`'s
  "hardware-free work" bucket actually hardware-free in practice, not
  just in claim.
- Adding a second vendor backend (a hypothetical future AMD adapter) is
  additive: implement the `eltanin-backend` trait, no `eltanin-core`
  changes required, by construction of this boundary.
