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

- `crates/domain`, `crates/resource`, `crates/identity`, `crates/policy`,
  `crates/lease`, `crates/provenance`, `crates/agent-core` model
  authorization concepts in vendor-neutral terms (a "protected resource,"
  not "an NVIDIA GPU"; a "compute lease," not "a CUDA context grant").
- `crates/backend-api` defines the trait contract a compute backend must
  implement (discovery, telemetry, process attribution, enforcement
  hooks). It depends on nothing vendor-specific.
- `backends/nvidia-linux` (added by F-M1-002) implements `backend-api`
  for NVIDIA/Linux. `crates/simulator`'s Fake Compute Backend implements
  the same trait for testing/CI.
- Dependency direction is one-way: vendor backend → `backend-api` →
  domain crates. Domain crates never depend on a vendor backend crate.

## Consequences

- Every F-M1-* Feature that touches "compute backend" concepts (F-M1-001,
  F-M1-002, F-M1-005, F-M1-006) must express itself through
  `backend-api`'s trait, not NVIDIA-specific types, in any crate other
  than `backends/nvidia-linux` itself.
- CI can run the full domain/policy/lease/agent test suite with zero GPU
  hardware, using the Fake Compute Backend (`crates/simulator`) — this is
  what makes `docs/development/campaign-state.md`'s "hardware-free work"
  bucket actually hardware-free in practice, not just in claim.
- Adding a second vendor backend (a hypothetical future AMD adapter) is
  additive: implement `backend-api`, no domain-crate changes required, by
  construction of this boundary.
