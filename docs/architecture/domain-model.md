# Domain Model

Canonical vendor-neutral types living in `crates/eltanin-core`, defined
Feature-by-Feature as MVP 1.0 progresses. This document tracks what
exists and which ticket owns it — see the crate's own rustdoc for exact
field-level detail.

## Resource domain (F-M1-001, HORO-825) — `eltanin_core::resource`

| Type | Purpose |
|---|---|
| `ResourceVendor` | Open enum tagging which vendor owns a resource (`Nvidia`, `Fake`, `Unknown`). Opaque to the domain — never used to branch into vendor-specific logic here. |
| `ResourceKind` | Open enum for the resource class (`Gpu`, `Unknown`). |
| `ResourceIdentity` | Stable identity: vendor + kind + opaque `local_id`. |
| `Capability` | One of DISCOVER/OBSERVE/ATTRIBUTE/AUTHORIZE/ENFORCE/REVOKE/ATTEST. |
| `ResourceCapabilities` | The capability set a backend actually supports for a resource — a value type so downgrade is checkable data, not an assumption. |
| `ProtectedResource` | `ResourceIdentity` + `ResourceCapabilities`. |
| `Action` | What a workload asks to do (`Compute`, `Unknown`). |
| `ComputeRequest` | `ResourceIdentity` + `Action` — the seam F-M1-004/005 evaluate against. Carries no caller identity; that's `WorkloadIdentity`/`ExecutionContext` (F-M1-003), composed alongside it. |
| `EnforcementResult` | `Allowed` / `Denied{reason}` / `Unsupported{capability}` / `Error{message}` — `Unsupported` is first-class so a capability downgrade can never masquerade as `Allowed`. |

## Versioned envelope (HORO-825) — `eltanin_core::envelope`

`Versioned<T>` wraps any domain payload with an explicit `version: u16`.
`into_current()` fails explicitly (`UnsupportedVersion`) rather than
silently reinterpreting bytes from a schema this build doesn't
understand. `DOMAIN_SCHEMA_VERSION` is bumped whenever a wrapped type's
wire shape changes incompatibly.

## Architecture enforcement

`crates/eltanin-core/tests/architecture_no_vendor_leak.rs` scans all
non-comment source lines in the crate for vendor/platform terms
(`nvidia`, `cuda`, `cgroup`, `nvml`, ...) and fails CI if any appear —
this is HORO-825's "architecture test/review rule catches vendor-specific
concepts leaking into core" acceptance criterion, enforced mechanically
rather than by review discipline alone.

## Not yet implemented

Backend capability trait contract (F-M1-001/HORO-826), Fake Compute
Backend (F-M1-001/HORO-827), identity/policy/lease/provenance domain
types (F-M1-003/004/005, HORO-831/834/836) — tracked in
`docs/development/campaign-state.md`.
