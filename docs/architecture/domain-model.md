# Domain Model

Canonical vendor-neutral types living in `crates/eltanin-core`, defined
Feature-by-Feature as MVP 1.0 progresses. This document tracks what
exists and which ticket owns it — see the crate's own rustdoc for exact
field-level detail.

## Resource domain (F-M1-001, HORO-825) — `eltanin_core::resource`

| Type | Purpose |
|---|---|
| `ResourceVendor` | Opaque string-backed tag for which vendor owns a resource (e.g. `"fake"`; a real vendor's tag is defined by that vendor's own adapter crate, never named here). Round-trips any tag without data loss — no lossy `Unknown` placeholder. |
| `ResourceKind` | Opaque string-backed tag for the resource class (e.g. `"gpu"`), same round-trip guarantee as `ResourceVendor`. |
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

## Backend contract (F-M1-001, HORO-826) — `eltanin_backend::contract`

| Type | Purpose |
|---|---|
| `ComputeBackend` | The trait every backend implements: `discover`, `observe`, `enforce`, `revoke`. Fake (`eltanin_backend::fake`, HORO-827) and, later, the real NVIDIA backend (`crates/eltanin-nvidia`, F-M1-002) both target exactly this trait — no backend-specific method exists outside it. Not a promise of a stable dynamic Rust ABI: if externalized to a separate process, the wire contract is `eltanin-protocol`'s versioned protocol (ADR 0004), not this trait's vtable. |
| `BackendError` | Typed operation failure distinct from `EnforcementResult` (which describes an enforcement *outcome*, not why an attempt couldn't be made): `Unsupported{capability}` (structural — never retry), `Unavailable{resource}`, `PermissionDenied`, `Transient{message}` (retryable), `Invariant{message}` (a bug, not a runtime condition). |

`ComputeBackend::enforce` does not decide authorization (F-M1-004 already
did) — it only reports whether the backend could carry out or verify the
already-decided action. A backend lacking `Capability::Enforce` returns
`Ok(EnforcementResult::Unsupported{..})`, never `Ok(Allowed)`.

## Architecture enforcement

`crates/eltanin-core/tests/architecture_no_vendor_leak.rs` and
`crates/eltanin-backend/tests/architecture_no_vendor_leak.rs` scan all
non-comment source lines in their crate for vendor/platform terms
(`nvidia`, `cuda`, `cgroup`, `nvml`, ...) and fail CI if any appear — this
is HORO-825/826's "architecture test/review rule catches vendor-specific
concepts leaking into core" acceptance criterion, enforced mechanically
rather than by review discipline alone. The backend crate's test also
asserts `eltanin-core` never depends back on `eltanin-backend`, enforcing
HORO-826's required dependency direction (vendor backend → `eltanin-backend`
→ `eltanin-core`).

## Fake Compute Backend (F-M1-001, HORO-827) — `eltanin_backend::fake::FakeBackend`

Deterministic, in-memory `ComputeBackend` implementation for tests/CI —
no special-case logic a real backend couldn't also provide. Resources
are added via `insert`/removed via `remove` (simulating disappearance);
`script_enforcement` pins a specific `enforce` outcome for a resource,
which is how tests simulate an already-decided policy ALLOW/DENY
(F-M1-004) or a lease-expiry denial (F-M1-005) without depending on
either Feature, neither of which exists yet.

`crates/eltanin-backend/tests/fake_backend_scenarios.rs` covers every
scenario named in HORO-827's scope: resource present/absent, a backend
lacking a capability, enforcement success/scripted-failure, resource
disappearance, a lease-expiry stand-in, revoke with/without capability,
and determinism across repeated runs (same script, same result, every
time — no hidden state or ordering dependency).

## Workload identity (F-M1-003, HORO-831) — `eltanin_core::identity`

| Type | Purpose |
|---|---|
| `EvidenceSource` | How a signal was obtained: `KernelObserved` (unforgeable by the observed process), `BestEffort` (unforgeable by the caller, but a narrow TOCTOU race is possible), `SelfAsserted` (the process's own claim, never an authorization basis). |
| `Evidence<T>` | `Present{value, source}` / `Missing{reason}` / `Unsupported` — every field a caller must handle explicitly; there is no default/fallback state, so missing evidence can never be silently treated as present-and-trusted. |
| `ProcessStartToken` | Opaque value paired with a PID to detect PID reuse. |
| `ProcessAncestor` | One entry in a process's parent chain — a contextual signal, never authority. |
| `WorkloadIdentity` | pid, process_start, uid, gid, executable_path/hash, ancestry — all as `Evidence<T>`. |
| `ExecutionContext` | `WorkloadIdentity` + cgroup_path/namespace_hint/container_hint/session_origin, all `Evidence<T>`. |

`WorkloadIdentity::same_process` defines PID-reuse/restart semantics
(HORO-831 AC): two identities are the same process only if `pid` matches
**and** both `process_start` tokens are `Present` and equal. Either side
missing or unsupported means "not confirmed the same" (`false`), never a
silent assumption of sameness — this is what keeps `uid == owner`,
`name == trusted`, `path == trusted`, `parent == trusted` from ever
becoming unconditional authorization (North Star invariant 4).

## Not yet implemented

Policy/lease/provenance domain types (F-M1-004/005, HORO-834/836), and
the Linux collector that actually populates `WorkloadIdentity`/
`ExecutionContext` from observed process state (F-M1-003, HORO-832) —
tracked in `docs/development/campaign-state.md`.
