# Apple Silicon Real Metal Workload Fixture (F-M1-010, HORO-1014)

This document explains `metal_workload_fixture` — the repository-owned
program that gives Eltanin's Apple Silicon evidence class (E2, see
[`SECURITY_MODEL.md`](SECURITY_MODEL.md#supported-platform-boundary)) a
real GPU workload to authorize, rather than depending on an external ML
framework or a placeholder command like `echo`.

## What it is

`metal_workload_fixture` is a small, standalone binary built by the
`eltanin-apple` crate
([`crates/eltanin-apple/src/bin/metal_workload_fixture.rs`](../../crates/eltanin-apple/src/bin/metal_workload_fixture.rs)).
It is not part of the `AppleBackend` `ComputeBackend` adapter and is not
product runtime code — it exists purely as a QA/demonstration fixture,
per Jira HORO-1014's explicit allowance for "a dedicated test/example
binary/package rather than product runtime code."

It dispatches one real Metal compute kernel (`double_elements`, reused
from `eltanin_apple::probe` — the same code F-M1-010/HORO-1012's
`metal_compute_probe.rs` test already exercises) on the system's default
Metal device, reads back the result, and independently verifies every
output element against its CPU-computed expected value.

## Running it directly

```sh
cargo build -p eltanin-apple --bin metal_workload_fixture
./target/debug/metal_workload_fixture
```

On success, it prints a JSON evidence document to stdout and exits `0`:

```json
{
  "schema_version": 1,
  "fixture": "eltanin-apple-metal-workload-fixture",
  "host": { "arch": "aarch64", "os": "macos" },
  "device": { "name": "Apple M3 Max", "registry_id": "0x...", "has_unified_memory": true },
  "workload": { "kernel": "double_elements", "element_count": 16, "input_hash": "0x..." },
  "result": { "verified_elements": 16, "all_elements_verified": true, "gpu_command_completed": true }
}
```

`--evidence-out <path>` additionally writes the same JSON to a file —
useful when the fixture is run as a managed workload and its stdout is
consumed by something else (see below).

### Exit codes

| Exit | Meaning |
|---|---|
| `0` | Metal compute completed and the result was independently verified. |
| `1` | No Metal device/command execution is available on this host (non-macOS, or macOS with no Metal device) — an environment precondition, not a compute failure. |
| `2` | A Metal device was present but dispatch, readback, or verification failed — always a hard failure, never silently downgraded to a skip or a fabricated success. |

No code path falls back to a CPU-only computation and reports success —
see `crate::probe::run_compute_probe`'s doc comment.

## Running it as a managed `eltanin run` workload

The fixture is a normal executable, so it can be launched exactly like
any other `eltanin run` workload
([`QUICKSTART.md`](QUICKSTART.md#3-run-a-workload)):

```sh
eltanin run --profile gpu -- ./target/debug/metal_workload_fixture --evidence-out /tmp/eltanin/evidence.json
```

On ALLOW, the fixture's own JSON evidence passes through `eltanin run`'s
stdout verbatim, and `/tmp/eltanin/evidence.json` is written. On DENY,
`eltanin run` exits `77` and the fixture never starts — no evidence file
is ever created, which is exactly what
[`crates/eltanin-cli/tests/apple_metal_canonical_e2e.rs`](../../crates/eltanin-cli/tests/apple_metal_canonical_e2e.rs)
asserts for real on physical Apple Silicon hardware.

## What this proves

- A real Metal command buffer was submitted to a real system GPU device
  and completed (`waitUntilCompleted` returned) — the evidence report's
  `gpu_command_completed` field is structural, not a separately measured
  signal: it is only ever present because the `Ok` result it lives on
  cannot be constructed until `waitUntilCompleted` has already returned.
- Its output was read back and independently checked against a
  CPU-computed expected value for a known, deterministic input.
- When run as a managed workload: the full `eltanin run` ALLOW path
  (authorization → lease → spawn → real GPU compute → verified result)
  and DENY path (authorization refused → the workload never spawns at
  all, so it never touches the GPU) both work end to end on real
  hardware, correlated with `eltanin-explain`'s audit evidence exactly
  as `QUICKSTART.md`'s Linux/macOS journey already is.

## What this does NOT prove

Per `SECURITY_MODEL.md`'s E2/E3 distinction and ADR 0006/0007's
capability-honesty tables — **never conflate this with device-level
protection**:

- No claim of device-level GPU enforcement or revocation.
  `Capability::DeviceEnforce`/`DeviceRevoke` remain `Unsupported` for the
  Apple Silicon backend on every target, unconditionally.
- No claim that an *unmanaged* process (one that never went through
  `eltanin run`/the agent) can be prevented from using the GPU. This
  fixture proves the *authorized* path works; it says nothing about
  whether an attacker could bypass it and dispatch Metal work directly.
- No claim of arbitrary system-wide Metal access prevention,
  device-file/kernel-level isolation, or root/kernel attacker
  resistance. See `SECURITY_MODEL.md`'s threat-level tables for what E2
  evidence is and is not.
- The sole mandatory device-level enforcement gate remains E3 (bare-metal
  Linux + NVIDIA, F-M1-007) — an Apple-only PASS stays `BLOCKED ON E3`,
  never `READY`, exactly as `SECURITY_MODEL.md` already states for every
  other Apple Silicon evidence class.

## Formal QA status

This fixture and its real-hardware canonical E2E test
(`apple_metal_canonical_e2e.rs`) were first verified by hand on a real M3
Max at HORO-1014. HORO-1015 closed the formal QA gate: the Track B
scenario is [`B-M1-APPLE-v1`](../qa/e2e/B-M1-APPLE.md) (extending this
test file with ALLOW/DENY audit-explain coverage and a repeated-cycle
determinism test) and the Feature Verification Record is
[`F-M1-010.md`](../qa/feature-verification/F-M1-010.md) — **Status:
PASS**, scoped to E2 functional evidence only (never device-level
enforcement, and never a replacement for F-M1-007's Linux/NVIDIA
evidence — see that record for the full scope statement).

## Optional MLX scenario — not added

Jira HORO-1014 allows an optional, supplementary MLX (Apple AI/ML
framework) scenario "if economical." It was deliberately not added in
this pass: the native Metal fixture above already satisfies every
Acceptance Criterion (a real, independently-verified, repository-owned
GPU workload with no CPU fallback), and the MLX scenario is explicitly
required to never be the sole proof of real Apple GPU compute — so
skipping it trades no evidence for avoiding a new Python/MLX dependency
surface. It remains isolated-by-design if a future ticket adds it:
never a Cargo dependency, never required for any CI job to pass.
