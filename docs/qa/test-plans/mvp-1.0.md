# Test Plan — Eltanin MVP 1.0 (HORO-810)

The versioned Track A (QA/Security engineering) test plan for the
`Eltanin MVP 1.0 — Authorization Happy Path` milestone (HORO-772), per
[`docs/qa/README.md`](../README.md)'s governance. This plan states what
test layer exists, what's genuinely absent, and — critically — never
claims hardware evidence this repository does not have. See
[`docs/qa/e2e/F-M1-008-controlled-launch.md`](../e2e/F-M1-008-controlled-launch.md)
for Track B (Product/Business E2E), a distinct evidence class this plan
does not duplicate. HORO-811 owns formalizing a dedicated Track B index;
until then, this is the one existing Track B record.

`crates/eltanin-cli/tests/qa_governance_sync.rs` mechanically enforces
that every test file path this plan cites actually exists — see that
file's doc comment for exactly what it checks and doesn't.

## Quality model — 10 layers

Every layer below is marked **REQUIRED** (exists and runs in CI today),
**NOT APPLICABLE** (genuinely doesn't apply to MVP 1.0's scope, with
reason), or **DEFERRED** (a real, named gap, with reason and — where one
exists — what stands in for it today).

| # | Layer | Status | Notes |
|---|---|---|---|
| 1 | Unit tests | REQUIRED | Present in every crate; run by `cargo test --workspace` in CI (`.github/workflows/ci.yml`'s `test` job). |
| 2 | Domain/property tests | DEFERRED (partial) | Golden/table-driven coverage exists (`*_golden.rs` in `eltanin-core`, `eltanin-audit`, `eltanin-protocol` — 7 files) proving fixed input/output pairs, plus exhaustive-over-enum coverage for the capability/memory model (`crates/eltanin-core/tests/resource_capability_states.rs` — all 9 `Capability` dimensions × all 4 `SupportState` values; `crates/eltanin-core/tests/resource_golden.rs`'s `AcceleratorMemory` cases and unrecognized-`SupportState`-fails-decode case — all HORO-1011). Property-based *generation* (e.g. `proptest`/`quickcheck`) is absent — no such dependency exists anywhere in the workspace (verified: `grep -r proptest\|quickcheck\|arbitrary Cargo.toml` across every crate returns nothing). Deferred, not N/A: a domain this security-sensitive would benefit from it: no incident currently justifies the new dependency. |
| 3 | Protocol/parser fuzzing | DEFERRED | `eltanin-protocol/tests/protocol_fail_closed.rs` hand-writes negative/malformed-input coverage (oversized, malformed-shape, version-mismatch — see that file). No `cargo-fuzz`/structured fuzzing harness exists. For a daemon parsing attacker-influenced bytes over a Unix Domain Socket, marking this **NOT APPLICABLE** would be dishonest — it is a real, open gap, deferred pending a driving incident or explicit prioritization. |
| 4 | Component/integration tests | REQUIRED | The bulk of this workspace's test suite: `crates/*/tests/*.rs` integration tests, including real-socket end-to-end tests (`eltanin-agent/tests/authz_end_to_end.rs`, `eltanin-cli/tests/canonical_e2e.rs`) that exercise the real binaries together, not just library calls — both now widened to `any(target_os = "linux", target_os = "macos")` and run for real on a `macos-latest` CI job (F-M1-010/HORO-1013). The Apple Silicon adapter's discovery path (`crates/eltanin-apple/tests/non_macos_fallback.rs`, F-M1-010/HORO-1012) exercises both the real `macos` discovery path (validated on a real macOS dev machine, not run by this repo's `ubuntu-latest` CI) and the `Unsupported` fallback every other target actually runs in CI — same dual-arm pattern as `eltanin-linux/tests/peer_credential.rs` and the new `eltanin-macos/tests/peer_credential.rs` (F-M1-010/HORO-1013). Unlike the Apple Silicon adapter's Metal-specific tests, `eltanin-macos`'s real `macos` path is not developer-verification-only — `.github/workflows/ci.yml`'s `test-macos`/`clippy-macos` jobs actually compile and run it in CI, since GitHub does not bill macOS runner minutes on this public repository. |
| 5 | Privileged Linux/cgroup/eBPF integration tests | DEFERRED — blocked on hardware | F-M1-007 (Linux Protected-Device Enforcement, HORO-789) owns this layer and has not started; MVP 1.0 has no cgroup v2 device-BPF enforcement code to test yet. See "Hardware requirement" below. |
| 6 | Adversarial/security regression corpus | REQUIRED | Broad and real — see "North Star invariant → defending tests" below for the indexed list. Not a separate directory; these are ordinary `crates/*/tests/*.rs` files named for what they defend against (spoof, replay, self-asserted-identity, PID reuse, execve substitution, etc.). `crates/eltanin-backend/tests/capability_support_states.rs` (HORO-1011) defends the compatibility-vs-protection distinction ADR 0006 introduces: `Partial`/`NotEvaluated` device-enforce support and mere `ControlledLaunch` support both provably never produce `EnforcementResult::Allowed`. `crates/eltanin-apple/tests/enforcement_honesty.rs` and `crates/eltanin-apple/tests/capability_mapping.rs` (F-M1-010/HORO-1012, ADR 0007) defend the same distinction for the Apple Silicon adapter specifically: `enforce`/`revoke` always report `Unsupported` regardless of target, and the capability mapping never reports anything but `DiscoverResource` as fully `Supported`. |
| 7 | Failure/recovery/upgrade/rollback tests | REQUIRED (partial) | Failure/recovery: extensive (agent restart — `eltanin-core/tests/lease_restart.rs`; renewal failure — `eltanin-agent/tests/authz_renewal.rs`, `eltanin-cli/tests/launch_lifecycle.rs`; release-failure warning path — same file; backend failure — `eltanin-agent/tests/authz_backend_failure.rs`). Upgrade/rollback: NOT APPLICABLE for MVP 1.0 — there is no shipped prior version to upgrade from or roll back to; this becomes REQUIRED starting whichever version first ships an upgrade path. |
| 8 | Compatibility/hardware matrix tests | DEFERRED — blocked on hardware | See "Hardware requirement" below. No `matrices/hardware.yaml`-style artifact is created by this plan — an empty or aspirational matrix with no real hardware behind it would be worse than stating the gap in prose. |
| 9 | Performance/soak tests | NOT APPLICABLE for MVP 1.0 | MVP 1.0 is an authorization-happy-path vertical slice on one workstation, not a throughput/scale claim (see `NORTH_STAR.md`'s "What MVP 1.0 is allowed to be, and is not allowed to become"). Revisit once a real performance claim is made in a later stage. |
| 10 | Supply-chain/release integrity tests | REQUIRED (partial) | `cargo-deny` (license/advisory/bans/sources) runs in CI on every PR (`.github/workflows/ci.yml`'s `deny` job). Release-artifact signing/provenance (e.g. sigstore, SLSA) is DEFERRED — no release artifact exists yet to sign; MVP 1.0 ships as source, not a distributed binary. |

## North Star invariant → defending tests

[`docs/product/NORTH_STAR.md`](../../product/NORTH_STAR.md) states 9
locked invariants. This table indexes which real test file(s) currently
defend each one — it does not relocate or duplicate those tests, only
points at them, so this plan cannot silently drift from what the tests
actually assert (`qa_governance_sync.rs` checks every path below
resolves).

| # | Invariant | Defending tests |
|---|---|---|
| 1 | Authorization before consumption; default deny | `crates/eltanin-core/tests/policy_decision.rs`, `crates/eltanin-cli/tests/launch_lifecycle.rs`, `crates/eltanin-cli/tests/canonical_e2e.rs` |
| 2 | Allocation != Authorization | **N/A for MVP 1.0** — no scheduler/orchestrator integration exists to test against. The structural defenses that stand in until one does: `crates/eltanin-core/tests/architecture_no_vendor_leak.rs`, `crates/eltanin-backend/tests/architecture_no_vendor_leak.rs`, `crates/eltanin-audit/tests/architecture_no_vendor_leak.rs`, `crates/eltanin-cli/tests/architecture_no_shell.rs`, `crates/eltanin-agent/tests/agent_architecture_guard.rs`. |
| 3 | Monitoring != Security | `crates/eltanin-audit/tests/record_not_authority.rs`, `crates/eltanin-audit/tests/redaction.rs` |
| 4 | Contextual signals are not authority | `crates/eltanin-core/tests/policy_spoof_signals.rs`, `crates/eltanin-core/tests/identity_adversarial.rs`, `crates/eltanin-core/tests/policy_replay.rs` |
| 5 | Remember intent, never possession of privilege | `crates/eltanin-core/tests/lease_expiry.rs`, `crates/eltanin-agent/tests/authz_renewal.rs` |
| 6 | A lease is scoped and expiring | `crates/eltanin-core/tests/lease_binding.rs`, `crates/eltanin-core/tests/lease_restart.rs`, `crates/eltanin-core/tests/lease_renewal.rs` |
| 7 | Locally observable identity is not overridable by caller claims | `crates/eltanin-protocol/tests/protocol_no_self_asserted_identity.rs`, `crates/eltanin-linux/tests/peer_credential.rs`, `crates/eltanin-macos/tests/peer_credential.rs` (F-M1-010/HORO-1013) |
| 8 | No permanent plaintext bearer credential | Structural — no such credential type exists in `eltanin-core`'s domain model to begin with (see `docs/architecture/domain-model.md`); no dedicated regression test names this directly today. Deferred: add one if a future artifact type makes this a live risk rather than an absence. |
| 9 | Cloud absent from the per-compute hot path | Structural — `eltanin-agent`'s authorization path has no network dependency beyond the local Unix Domain Socket (see `docs/adr/0004-local-ipc-and-nvml-ffi-boundary.md`); no dedicated regression test names this directly today, same reasoning as invariant 8. |

Invariants 8 and 9 are honestly marked as structurally-true-but-not-
test-pinned, rather than either fabricating a test or silently omitting
them from this table.

## Apple Silicon real-hardware probe (F-M1-010, HORO-1012)

`crates/eltanin-apple/tests/metal_compute_probe.rs` is `#![cfg(target_os = "macos")]`
for its entire file — it is never compiled-and-run by this repository's
`ubuntu-latest` CI, which has no macOS runner. It is local developer
verification only, not a Feature Verification Record or formal F-M1-010
evidence — producing that is HORO-1015's scope (physical M3 Max E2E,
QA, and capability/documentation closure), separate from this ticket.
This test plan does not claim CI coverage for it that does not exist.

## Apple Silicon native Metal workload fixture (F-M1-010, HORO-1014)

`crates/eltanin-apple/src/bin/metal_workload_fixture.rs` is a deterministic,
repository-owned, spawnable Metal compute workload — see
[`docs/product/APPLE_SILICON_FIXTURE.md`](../../product/APPLE_SILICON_FIXTURE.md)
for what it proves and does not prove. Its real-hardware canonical
Product/Business E2E scenario,
`crates/eltanin-cli/tests/apple_metal_canonical_e2e.rs`, exercises the
same `eltanin run` ALLOW/DENY journey as `canonical_e2e.rs` but with
this real Metal fixture as the managed workload instead of `echo`/`sh`.
Both tests are `#[ignore]`d and the file is `#![cfg(target_os =
"macos")]` — `cargo test --workspace` compiles but never executes them,
same CI-exclusion rationale as `metal_compute_probe.rs` above (ADR
0007's decision against a macOS CI runner for real Metal dispatch).
Verified for real by hand on this ticket's physical M3 Max at HORO-1014.
HORO-1015 subsequently extended this file with 3 more real-hardware
tests (ALLOW/DENY `eltanin-explain` audit-evidence correlation, and a
repeated-cycle determinism test) and a new `crates/eltanin-apple/tests/real_discovery.rs`
(real accelerator discovery/capability-state inspection), then produced
the formal [`B-M1-APPLE-v1`](../e2e/B-M1-APPLE.md) Track B record and the
[F-M1-010 Feature Verification Record](../feature-verification/F-M1-010.md)
— **Status: PASS** (E2 functional-evidence scope; does not replace
F-M1-007's E3 gate).

## Hardware requirement (F-M1-002, F-M1-007, HORO-790)

**Zero hardware evidence exists today.** No representative bare-metal
Linux/NVIDIA host has been identified in this environment (see
`docs/development/campaign-state.md`'s "Hardware evidence state"). This
section states what a real evidence-producing host would need, so the
ask is concrete rather than perpetually vague. A full setup/test/cleanup
runbook — GPU/kernel/driver requirements, exact commands, and
automated pre-flight/evidence-capture scripts — is prepared in
[`docs/development/hardware-validation-runbook.md`](../../development/hardware-validation-runbook.md);
that document is preparation only and does not itself contain any
hardware evidence. That runbook's "Two-stage strategy" section splits
this into Stage-1 preflight (free, VM/container-eligible, always
labeled `E3_PREFLIGHT_ONLY`) and Stage-2 bare-metal certification (the
only part that requires paid/scarce physical time) — Stage-1 preflight
work does not require bare-metal and is not blocked on hardware
provisioning.

- **Platform**: bare-metal Linux (not a VM — cgroup v2 device-BPF
  enforcement and NVML GPU access are the things under test, and both
  are commonly restricted or unavailable inside a VM/container).
- **Kernel**: cgroup v2 enabled, with device-BPF program attachment
  support (F-M1-007's enforcement substrate — see
  `docs/adr/0001-linux-nvidia-cgroup-ebpf-enforcement.md`).
  Kernel version constraints will firm up once F-M1-007's implementation
  starts; not yet.
  Rust is the default implementation language; C only at unavoidable FFI
  boundaries — no `eltanin-nvidia`/`ebpf/eltanin-device-guard` code
  exists in this workspace yet (see the root `Cargo.toml`'s comment on
  when those crates get added).
- **GPU**: an NVIDIA GPU with NVML reachable (F-M1-002's discovery
  target).
- **What each hardware suite would produce**: F-M1-002 — real
  `ProtectedResource` discovery evidence (an NVML-backed `ComputeBackend`
  implementation's `discover()`/`observe()` against the real device);
  F-M1-007 — real enforcement evidence (a denied lease actually
  prevents GPU compute; a granted lease actually permits it; revocation
  actually cuts it off mid-run); HORO-790 — the combined "prove the real
  Linux/NVIDIA Authorization Happy Path on hardware" milestone gate.
- **How it would be triggered**: as a separate, explicitly-labeled CI
  job or manual workflow_dispatch gated on a self-hosted runner with the
  above spec — never folded into the existing `ubuntu-latest`
  hardware-free jobs, so a missing/misconfigured hardware runner fails
  loudly as "hardware job didn't run" rather than silently passing as
  "no GPU tests failed." Not implemented yet — no runner exists to
  target.

This repository does not fabricate, simulate, or project hardware
results under any circumstance. Every reference to F-M1-002/F-M1-007/
HORO-790 elsewhere in this repository's QA documents states them as
blocked, not as passed-with-caveats.

## Machine-readable evidence emission

Jira's AC for this ticket asks CI to emit JUnit/JSON test results,
coverage, fuzz/property-test summaries, SARIF, and per-feature
verification status as machine-readable artifacts. **Deferred, reason:
no consumer yet.** A Release Quality Report (see
[`docs/qa/reports/TEMPLATE.md`](../reports/TEMPLATE.md)) is only
produced at an actual release gate, and the only release gate defined
so far (HORO-790, MVP 1.0 READY) is itself hardware-blocked. Adding a
JUnit/coverage/SARIF pipeline with nothing reading its output would be
scaffolding for its own sake. Revisit when a release gate is actually
imminent. Note also: switching the test runner to `cargo-nextest`
(commonly used to emit JUnit XML) would silently skip doctests, a real
regression this workspace's `cargo test --workspace` does not have —
any future adoption must account for that trade-off explicitly, not
adopt nextest as a drop-in default.

## Vestigial scaffold

`tests/conformance/.gitkeep` at the repository root predates this test
plan (HORO-781's initial scaffold). The root `Cargo.toml` is a virtual
workspace manifest with no `[package]` of its own, so a root-level
`tests/` directory is never compiled or run by `cargo test` — it is
dead scaffolding, not a hidden test suite. Recorded here so a future
agent doesn't mistake it for an active convention or re-propose Jira's
generic `tests/{unit,integration,adversarial,conformance,e2e}/` shape
into it; this repository's real convention is `crates/<crate>/tests/*.rs`
per-crate integration tests plus `docs/qa/` for governance. Not deleted
in this pass — no deletion without explicit confirmation, per this
repo's safe-implementation policy.

Similarly, Jira's suggested `qa/features/<feature-id>.yaml` shape is not
this repository's convention: HORO-819 already established Feature
Verification Records as Markdown, not YAML, at
`docs/qa/feature-verification/<feature-id>.md` — human-readable prose
with citations, not a machine-parsed schema. This test plan and
`qa_governance_sync.rs` both build on that existing `.md` convention
rather than introducing a second, parallel `.yaml` format.

## Open gaps summary

| Gap | Closeable now? |
|---|---|
| No versioned test plan for MVP 1.0 | Closed by this document. |
| Nothing mechanically checks QA-inventory/test-path drift | Closed by `crates/eltanin-cli/tests/qa_governance_sync.rs`. |
| No Release Quality Report template | Closed by `docs/qa/reports/TEMPLATE.md` (template only — an instantiated report requires an actual release gate). |
| Machine-readable CI evidence (JUnit/JSON/SARIF/coverage) | Deferred — no consumer until a release gate is imminent. |
| Structured fuzzing / property-based testing | Deferred — no incident currently justifies the new dependency. |
| Hardware matrix + privileged Linux/cgroup/eBPF suites | Deferred — blocked on hardware access (see "Hardware requirement"). |
| F-M1-001 has no Feature Verification Record | Deferred to HORO-784, not this ticket's scope. |
| General cross-`docs/` link/snippet/version-consistency linter | Deferred to its own future ticket — a real but distinct concern from QA-evidence governance; `docs/development/documentation-governance.md` previously pointed this at HORO-810, corrected here since this plan is evidence/test governance, not a documentation linter. |
