# Track B (Product/Business E2E) — B-M1-APPLE Apple Silicon Journey

**Scenario ID**: `B-M1-APPLE-v1`
**Test files**: `crates/eltanin-cli/tests/apple_metal_canonical_e2e.rs`,
`crates/eltanin-apple/tests/real_discovery.rs`.
**Ticket**: HORO-1015 (F-M1-010 Feature closure).
**User docs it backs**: [`docs/product/APPLE_SILICON_FIXTURE.md`](../../product/APPLE_SILICON_FIXTURE.md),
[`docs/product/QUICKSTART.md`](../../product/QUICKSTART.md#3-run-a-workload)
(the same `eltanin run` command shape, with the real Metal fixture in
place of `echo`/`sh`).

This is the second Track B scenario lineage this repository has — deliberately
prefixed `B-M1-` rather than reusing `E2E-F-M1-008-*`'s prefix, per
HORO-1015's own Jira text and `docs/development/campaign-state.md`'s
"Apple Silicon scope amendment," which name this scenario `B-M1-APPLE`
specifically (not a new `E2E-F-M1-010-*` ID). The `-v1` suffix matches
this repo's existing scenario-versioning convention. It proves the same
"authorization before consumption" journey `E2E-F-M1-008-controlled-launch-v1`
proves on Linux against `FakeBackend`, but end to end on **physical
Apple Silicon** against a **real Metal GPU** — the E2 evidence class
[`SECURITY_MODEL.md`](../../product/SECURITY_MODEL.md#supported-platform-boundary)
and [ADR 0006](../../adr/0006-cross-accelerator-capability-and-memory-model.md)
define.

## Precondition

macOS only (`#![cfg(target_os = "macos")]` on both test files); the
whole workspace must already be built (`cargo build --workspace`) so
`eltanin-agentd`, `eltanin-explain`, and `metal_workload_fixture` exist
next to `eltanin` in the same `target/<profile>/` directory; a real
Metal-capable Apple Silicon device must be present; the test process
must not run as uid `0` (same `assert_non_root_precondition` guard as
`canonical_e2e.rs`). Every test in `apple_metal_canonical_e2e.rs` is
additionally `#[ignore]`d (never executed by `cargo test --workspace`,
including on this repo's `test-macos` CI job, which `--exclude`s
`eltanin-apple` entirely per ADR 0007) — run by hand with
`cargo test -p eltanin-cli --test apple_metal_canonical_e2e -- --ignored`.
`real_discovery.rs`'s two tests are cheap enumeration only (no Metal
kernel dispatch) and are **not** `#[ignore]`d, but still never run in CI
for the same package-level `--exclude` reason — run by hand with
`cargo test -p eltanin-apple --test real_discovery`.

## Coverage — Features this scenario provides Track B evidence for

| Feature | How this scenario exercises it live |
|---|---|
| F-M1-010 (this ticket's Feature) | Real Apple accelerator discovery, capability-state inspection, ALLOW authorization + real Metal GPU compute, DENY non-start, ALLOW/DENY audit correlation, and repeated-cycle determinism — all on physical Apple Silicon. |
| F-M1-003 (workload identity/trust) | The agent's real `SO_PEERCRED`-observed uid (via `eltanin-macos`'s collector, F-M1-010/HORO-1013) is what the ALLOW/DENY decision conditions on, same as the Linux scenario. |
| F-M1-004 (policy engine) | A real `PolicySet` evaluation on macOS: an `Allow` match and a genuine default-deny. |
| F-M1-005 (lease) | A real `ComputeLease` is issued (ALLOW leg) and released on workload exit. |
| F-M1-006 (agent/protocol) | Real wire traffic over a real UDS, through `eltanin-agentd`'s actual accept loop, running as a macOS process. |
| F-M1-009 (audit/explain) | `allow_journey_is_explainable_via_the_audit_log` and `deny_journey_is_explainable_via_the_audit_log` each write a real audit record and read it back with the real `eltanin-explain` binary. |

## Scenario-to-journey mapping (Jira's 13-step Track B journey)

| Jira step | Test(s) | Notes |
|---|---|---|
| 1. Fresh supported physical M3 Max environment | `docs/qa/evidence/HORO-1015/environment.md` | Captured once per QA pass, not per test run. |
| 2. Start/configure Eltanin local path | `Agentd::start` (both test files) | Fresh `eltanin-agentd` + on-disk policy/profile per test. |
| 3. Discover Apple accelerator | `real_discovery.rs::discover_finds_at_least_one_real_apple_gpu` | Real `AppleBackend::discover()`, not a synthetic `DeviceSnapshot`. |
| 4. Inspect capability state | `real_discovery.rs::discovered_resource_capability_state_matches_the_honesty_table` | Asserts `DiscoverResource = Supported`, `DeviceEnforce`/`DeviceRevoke = Unsupported`, memory never fabricated as `Dedicated`. |
| 5. Submit authorized managed Metal workload | `apple_metal_canonical_e2e.rs::allow_journey_runs_the_real_metal_workload_and_verifies_output` | `eltanin run --profile gpu -- metal_workload_fixture`. |
| 6. Policy ALLOW + scoped lease | Same test | A real `ComputeLease` is issued before the workload spawns. |
| 7. Real Metal GPU compute completes with verified result | Same test | The fixture's own JSON evidence (`all_elements_verified: true`, `gpu_command_completed: true`) passes through `eltanin run`'s stdout verbatim and is independently confirmed via `--evidence-out`. |
| 8. Inspect correlated `eltanin explain` evidence (ALLOW) | `allow_journey_is_explainable_via_the_audit_log` | `eltanin-explain --pid <eltanin's pid>` returns a non-empty decision record. |
| 9. Submit equivalent unauthorized managed workload | `deny_journey_never_spawns_the_real_metal_workload` | Same fixture, a uid that matches no policy rule. |
| 10. Policy DENY and workload does not start/perform managed compute | Same test | Exit `77`; the fixture's own `--evidence-out` file — creatable only by a real fixture run — does not exist. |
| 11. Inspect DENY evidence | `deny_journey_is_explainable_via_the_audit_log` | `eltanin-explain --pid <eltanin's pid>` returns a non-empty decision record for the denial. |
| 12. Verify product/docs say `DEVICE_ENFORCE`/`DEVICE_REVOKE` unsupported/not proven | `real_discovery.rs` (assertions above) + [`APPLE_SILICON_FIXTURE.md`](../../product/APPLE_SILICON_FIXTURE.md#what-this-does-not-prove) + [`SECURITY_MODEL.md`](../../product/SECURITY_MODEL.md#supported-platform-boundary) | Both machine-asserted (capability state) and documented (product docs) — checked to actually agree, not just each independently claimed. |
| 13. Repeat lifecycle to prove determinism | `lifecycle_is_deterministic_across_repeated_allow_and_deny_cycles` | 3 fresh ALLOW+DENY cycles, each with its own `agentd`/scenario directory; identical outcome every cycle. |

Every assertion failure message in `apple_metal_canonical_e2e.rs` is
prefixed `[F-M1-010-apple-metal-fixture (provisional, pre-B-M1-APPLE)/{ALLOW,DENY}]`
(a leftover from HORO-1014's own doc comment predating this ticket's
formal `B-M1-APPLE-v1` assignment — left as the file's actual constant
name rather than renamed cosmetically in this QA pass, since the message
text itself, not the label, is what a failing assertion needs).

## North Star assertions

| Invariant | How this scenario relates to it |
|---|---|
| 1 — Authorization before consumption | **Machine-asserted.** The ALLOW leg reaches real Metal GPU dispatch only after a granted lease; the DENY leg never spawns the fixture at all (no evidence file is ever created). |
| 3 — Monitoring != Security | **Machine-asserted.** Both `*_is_explainable_via_the_audit_log` tests require a non-empty, real `eltanin-explain` record for both ALLOW and DENY — not a stub. |
| 6 — A lease is scoped and expiring | **Machine-asserted.** The ALLOW leg's lease is issued and released on fixture exit, same lease machinery as the Linux scenario. |
| 7 — Locally observable caller identity is not overridable | **Machine-asserted.** The connecting `eltanin` process's real macOS `LOCAL_PEERCRED`-observed uid (via `eltanin-macos`) is what the decision conditions on. |

Invariants 2, 4, 5, 8, 9 are not independently re-proven by this Apple
scenario beyond what `E2E-F-M1-008-controlled-launch-v1`'s own North Star
table already states for the shared authorization machinery — this
scenario's incremental claim is that the same machinery also holds when
the managed workload is real Metal GPU compute on macOS, not a new claim
about those invariants themselves.

## Named limitations (not silently closed)

- **Never run in CI.** `.github/workflows/ci.yml`'s `test-macos` job
  `--exclude`s `eltanin-apple` entirely (ADR 0007 — no virtualized macOS
  CI runner may dispatch real Metal work), and every test in
  `apple_metal_canonical_e2e.rs` is additionally `#[ignore]`d. This
  scenario's evidence is real-hardware, hand-run QA evidence
  ([`docs/qa/evidence/HORO-1015/`](../evidence/HORO-1015/)), never a
  standing CI gate — unlike `E2E-F-M1-008-controlled-launch-v1`, which
  Linux CI runs on every PR.
- **No device-level enforcement or revoke claim, anywhere in this
  scenario.** `Capability::DeviceEnforce`/`DeviceRevoke` are asserted
  `Unsupported` for every discovered resource
  (`real_discovery.rs`) and the fixture's own docs state this explicitly
  (Jira AC "capability state explicitly reports device
  enforcement/revoke unsupported/not proven"). An ALLOW/DENY PASS here is
  **application-level authorization functional evidence (E2)**, never
  device-level protection (E3) — see `SECURITY_MODEL.md`'s threat-level
  tables. This PASS does **not** replace F-M1-007's Linux/NVIDIA physical
  device-level enforcement evidence requirement; an Apple-only PASS stays
  `BLOCKED ON E3`, never `READY`, per HORO-790's own release-gate
  definition.
- **No unmanaged-access-prevention claim.** This scenario proves the
  *authorized* path works and the *managed* denied path does not start —
  it says nothing about whether a process that never went through
  `eltanin run` could dispatch Metal work directly, and makes no such
  claim.
- **Determinism is checked across 3 cycles, not exhaustively.** 3
  ALLOW+DENY cycles is enough to catch state-leak/timing non-determinism
  of the kind a single run cannot, but is not a statistical guarantee —
  same practical bound every other timing-sensitive test in this
  repository (e.g. `launch_lifecycle.rs`'s renewal tests) accepts.
- **`real_discovery.rs`'s capability-state assertions are structural,
  not exhaustive.** They confirm the honesty table already unit-tested
  against synthetic data in `capability_mapping.rs` also holds for a real
  discovered resource, for the specific capabilities HORO-1015's AC names
  (`DiscoverResource`, `DeviceEnforce`, `DeviceRevoke`, memory topology) —
  not every `Capability` variant.
