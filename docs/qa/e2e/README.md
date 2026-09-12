# Track B (Product/Business E2E) — Scenario Index (HORO-811)

This is the Track B counterpart to [`docs/qa/README.md`](../README.md):
that document governs Track A (QA/Security engineering) at the Feature
level; this one governs Track B (Product/Business E2E) at the scenario
level. Both tracks are named by `.github/PULL_REQUEST_TEMPLATE.md` as
the two evidence classes every PR must classify — see
`docs/qa/README.md`'s "Track A vs. Track B" section for the full
definition of what distinguishes them.

## Scenario model

A **Track B scenario** is a whole-system, user-facing journey through
real binaries over a real transport — never a unit or mocked-component
test — that proves one or more Features work the way a real
user/operator would actually use them. `F-M1-008-controlled-launch.md`
is the one scenario this repository has today; its own file documents
the exact shape (Scenario ID, precondition, coverage table,
scenario-to-Quickstart mapping, named limitations) every future scenario
record should follow.

Not every Feature needs its own scenario. Several Features are covered
as a side effect of another Feature's canonical journey — e.g. F-M1-003
(workload identity) is proven live by `F-M1-008-controlled-launch`'s
ALLOW/DENY legs without needing a separate identity-specific scenario.
A Feature only needs its own new scenario when no existing journey
already exercises it end to end.

## Scenario manifest

| Scenario ID | Ticket | Test file | Record | Features covered |
|---|---|---|---|---|
| `E2E-F-M1-008-controlled-launch-v1` | HORO-847 | [`crates/eltanin-cli/tests/canonical_e2e.rs`](../../../crates/eltanin-cli/tests/canonical_e2e.rs) | [`F-M1-008-controlled-launch.md`](F-M1-008-controlled-launch.md) | F-M1-003, F-M1-004, F-M1-005, F-M1-006, F-M1-008, F-M1-009 |
| `B-M1-APPLE-v1` | HORO-1015 | [`crates/eltanin-cli/tests/apple_metal_canonical_e2e.rs`](../../../crates/eltanin-cli/tests/apple_metal_canonical_e2e.rs) | [`B-M1-APPLE.md`](B-M1-APPLE.md) | F-M1-003, F-M1-004, F-M1-005, F-M1-006, F-M1-009, F-M1-010 |

`crates/eltanin-cli/tests/qa_governance_sync.rs` mechanically checks
that every Feature ID in `canonical_e2e.rs`'s `pub const COVERS` list
appears in both this manifest and `F-M1-008-controlled-launch.md`'s own
coverage table — a scenario's code-level coverage claim and its
documentation can't silently drift apart.

## Per-Feature Track B coverage

| Feature | Track B coverage |
|---|---|
| F-M1-001 — Protected Resource & Backend Abstraction | N/A — no user/operator-facing journey of its own; it is the `ComputeBackend` trait/`FakeBackend` double every scenario runs against, not something a user directly invokes. |
| F-M1-002 — NVIDIA Protected Resource Discovery | BLOCKED — real NVIDIA hardware discovery has no scenario because it has no implementation yet (bare-metal Linux/NVIDIA hardware access, see `docs/development/campaign-state.md`'s "Dependency blockers"). |
| F-M1-003 — Workload Identity & Execution Provenance | `E2E-F-M1-008-controlled-launch-v1` — the agent's live `SO_PEERCRED`-observed uid is what the ALLOW/DENY policy decision actually conditions on. |
| F-M1-004 — Authorization Policy Decision | `E2E-F-M1-008-controlled-launch-v1` — a real `PolicySet` evaluates both an `Allow` match and a genuine default-deny. |
| F-M1-005 — Scoped Short-Lived Compute Lease | `E2E-F-M1-008-controlled-launch-v1` — a real `ComputeLease` is issued and released. |
| F-M1-006 — Local Authorization Agent & Authenticated IPC | `E2E-F-M1-008-controlled-launch-v1` — real wire traffic over a real UDS through `eltanin-agentd`'s actual accept loop. |
| F-M1-007 — Linux Protected-Device Enforcement | BLOCKED — same hardware dependency as F-M1-002; no scenario exists because no enforcement implementation exists yet. |
| F-M1-008 — Controlled Protected Launch (`eltanin run`) | `E2E-F-M1-008-controlled-launch-v1` — this is the scenario's own subject; the whole S0–S11 launch path is exercised directly. |
| F-M1-009 — Local Audit & Explain Evidence | `E2E-F-M1-008-controlled-launch-v1` — `deny_journey_is_explainable_via_the_audit_log` writes a real audit record and reads it back with the real `eltanin-explain` binary. Also `B-M1-APPLE-v1` on Apple Silicon (both ALLOW and DENY legs). |
| F-M1-010 — Apple Silicon Real-Accelerator Functional Validation | `B-M1-APPLE-v1` — this scenario's own subject; the full discover → capability-inspect → ALLOW+lease → real Metal compute → DENY-non-start → audit-correlate → repeat-for-determinism journey is exercised directly on physical Apple Silicon. |

`qa_governance_sync.rs` mechanically checks that every `F-M1-00N` in
[`docs/qa/README.md`](../README.md)'s Feature inventory appears
somewhere in this table with a scenario ID, `N/A`, or `BLOCKED` — never
a silently missing row.

## North Star assertion honesty

Not every claim a scenario's test function makes is proven the same
way. `F-M1-008-controlled-launch.md`'s own "North Star assertions"
section states, per assertion, whether it is machine-asserted by
`canonical_e2e.rs` itself, asserted only by a Track A test (not this
canonical journey), true only at the documentation level (a design
property the test doesn't independently exercise), or not applicable to
MVP 1.0's scope (e.g. no scheduler exists yet to test against) —
following the same "state the gap, don't paper over it" convention
`docs/qa/test-plans/mvp-1.0.md` already uses for Track A.

## Release-gate interaction

Per [`docs/qa/README.md`](../README.md)'s release-gate contract, Track B
evidence (or an explicit, reasoned N/A) is required for every in-scope
Feature before a release gate may pass. A canonical scenario failing
blocks the release gate even if every Track A suite is green — Track B
proves the user-facing outcome Track A's component-level tests cannot,
by construction, prove on their own.
