# Track B (Product/Business E2E) — F-M1-008 Controlled Launch

**Scenario ID**: `E2E-F-M1-008-controlled-launch-v1`
**Test file**: `crates/eltanin-cli/tests/canonical_e2e.rs`
**Ticket**: HORO-847 (F-M1-008 subtask 3/3).
**User docs it backs**: [`docs/product/QUICKSTART.md`](../../product/QUICKSTART.md)
— pinned to this scenario by `crates/eltanin-cli/tests/docs_sync.rs`.

This is the "Track B (Product/Business E2E)" evidence named by
`.github/PULL_REQUEST_TEMPLATE.md` for F-M1-008: a whole-system,
user-facing ALLOW/DENY journey through the two real binaries
(`eltanin-agentd`, `eltanin`) over a real Unix Domain Socket and a real
on-disk policy — as opposed to Track A (QA/Security) coverage, which
lives in each subtask's own unit/integration tests
(`crates/eltanin-cli/tests/{argv_contract,exit_code_contract,
failure_messages,profile_contract,profile_loader,launch_lifecycle,
architecture_no_shell}.rs`, `crates/eltanin-agent/tests/authz_renewal.rs`).

## Precondition

Linux only (`#![cfg(target_os = "linux")]`); the whole workspace must
already be built (`cargo build --workspace` — CI always runs this before
`cargo test --workspace`) so `eltanin-agentd` and `eltanin-explain` exist
next to `eltanin` in the same `target/<profile>/` directory; the test
process must not be running as uid `0` (the fixture's `deny-root` rule
would otherwise swallow the ALLOW leg — asserted explicitly, not worked
around, in `assert_non_root_precondition`).

## Coverage — Features this scenario provides Track B evidence for

| Feature | How this scenario exercises it live |
|---|---|
| F-M1-008 (this ticket's parent) | The whole `eltanin run` launch path, S0–S11, against a real agent. |
| F-M1-003 (workload identity/trust) | The agent's `SO_PEERCRED`-observed uid of the connecting `eltanin` process is what the policy actually conditions on. |
| F-M1-004 (policy engine) | A real `PolicySet` evaluation, both an `Allow` match and a genuine default-deny (`NoMatchingRule`, not a scripted `ExplicitDeny`). |
| F-M1-005 (lease) | A real `ComputeLease` is issued (ALLOW leg) and released on workload exit. |
| F-M1-006 (agent/protocol) | Real wire traffic over a real socket, through `eltanin-agentd`'s actual accept loop. |
| F-M1-009 (audit/explain) | `deny_journey_is_explainable_via_the_audit_log` writes a real audit record and reads it back with the real `eltanin-explain` binary. |

## Scenario-to-Quickstart mapping

| Test fn | Quickstart step(s) | Launch stage | North-Star invariant | Expected exit |
|---|---|---|---|---|
| `allow_journey_authorizes_and_runs_the_workload` | §1 (profile), §2 (agent+policy), §3 (run) | `RequestLease` → `SpawnWorkload` | 1 ("Authorization before consumption") | `0` (workload's own status) |
| `deny_journey_never_spawns_the_workload` | §1, §2 (mismatched uid), §4 | `RequestLease` (no `SpawnWorkload` reached) | 1 (default deny), plus the structural guarantee that no `LaunchStage` exists between `RequestLease` and `SpawnWorkload` | `77` |
| `deny_journey_is_explainable_via_the_audit_log` | §2 (`ELTANIN_AUDIT_LOG`), §4 (`eltanin-explain`) | `RequestLease`; then a real `eltanin-explain --pid` read | 3 ("Monitoring != Security" — audit must be genuine evidence) | `77`, plus a non-empty `eltanin-explain` record |

Every assertion failure message in `canonical_e2e.rs` is prefixed
`[E2E-F-M1-008-controlled-launch-v1/{ALLOW,DENY}]`, names the specific
`LaunchStage` involved, and quotes which `NORTH_STAR.md` invariant it
would violate — so a CI failure here identifies the user-visible
Quickstart step and the security property at risk without needing to
read the test body.

## North Star assertions

Not every `NORTH_STAR.md` invariant this scenario touches is proven the
same way. Stated honestly rather than blanket-claimed (HORO-811):

| Invariant | How this scenario relates to it |
|---|---|
| 1 — Authorization before consumption | **Machine-asserted.** `allow_journey_authorizes_and_runs_the_workload` proves the ALLOW leg reaches `SpawnWorkload` only after `RequestLease` succeeds; `deny_journey_never_spawns_the_workload` proves the DENY leg never does. |
| 2 — Allocation != Authorization | **N/A for MVP 1.0.** No scheduler/orchestrator exists yet to test the distinction against — the invariant has nothing to violate until one does. |
| 4 — Contextual signals are not authority | **Track-A-only.** This scenario's two legs differ only by uid — it never attempts a spoofed/forged signal. The adversarial cases (forged PID, replayed decision, multi-vector spoof) are `crates/eltanin-core/tests/{policy_spoof_signals,identity_adversarial,policy_replay}.rs`, per `docs/qa/test-plans/mvp-1.0.md`'s invariant map. |
| 5 — Remember authorization intent, never possession | **Documentation-level.** True by the `ComputeLease`/`LeaseIssuer` design (`docs/adr/`), but this scenario's assertions don't independently exercise "intent vs. possession" as a distinct claim — it only proves a lease is issued and released. |
| 6 — A lease is scoped and expiring | **Machine-asserted.** The ALLOW leg's lease is issued, then released on workload exit — both observed directly. |
| 7 — Locally observable caller identity is not overridable | **Machine-asserted.** The connecting `eltanin` process's real `SO_PEERCRED` uid — not a client-supplied claim — is what the ALLOW/DENY decision actually conditions on. |

Invariants 3, 8, and 9 are addressed elsewhere: 3 ("Monitoring !=
Security") by `deny_journey_is_explainable_via_the_audit_log` (already
in the coverage table above); 8 and 9 have no Track B claim in this
scenario and are tracked as structural-only in
`docs/qa/test-plans/mvp-1.0.md`'s invariant map, not restated here.

## Named limitations (not silently closed)

- **Runs against `FakeBackend`.** This scenario proves the
  *authorization* path — lease issuance, policy evaluation, audit — end
  to end. It is not real GPU hardware enforcement evidence; that remains
  gated on bare-metal NVIDIA hardware access (F-M1-002/F-M1-007, see
  `docs/development/campaign-state.md`'s "Dependency blockers").
- **No workload-executable-identity claim.** By construction (the reused
  `eltanin_run_example_policy.json`/`example_profile.json` fixtures —
  founder decision D-B, HORO-988), only uid is varied between the ALLOW
  and DENY legs. This scenario does not and must not exercise
  `executable_path`/`executable_hash` conditions through `eltanin run` —
  see `docs/product/CLI_CONTRACT.md`'s "MVP 1.0 limitation" section.
- **Does not duplicate `launch_lifecycle.rs`'s internal-branch coverage**
  (renewal, signal forwarding, every `LaunchFailure` variant, spawn
  failure taxonomy) — that remains the deeper Track A suite for
  HORO-846. This scenario is deliberately shallow and end-to-end.
