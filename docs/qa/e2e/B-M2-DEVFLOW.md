# Track B (Product/Business E2E) — B-M2-DEVFLOW Developer Flow

**Scenario ID**: `B-M2-DEVFLOW-v2`
**Test file**: `crates/eltanin-cli/tests/mvp2_dev_flow_e2e.rs`
**Ticket**: HORO-797 (MVP 2.0 release-readiness gate, Track B subtask).
**User docs it backs**: [`docs/product/QUICKSTART.md`](../../product/QUICKSTART.md)'s
MVP 1.0 journey plus the MVP 2.0 `eltanin approve`/`eltanin
audit`/`eltanin status` surface documented in
[`docs/product/CLI_CONTRACT.md`](../../product/CLI_CONTRACT.md). Unlike
`F-M1-008-controlled-launch.md`, this record is **not** pinned by
`crates/eltanin-cli/tests/docs_sync.rs` (that file's checks are scoped
to `canonical_e2e.rs` only) — see "Named limitations" below.

This is the first MVP 2.0 Track B scenario (HORO-811's system), proving
a real developer's low-friction workflow once `eltanin-agentd`'s
MVP 2.0 gates are actually turned on via real environment configuration
— not called as library functions directly, which is all Track A
(`crates/eltanin-agent/tests/authz_approval.rs`,
`crates/eltanin-agent/tests/authz_lifecycle.rs`,
`crates/eltanin-cli/tests/{status_binary,explain_audit_binary}.rs`)
proves today.

## Precondition

Linux and macOS (`#![cfg(any(target_os = "linux", target_os = "macos"))]`,
mirroring `canonical_e2e.rs`); the whole workspace must already be built
(`cargo build --workspace`) so `eltanin-agentd` exists next to `eltanin`
in the same `target/<profile>/` directory; the test process must not be
running as uid `0` (same `deny-root` fixture rule as `canonical_e2e.rs`,
asserted explicitly).

## A real product gap found while building this scenario — resolved by HORO-1278

This scenario was originally designed to also cover F-M2-001 (Trusted
Compute Session): `eltanin session start` once, then several later
`eltanin run`/`eltanin approve` invocations relying on that session.
Building it against the real binaries found that this did not work:

- `eltanin-agentd`'s `session_establish_inputs`
  (`crates/eltanin-agent/src/authz/mod.rs`) set a new session's anchor
  `leader` to `observed.workload.clone()` — the **`CreateSession`
  request's own connecting peer**, i.e. `eltanin session start`'s own
  process identity (pid + start-time).
- `eltanin session start` is a real, short-lived process that exits the
  moment it prints its result (`crate::session::run`'s own module doc:
  "establishes it and exits").
- Every later session-touching operation
  (`membership_for_peer`/`SessionState::reap`) re-collected that same
  anchor-leader pid's *current* identity and required
  `WorkloadIdentity::compare_process` to report `Same` — which required
  the *exact same pid*, still alive, with a matching process-start
  token (`crates/eltanin-core/src/identity.rs::compare_process`).
- Once `eltanin session start` exited, that pid was gone. Confirmed
  live, outside this test file (a standalone repro against the real
  binaries, macOS): `eltanin session start` reported
  `SessionEstablished`; the very next `eltanin session list` — a
  separate process, same real POSIX session — reported "no active
  Trusted Compute Session," not the session just established.

This meant `ELTANIN_AGENT_SESSION_REQUIRED=1` behaved as a **deny-all
switch** for any real multi-invocation CLI usage, not the "prove intent
once per terminal" gate `docs/adr/0009-trusted-compute-session.md`
describes. Track A's own `crates/eltanin-agent/tests/authz_session.rs`
did not catch this because its `self_peer_context()` helper is the
*same* live test-process object used for the whole test — the anchor
leader never actually died mid-test there, which is exactly the
condition every real separate CLI invocation produces.

**This was a product/security design question, not a QA-scenario
workaround** — resolving it meant deciding which identity dimension the
product anchors session trust to, per this repo's `.claude/CLAUDE.md`
§5. It has since been resolved by **HORO-1278** ([PR #70 — Trusted
Compute Session anchor redesign](https://github.com/horonomy/eltanin/pull/70),
[PR #73 — session-refusal audit fidelity + `DOMAIN_SCHEMA_VERSION` 7](https://github.com/horonomy/eltanin/pull/73)):
`eltanin-agentd` now anchors a session to the caller's real POSIX
session id (`sid`), which outlives any one short-lived CLI invocation
and is shared by everything spawned in that terminal, matching ADR
0009's original intent.

F-M2-001 is now covered by this scenario, in this same `v2` — see the
Coverage table below for what the `f_m2_001_*` tests
(`crates/eltanin-cli/tests/mvp2_dev_flow_e2e.rs`) prove. Full Feature
Verification Record reconciliation (status line, known-limitations
cleanup) for F-M2-001 happens in a following PR in this HORO-1278
sequence — see
[`docs/qa/feature-verification/F-M2-001.md`](../feature-verification/F-M2-001.md).

## Coverage — Features this scenario provides Track B evidence for

| Feature | How this scenario exercises it live |
|---|---|
| F-M2-001 (Trusted Compute Session) | `f_m2_001_a_session_established_by_one_process_is_honored_by_later_separate_invocations` proves a session established by one, short-lived `eltanin session start` process is honored by later, genuinely separate `eltanin session list`/`eltanin run` invocations (a real multi-process establish → list → run × 2 journey); `f_m2_001_session_end_from_a_later_separate_process_fails_closed` proves `eltanin session end`, itself a separate later process, fails a subsequent run closed; `f_m2_001_an_expired_session_denies_a_later_separate_run` proves a session past its own TTL denies a later separate run and is honestly reported gone by `eltanin session list`. Every leg spawns and waits on a genuinely separate OS process — never the same live test-process object — so this is exactly the condition HORO-1278 fixes. |
| F-M2-002 (Remembered Authorization Intent) | `low_friction_repeated_runs_grant_every_request_with_zero_additional_prompts` proves one `eltanin approve --profile <p> --remember` backs several independent `eltanin run` invocations with zero further prompts; `a_changed_launcher_identity_is_denied_then_recovers_and_is_explainable` proves a changed launcher identity is re-evaluated (denied), never trusted from stored bytes, and that re-approving recovers it. |
| F-M2-005 (Compute Lease Lifecycle Hardening) | `ELTANIN_AGENT_REVOCATION_REQUIRED=1` is real, operator-set configuration for the whole scenario (`eltanin status` discloses `revocation required: yes`); every lease this scenario's several `eltanin run` invocations obtain is issued under that gate and released on workload exit. |
| F-M2-006 (Audit Durability + Shadow Enforcement Mode) | `a_changed_launcher_identity_is_denied_then_recovers_and_is_explainable` reads a real on-disk audit log via the real `eltanin explain --pid <pid>` and `eltanin audit` subcommands, correlating a real denial to the real pid that received it; both tests read real `eltanin status` output disclosing the agent's actual gate configuration. |

## Scenario-to-Quickstart mapping

| Test fn | Journey step(s) | North-Star invariant | Expected exit |
|---|---|---|---|
| `low_friction_repeated_runs_grant_every_request_with_zero_additional_prompts` | `eltanin status` → `eltanin approve --profile gpu --remember` → `eltanin run --profile gpu -- echo <n>` ×3 | 1 ("Authorization before consumption"), 5 ("Remember authorization intent, never possession") | `0` for every run |
| `a_changed_launcher_identity_is_denied_then_recovers_and_is_explainable` | approve → run (granted) → run through a different launcher path (denied) → re-approve → run (granted again) → `eltanin explain --pid`/`eltanin audit` | 5 (an approval is re-verified on every use, not treated as a possessed credential), 3 ("Monitoring != Security" — audit/explain must be genuine evidence) | `0`, `77`, `0` |

## North Star assertions

| Invariant | How this scenario relates to it |
|---|---|
| 1 — Authorization before consumption | **Machine-asserted.** Every granted `eltanin run` in this scenario reaches the workload only after a real `RequestLease` succeeds against a real, remembered approval; the denied leg never spawns `true`. |
| 5 — Remember authorization intent, never possession | **Machine-asserted, for the dimension this scenario varies.** `low_friction_...` proves a remembered `Remember` disposition is re-verified (not just looked up) on every one of three independent `eltanin run` calls with zero re-prompt; `a_changed_launcher_identity_...` proves that re-verification actually rejects a changed launcher identity rather than trusting a cached decision — the approval is possession of *nothing replayable*, it only ever back-authorizes a fresh, matching observation. Digest-specific (on-disk content) re-verification remains Track-A-only — see "Named limitations." |
| 3 — Monitoring != Security | **Machine-asserted.** `eltanin explain --pid`/`eltanin audit` read a real on-disk audit log this scenario's own real denial produced, not a scripted fixture. |
| 6 — A lease is scoped and expiring | **Machine-asserted.** Every lease this scenario's `eltanin run` invocations obtain is issued under `ELTANIN_AGENT_REVOCATION_REQUIRED=1` and released on workload exit. |
| 7 — Locally observable caller identity is not overridable | **Track-A-only for this scenario.** Every leg here uses the same real uid throughout; the identity dimension this scenario varies is launcher path, not caller uid — `canonical_e2e.rs` already covers the uid dimension for MVP 1.0's ALLOW/DENY split. HORO-1278's session-anchor redesign additionally verifies a session's stored `owner_uid` server-side (not merely trusted from the connecting peer), but this scenario does not itself vary caller uid to exercise that check — see `crates/eltanin-agent/tests/authz_session.rs` for that dimension. |
| 8 — No permanent plaintext bearer credential | **Proven elsewhere, not by this scenario's own tests.** `crates/eltanin-cli/tests/session_argv_contract.rs::session_start_persists_no_client_side_credential` machine-asserts that `eltanin session start` persists no client-side credential/token file; this scenario's own `f_m2_001_*` tests exercise the multi-process session-honoring behavior, not the no-persisted-credential property. |

Invariants 2, 4, and 9 have no claim in this scenario — same "state the
gap, don't paper over it" convention `F-M1-008-controlled-launch.md`
already established.

## Named limitations (not silently closed)

- **Runs against `FakeBackend`.** Same as `canonical_e2e.rs` — this
  scenario proves the *authorization* path end to end, not real GPU
  hardware enforcement.
- **F-M2-003 (delegation) and F-M2-004 (step-up) are not exercised.**
  `eltanin-agentd`'s `configure_gates` has no environment-variable
  surface for either as of HORO-797 prep — both remain library-only,
  reachable only from Track A tests that call `AuthorizationConfig`
  directly, not from the real binary.
- **Launcher-identity change is path-based, not digest-based.** This
  scenario copies the real `eltanin` binary to two distinct absolute
  paths and approves/runs through each — `ApprovalBinding::launcher_path`
  differs between them, triggering the same `DenialReason::ApprovalRequired`
  re-evaluation path a digest change would. It deliberately does not
  mutate the launcher binary's on-disk bytes and re-execute it (a
  portable, non-destructive way to do this over a real transport across
  both Linux and macOS was not found in this pass — Apple Silicon's
  mandatory code-signing enforcement makes a naive byte-append-then-exec
  approach unreliable). Digest-specific "on-disk replacement" detection
  — the exact scenario `authz_approval.rs::a_changed_executable_digest_is_reevaluated_and_denied`
  proves — remains Track-A-only.
- **Not pinned by `docs_sync.rs`.** `crates/eltanin-cli/tests/docs_sync.rs`'s
  environment-variable/Quickstart-drift checks are scoped specifically
  to `canonical_e2e.rs`'s literals; this scenario introduces no parallel
  checks against `QUICKSTART.md` for its own env vars
  (`ELTANIN_AGENT_APPROVAL_REQUIRED`/`ELTANIN_AGENT_APPROVAL_STORE`/
  `ELTANIN_AGENT_REVOCATION_REQUIRED`), which are documented in
  `docs/product/CLI_CONTRACT.md` rather than the Quickstart.
