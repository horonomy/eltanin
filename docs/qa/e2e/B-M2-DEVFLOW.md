# Track B (Product/Business E2E) — B-M2-DEVFLOW Developer Flow

**Scenario ID**: `B-M2-DEVFLOW-v1`
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

## A real product gap found while building this scenario — F-M2-001 is BLOCKED, not covered

This scenario was originally designed to also cover F-M2-001 (Trusted
Compute Session): `eltanin session start` once, then several later
`eltanin run`/`eltanin approve` invocations relying on that session.
Building it against the real binaries found that this does not work:

- `eltanin-agentd`'s `session_establish_inputs`
  (`crates/eltanin-agent/src/authz/mod.rs`) sets a new session's anchor
  `leader` to `observed.workload.clone()` — the **`CreateSession`
  request's own connecting peer**, i.e. `eltanin session start`'s own
  process identity (pid + start-time).
- `eltanin session start` is a real, short-lived process that exits the
  moment it prints its result (`crate::session::run`'s own module doc:
  "establishes it and exits").
- Every later session-touching operation
  (`membership_for_peer`/`SessionState::reap`) re-collects that same
  anchor-leader pid's *current* identity and requires
  `WorkloadIdentity::compare_process` to report `Same` — which requires
  the *exact same pid*, still alive, with a matching process-start
  token (`crates/eltanin-core/src/identity.rs::compare_process`).
- Once `eltanin session start` exits, that pid is gone. Confirmed live,
  outside this test file (a standalone repro against the real
  binaries, macOS): `eltanin session start` reports
  `SessionEstablished`; the very next `eltanin session list` — a
  separate process, same real POSIX session — reports "no active
  Trusted Compute Session," not the session just established.

This means `ELTANIN_AGENT_SESSION_REQUIRED=1` behaves as a **deny-all
switch** for any real multi-invocation CLI usage, not the "prove intent
once per terminal" gate `docs/adr/0009-trusted-compute-session.md`
describes. Track A's own `crates/eltanin-agent/tests/authz_session.rs`
does not catch this because its `self_peer_context()` helper is the
*same* live test-process object used for the whole test — the anchor
leader never actually dies mid-test there, which is exactly the
condition every real separate CLI invocation produces.

**This is a product/security design question, not a QA-scenario
workaround.** Resolving the anchor leader to something that outlives
one CLI invocation (e.g. the real POSIX session leader, not the
connecting peer) changes which identity dimension the product
authorizes on — per this repo's `.claude/CLAUDE.md` §5, that requires a
founder decision and an ADR amendment, not a silent fix folded into
this scenario's test file. This record states the gap; it does not
resolve it.

Consequently: `docs/qa/e2e/README.md`'s per-Feature Track B coverage row
for F-M2-001 is `BLOCKED` (not `N/A` — an implementation exists, it is
demonstrably non-functional over the real CLI surface, distinct from
"no scenario written yet"), and this record's `COVERS` excludes it.

## Coverage — Features this scenario provides Track B evidence for

| Feature | How this scenario exercises it live |
|---|---|
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
| 7 — Locally observable caller identity is not overridable | **Track-A-only for this scenario.** Every leg here uses the same real uid throughout; the identity dimension this scenario varies is launcher path, not caller uid — `canonical_e2e.rs` already covers the uid dimension for MVP 1.0's ALLOW/DENY split. |

Invariants 2, 4, 8, and 9 have no claim in this scenario — same
"state the gap, don't paper over it" convention `F-M1-008-controlled-launch.md`
already established.

## Named limitations (not silently closed)

- **F-M2-001 is `BLOCKED`, not covered.** See the dedicated section
  above — a real product gap, not something this scenario works around.
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
