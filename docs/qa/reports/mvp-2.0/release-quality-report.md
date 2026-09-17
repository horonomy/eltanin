# Release Quality Report — Eltanin MVP 2.0 (HORO-797)

**Commit/tag tested**: `062194c841cf8b35ca04fe302d21363464b44457` (`origin/next/mvp-2.0` tip
immediately before this report's own PR). This is an integration-branch
evaluation, not a `main` release — per the standing MVP 2.0 development
strategy, `next/mvp-2.0` never merges to `main` except at an explicit
promotion boundary, which this report does not authorize (see "Verdict"
below).
**Test plan revision**: [`docs/qa/test-plans/mvp-2.0.md`](../../test-plans/mvp-2.0.md).
**Report date**: 2026-09-18.

## Feature inventory and per-Feature QA verdict

Cross-referencing [`docs/qa/README.md`](../../README.md)'s MVP 2.0
Feature inventory and each Feature's own Verification Record — verdicts
are not re-derived here, only summarized.

| Feature | Feature Verification Record | QA status |
|---|---|---|
| F-M2-001 — Trusted Compute Session | [`F-M2-001.md`](../../feature-verification/F-M2-001.md) | PASS (decision-layer/library scope) / **BLOCKED for real multi-invocation CLI usage** — see "Critical/High blockers" |
| F-M2-002 — Remembered Authorization Intent | [`F-M2-002.md`](../../feature-verification/F-M2-002.md) | PASS (decision-layer scope; AC4 partially met — interpreter/script re-evaluation structurally out of reach, disclosed) |
| F-M2-003 — Bounded Compute Delegation | [`F-M2-003.md`](../../feature-verification/F-M2-003.md) | PASS (decision-layer scope; admission-side only; library-reachable only, no operator env-var surface) |
| F-M2-004 — Risk-Based Step-Up | [`F-M2-004.md`](../../feature-verification/F-M2-004.md) | PASS (decision-layer scope; classification layer, not a fourth gate; library-reachable only) |
| F-M2-005 — Compute Lease Lifecycle Hardening | [`F-M2-005.md`](../../feature-verification/F-M2-005.md) | PASS (decision-layer scope; two real fail-open bugs found and fixed during implementation, regression-pinned) |
| F-M2-006 — Audit Durability + Shadow Enforcement Mode | [`F-M2-006.md`](../../feature-verification/F-M2-006.md) | PASS (decision-layer scope; shadow mode explicitly not a security control; one disclosed differential-coverage gap) |

Every MVP 2.0 Feature is decision-layer only — no Feature's claim
depends on physical device enforcement (no cgroup/eBPF/NVML enforcement
code exists anywhere in this workspace: `crates/eltanin-apple/src/backend.rs`
maps `DeviceEnforce`/`DeviceRevoke` to `Unsupported` unconditionally;
`eltanin-linux`/`eltanin-macos` are identity collectors, not enforcement
backends; `FakeBackend` is a scripted double). Every Feature therefore
carries `UNVERIFIED_ON_BARE_METAL` per the test plan's hardware section,
distinct from the F-M2-001 CLI-usage defect below, which is a real
software defect independent of hardware availability.

## Environment / hardware

All automated evidence in this report ran on developer workstations —
no Linux/NVIDIA bare-metal hardware exists in this environment (E3,
tracked separately under HORO-790/MVP 1.0, permanently distinct from
MVP 2.0's own scope). Track A ran via `cargo test --workspace` on
macOS (Apple Silicon) during implementation of each subtask; CI ran
both a Linux (`ubuntu-latest`, no-GPU/fake-backend) and a macOS runner
for every merged PR (`rustfmt`, `clippy` ×2, `test` ×2, `cargo doc`,
`cargo-deny` — 7 checks, all green on every PR cited below). No hardware
evidence exists or is claimed for any MVP 2.0 Feature.

## Automated suites executed

All of the following merged into `next/mvp-2.0` with 7/7 CI checks
green (rustfmt, clippy ×2 platforms, test ×2 platforms, cargo doc,
cargo-deny) and were spot-checked for design/scope compliance before
merge:

| PR | Ticket/subtask | Contents |
|---|---|---|
| [#63](https://github.com/horonomy/eltanin/pull/63) | HORO-797 adversarial matrix | 7 new regression tests covering the 12-scenario matrix (S3–S8, S12); S1/S2/S9/S10 confirmed already covered by pre-existing tests; S11 confirmed `BLOCKED_ON_E3`, no test added |
| [#64](https://github.com/horonomy/eltanin/pull/64) | HORO-797 test plan + FV records | `docs/qa/test-plans/mvp-2.0.md`, 6 Feature Verification Records, `qa_governance_sync.rs` generalized to check both MVP milestones |
| [#65](https://github.com/horonomy/eltanin/pull/65) | HORO-797 prep (D1 fix) | `eltanin-agentd` gate-configuration exposure (`ELTANIN_AGENT_SESSION_REQUIRED`, `_APPROVAL_REQUIRED`+`_APPROVAL_STORE`, `_REVOCATION_REQUIRED`); 632 tests passed, 5 pre-existing ignored |
| [#66](https://github.com/horonomy/eltanin/pull/66) | HORO-797 dogfood prep | Dogfood procedure, `scripts/dogfood-metrics.sh` (validated against real generated audit logs including rotation/malformed-line edge cases), unpopulated results template |
| [#67](https://github.com/horonomy/eltanin/pull/67) | HORO-797 Track B scenario | `B-M2-DEVFLOW-v1` (`mvp2_dev_flow_e2e.rs`); 644 tests passed, 5 ignored; **found the F-M2-001 session-anchor defect below** |

`cargo test --workspace` at `062194c` (from PR #65's and #67's own
pre-merge runs, the two most recent full-workspace runs in this
sequence): 644 passed, 5 ignored, 0 failed.

Feature-level Track A evidence is cited per-Feature in each Feature
Verification Record's "Subtasks and evidence" table, not re-derived
here. Track B evidence: `crates/eltanin-cli/tests/canonical_e2e.rs`
(MVP 1.0, pre-existing) plus the new `mvp2_dev_flow_e2e.rs` (MVP 2.0,
`B-M2-DEVFLOW-v1`, covering F-M2-002/005/006 — F-M2-001 explicitly
excluded, F-M2-003/004 explicitly not exercised, both disclosed in
`docs/qa/e2e/B-M2-DEVFLOW.md`'s "Named limitations").

## Manual checks

None. Every check in this report is either CI-automated or a direct
source/git-history read performed while assembling the Feature
Verification Records and this report — no manual functional testing
was performed, and none is claimed.

## Failed / skipped / deferred, and why

See [`docs/qa/test-plans/mvp-2.0.md`](../../test-plans/mvp-2.0.md)'s
"Open gaps summary" for the full list. Highlights relevant to this
gate:

- Structured fuzzing, property-based testing: deferred, unchanged from
  MVP 1.0's posture.
- Privileged Linux/cgroup/eBPF integration tests, hardware compatibility
  matrix: deferred, blocked on E3 (no hardware access exists).
- Upgrade/rollback testing: newly REQUIRED-but-uncovered as of MVP 2.0
  (durable on-disk state — approval store, rotated audit log — now
  exists with a real migration consequence across 5 schema bumps this
  milestone; no coverage exists yet).
- Latency/overhead instrumentation: deferred by explicit design choice
  — adding a latency field to the audit schema would force a 7th
  `DOMAIN_SCHEMA_VERSION` bump, invalidating every durable approval
  again, for QA instrumentation rather than a product need. External
  wall-clock measurement is documented as the interim approach.
- `origin/main`'s two most recent commits (PRs #58/#59, CodeQL setup +
  CI workflow token-permission hardening) are not yet merged forward
  into `next/mvp-2.0` — this branch's supply-chain/security-scan
  evidence is weaker than `main`'s until that forward-merge happens.
  Independent of this report; does not block it.
- S11 (inherited/already-open device handle): no test exists and none
  was added — `BLOCKED_ON_E3`, and a `FakeBackend`-based test would
  falsely imply device-handle security that does not exist anywhere in
  this workspace.

## Known risks

- **F-M2-003 (delegation) and F-M2-004 (step-up) have no operator-facing
  configuration surface.** `eltanin-agentd`'s `configure_gates` (added
  by PR #65) exposes session/approval/revocation only — both take
  structured multi-field configuration (`DelegationBounds`,
  `StepUpPolicy`) with no scalar env-var story, deliberately left
  library-only. A real deployment cannot enable either today.
- **The dogfood evidence gap is total, not partial.** No human
  multi-hour developer session has been run. The procedure,
  instrumentation, and an explicitly-unpopulated results template exist
  (PR #66) — the actual low-friction/prompt-count/false-block/
  bypass-attempt/latency claims that only a real session can produce do
  not exist yet, and this report does not simulate or estimate them.
- **Every MVP 2.0 Feature is `UNVERIFIED_ON_BARE_METAL`.** Decision-layer
  correctness is evidenced; physical device enforcement is not, and
  cannot be, until E3 hardware exists.

## Critical/High blockers

1. **[Critical] F-M2-001 (Trusted Compute Session) does not survive real
   multi-invocation CLI usage.** `eltanin-agentd` anchors a session's
   trust to the exact process identity of the `eltanin session start`
   invocation that created it — a process that exits immediately after
   printing its result. Every subsequent CLI invocation
   (`eltanin session list`, `eltanin run`, etc.) is a *different*
   process and cannot be recognized as the same session, so
   `ELTANIN_AGENT_SESSION_REQUIRED=1` behaves as a deny-all switch for
   any real usage, not the "prove intent once per terminal" gate
   ADR 0009 describes. Found by HORO-797's Track B scenario (PR #67,
   `docs/qa/e2e/B-M2-DEVFLOW.md`), missed by F-M2-001's own Track A
   suite because its test harness never lets the anchor process die
   mid-test. **Resolving this requires a founder decision**: it means
   changing which identity dimension session trust anchors to (e.g. the
   real POSIX session leader instead of the connecting peer), which
   per this repo's `.claude/CLAUDE.md` §5 needs an ADR 0009 amendment,
   not a QA-scenario workaround. Not fixed as part of this pass —
   deliberately, per that same escalation rule.
2. **[High] No operator-facing dogfood evidence exists.** Distinct from
   (1): even once (1) is resolved, no real human session has validated
   the low-friction product claim. Procedure and instrumentation are
   ready (PR #66); the session itself has not run.

No other unresolved Critical/High Feature-level blocker exists as of
this report — F-M2-002 through F-M2-006's disclosed limitations are
accepted, documented trade-offs (see each record's own "Known
limitations"), not open blockers.

## Verdict

**NOT DECIDED — awaiting founder judgment.**

This report deliberately does not render a GO/NO-GO/CONDITIONAL
recommendation in place of
[`reports/TEMPLATE.md`](../TEMPLATE.md)'s "Final QA/Security
recommendation" section — the MVP 2.0 promotion/release decision is
reserved to the founder, per this campaign's standing instruction. What
follows is the accumulated evidence needed to decide, not a substitute
for deciding.

**What's needed to decide, concretely:**

1. **Resolution of Critical blocker (1) above** — the F-M2-001 session-
   anchor defect. This is the single largest open item: as shipped
   today, the flagship "Trusted Compute Session" feature this milestone
   is named for does not work over the real CLI.
2. **A real human multi-hour developer dogfood session**, using
   `docs/qa/dogfood/mvp-2.0-developer-session.md` and
   `scripts/dogfood-metrics.sh`, populating
   `docs/qa/dogfood/mvp-2.0-results.md` — cannot meaningfully happen
   until (1) is resolved, since the session-required gate is the
   product's own headline low-friction claim.
3. **E3 hardware evidence** — still entirely absent, tracked separately,
   not newly introduced by this report.
4. **A definitional call this report surfaces but does not resolve**:
   `docs/qa/README.md`'s release-gate contract requires every required
   Feature to be QA status **PASS** (item 2) and hardware evidence only
   for Features whose claim depends on physical enforcement (item 5).
   Every MVP 2.0 Feature is decision-layer only, so one reading says E3
   does not gate this milestone at all; a competing reading says
   "Trusted Compute Session" as a *product* claim implies real
   enforceability, which blocker (1) shows it currently lacks
   independent of E3. Separately: does the release-gate contract's PASS
   requirement admit a Feature (F-M2-003/004) that is implemented and
   Track-A-tested but not operator-enableable at all? Neither question
   is resolved by this report; both are stated so the founder can decide
   with the actual evidence in view, not a pre-selected framing.

This report does not authorize merging `next/mvp-2.0` into `main`, does
not mark HORO-797 Done, and does not weaken any release threshold in
[`docs/qa/README.md`](../../README.md)'s release-gate contract to make
the evidence above look more favorable than it is.
