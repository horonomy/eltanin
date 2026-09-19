# Release Quality Report — Eltanin MVP 2.0 (HORO-797)

**Commit/tag tested**: `e315725c78d1f7a306707ff36a04aa1200cf31a0` (`origin/next/mvp-2.0`
tip immediately before this report's own PR — PR #74's merge commit).
This is an integration-branch evaluation, not a `main` release — per the
standing MVP 2.0 development strategy, `next/mvp-2.0` never merges to
`main` except at an explicit promotion boundary, which this report does
not authorize (see "Verdict" below).
**Test plan revision**: [`docs/qa/test-plans/mvp-2.0.md`](../../test-plans/mvp-2.0.md).
**Report date**: 2026-09-19.

## Feature inventory and per-Feature QA verdict

Cross-referencing [`docs/qa/README.md`](../../README.md)'s MVP 2.0
Feature inventory and each Feature's own Verification Record — verdicts
are not re-derived here, only summarized.

| Feature | Feature Verification Record | QA status |
|---|---|---|
| F-M2-001 — Trusted Compute Session | [`F-M2-001.md`](../../feature-verification/F-M2-001.md) | PASS (decision-layer scope) — the real multi-invocation-CLI defect below is now RESOLVED (HORO-1278/ADR 0015); see "Critical/High blockers" for the resolution history |
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
| [#70](https://github.com/horonomy/eltanin/pull/70) | HORO-1278 core redesign | Session anchor resolved from the POSIX session leader, not the connecting peer; `LeaderCorroboration` (reject-only); `HostId`/`SessionNonce`; `membership()` extended with uid/host checks; `NotMemberReason::{KeyMismatch,OwnerUidMismatch,HostMismatch,Expired,AnchorRecycled}`; second real defect closed (`owner_uid` never compared); CLI byte-for-byte unchanged |
| [#71](https://github.com/horonomy/eltanin/pull/71) | HORO-1278 operator config | F-M2-003/F-M2-004 (delegation/step-up) made operator-configurable via `ELTANIN_AGENT_GATE_CONFIG` |
| [#72](https://github.com/horonomy/eltanin/pull/72) | HORO-1278 adversarial re-run | Full 12-scenario matrix re-run against the redesigned session model; S1 defense mechanism changed, S8 split into S8a/S8b/new-S8c, S3/S12 confirmed unaffected |
| [#73](https://github.com/horonomy/eltanin/pull/73) | HORO-1278 audit fidelity | `RecordedOutcome::SessionRequired` carries a real `RecordedSessionRefusal`; `DOMAIN_SCHEMA_VERSION` 6→7; a real bug found and fixed mid-implementation (`SessionState::reap` was evicting sessions using the same fresh evidence `membership()` needed) |
| [#74](https://github.com/horonomy/eltanin/pull/74) | HORO-1278 Track B v2 | `B-M2-DEVFLOW-v2`; `COVERS` now includes F-M2-001 alongside F-M2-002/005/006 (F-M2-003/004 still correctly excluded — library-only via config file, not this scenario's env vars) |

`cargo test --workspace` at `e315725`: a full run was attempted while
assembling this report and terminated early in this environment,
completing only `eltanin-agent`'s unit-test and architecture-guard
targets (15 tests, all passing) before stopping — it did not reach
`eltanin-agent`'s own integration suites (`authz_session.rs` included),
`eltanin-core`, `eltanin-audit`, or `eltanin-cli` at all. That partial
result is not evidence of workspace health and is not presented as
such; it is disclosed here as a real, unresolved gap in this report's
own evidence rather than papered over with the PR-reported numbers
below standing in for it. The individual PR-reported counts remain
useful as a record of what each PR's own pre-merge run showed, cited
per-PR, not combined into a new workspace total this report cannot
itself confirm: PR #65 (632 tests passed, 5 pre-existing ignored), PR
#67 (644 passed, 5 ignored), and PRs #70–#74's own merge-summary counts
(112/676/685 across different scopes — not directly comparable to a
`--workspace` total and not asserted as one here). The one clean,
complete, independently-run check this report itself performed is `cargo
test -p eltanin-cli --test qa_governance_sync --test docs_sync` (the
mechanical doc-consistency checks this reconciliation PR is required to
pass): 18 passed, 0 failed, 2 suites, run twice with identical results.

Feature-level Track A evidence is cited per-Feature in each Feature
Verification Record's "Subtasks and evidence" table, not re-derived
here. Track B evidence: `crates/eltanin-cli/tests/canonical_e2e.rs`
(MVP 1.0, pre-existing) plus `mvp2_dev_flow_e2e.rs` (MVP 2.0, now
`B-M2-DEVFLOW-v2` per PR #74 — covers F-M2-001/002/005/006; F-M2-003/004
still explicitly not exercised by this scenario, both disclosed in
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
  — adding a latency field to the audit schema would force a further
  `DOMAIN_SCHEMA_VERSION` bump, invalidating every durable approval
  again, for QA instrumentation rather than a product need. (The 7th
  bump has since happened anyway, for HORO-1278's unrelated session-anchor
  redesign — that does not change this deferral's own reasoning, which
  was never "avoid the next bump at all costs," only "don't force one for
  instrumentation alone.") External wall-clock measurement is documented
  as the interim approach.
- **RESOLVED.** `origin/main`'s PRs #58/#59 (CodeQL setup + CI workflow
  token-permission hardening) were forward-merged into `next/mvp-2.0`
  by HORO-1270 (`cd952d8`) — verified directly by `git log --oneline
  origin/main | grep -iE "codeql|permission"` matching commits present
  in `origin/next/mvp-2.0`'s own history. `next/mvp-2.0`'s
  supply-chain/security-scan evidence is no longer weaker than `main`'s.
- S11 (inherited/already-open device handle): no test exists and none
  was added — `BLOCKED_ON_E3`, and a `FakeBackend`-based test would
  falsely imply device-handle security that does not exist anywhere in
  this workspace.

## Known risks

- **F-M2-003 (delegation) and F-M2-004 (step-up) had no operator-facing
  configuration surface — RESOLVED by HORO-1278 (PR #71).**
  `eltanin-agentd`'s `configure_gates` (added by PR #65) originally
  exposed session/approval/revocation only; PR #71 added
  `ELTANIN_AGENT_GATE_CONFIG`, a JSON-file-configured surface reusing
  `DelegationBounds::new`/`StepUpPolicy::new` for validation, closing
  this gap for both Features. A real deployment can now enable either.
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

1. **[Critical, RESOLVED by HORO-1278] F-M2-001 (Trusted Compute
   Session) did not survive real multi-invocation CLI usage.**
   `eltanin-agentd` anchored a session's trust to the exact process
   identity of the `eltanin session start` invocation that created it —
   a process that exits immediately after printing its result. Every
   subsequent CLI invocation (`eltanin session list`, `eltanin run`,
   etc.) was a *different* process and could not be recognized as the
   same session, so `ELTANIN_AGENT_SESSION_REQUIRED=1` behaved as a
   deny-all switch for any real usage, not the "prove intent once per
   terminal" gate ADR 0009 describes. Found by HORO-797's Track B
   scenario (PR #67, `docs/qa/e2e/B-M2-DEVFLOW.md`), missed by
   F-M2-001's own Track A suite because its test harness never let the
   anchor process die mid-test. This required a founder decision (it
   meant changing which identity dimension session trust anchors to),
   escalated per this repo's `.claude/CLAUDE.md` §5 rather than fixed as
   a QA-scenario workaround — that decision was made, and the fix
   shipped across five PRs (#70–#74, HORO-1278) landing the redesign
   recorded in [ADR 0015](../../adr/0015-trusted-compute-session-anchor-and-binding.md):
   the session anchor is now resolved from the caller's POSIX session
   leader itself, never the connecting CLI peer, proven end-to-end by
   `crates/eltanin-agent/tests/authz_session.rs::horo1278_a_session_survives_the_establishing_peer_process_exiting`
   (a real establishing-peer process is spawned, killed, and waited on,
   then a later request from a different live process in the same
   session is confirmed granted) and by Track B's own updated
   `B-M2-DEVFLOW-v2` scenario (PR #74), which now covers F-M2-001
   directly. A second, independent real defect (`owner_uid` stored but
   never compared by `membership()`) was found and closed in the same
   pass. This blocker is closed; kept in this report's history rather
   than deleted, per this campaign's evidence-preservation convention.
2. **[High] No operator-facing dogfood evidence exists.** Unchanged by
   HORO-1278 — a real human multi-hour developer session still has not
   run. What HORO-1278 changes is the premise: the session-required gate
   this dogfood session depends on is now unblocked, not merely
   documented-as-ready. Procedure and instrumentation remain as PR #66
   left them (unrun).

No other unresolved Critical/High Feature-level blocker exists as of
this report — F-M2-002 through F-M2-006's disclosed limitations are
accepted, documented trade-offs (see each record's own "Known
limitations"), not open blockers. HORO-1278/ADR 0015's own disclosed
trade-offs (S8c's TTL-not-terminal-lifetime bound; `HostId`'s current
inertness; `SessionNonce`'s write-only status; the residual pid-wrap
false-negative) are likewise accepted, documented, and not blockers —
see F-M2-001.md's "Known limitations" for the full list.

## Verdict

**READY_FOR_PRERELEASE** (MVP 2.0 Developer Preview scope only —
this is not a production/enterprise-certified verdict; see item 3
below for the exact, disclosed reason those are different claims).

This supersedes the prior "NOT DECIDED" verdict under an explicit
founder policy update (2026-09-19): human dogfood is reclassified as
non-blocking UX evidence for a prerelease unless it would expose a
concrete, otherwise-untestable security/correctness invariant, and E3
hardware evidence gates only claims that actually depend on it. Applying
that policy to this report's own accumulated evidence (below) resolves
every item the prior verdict left open.

**Basis for READY_FOR_PRERELEASE:**

1. **Resolution of Critical blocker (1) above — DONE**, as already
   recorded: the F-M2-001 session-anchor defect is resolved
   (HORO-1278/ADR 0015, PRs #70–#74), machine-proven by
   `horo1278_a_session_survives_the_establishing_peer_process_exiting`
   and Track B's `B-M2-DEVFLOW-v2`. No other unresolved Critical/High
   Feature-level blocker exists (see "Critical/High blockers" above).
2. **E3 hardware evidence — resolved as Category B, non-blocking for
   this milestone.** Auditing HORO-790 (the canonical E3 definition)
   directly: E3 is defined entirely in terms of an NVIDIA
   discovery/enforcement backend (F-M1-002/HORO-785) and a Linux
   cgroup/eBPF device-guard (F-M1-007/HORO-789) — both status **To
   Do**, meaning no NVIDIA or Linux enforcement code exists anywhere in
   this codebase, on any hardware. HORO-790 is explicitly an **MVP
   1.0** ticket ("[MVP 1.0 READY]"), gating a different Fix Version
   than HORO-797. No F-M2-\* Feature's Acceptance Criteria, ADR, or
   Feature Verification Record claims physical device-level
   enforcement — this report's own "Feature inventory" section above
   states every MVP 2.0 Feature is decision-layer only and
   `UNVERIFIED_ON_BARE_METAL` by design, not by omission. Applying the
   founder's decision rule directly: E3 is not "a core security claim
   the prerelease itself depends on," so it does not block MVP 2.0's
   Developer Preview/prerelease. It remains, unchanged and correctly
   still open, the gate for MVP 1.0's own separate HORO-790 READY
   determination — that gate is not touched, weakened, or waived by
   this report. It would also gate any future claim of
   "production-certified" or "enterprise bare-metal-verified" support
   for MVP 2.0, which this release does not make (see "Environment /
   hardware" above and `docs/product/` for the disclosed scope).
3. **Automated real-machine dogfood evidence now exists**, replacing
   the "entirely outstanding" state of the prior verdict for every
   objectively-automatable item: real `eltanin-agentd`/`eltanin`
   binaries, a real Unix-domain-socket daemon, real process spawn/kill,
   exercised via [`scripts/automated-dogfood-session.sh`](../../../../scripts/automated-dogfood-session.sh),
   with results recorded in
   [`docs/qa/dogfood/automated-session-results.md`](../../dogfood/automated-session-results.md).
   Summary: 50/50 repeated real invocations succeeded once approved (no
   session drift); two false-block probes passed (a request the
   configured policy explicitly allows was admitted; a request it
   explicitly denies was refused by the policy engine itself even with
   an approval already on file, isolating the deny path from the
   approval gate); killing the agent process (`kill -9`) produced
   fail-closed behavior, not fail-open, and a fresh agent process
   resumed enforcement correctly after restart; the raw audit log
   recorded every decision with zero unreadable/malformed lines. The
   seeded launcher-identity-change probe (F-M2-002's `LauncherDigest`
   mechanism) was **inconclusive on this host** — placing any
   freshly-built or freshly-copied binary at a new path hung at `dyld`
   startup regardless of content or signature validity, a macOS
   Gatekeeper/dyld artifact of this execution environment, not of
   `eltanin`'s own logic; the underlying invariant is separately proven
   by this codebase's own Track A regression tests
   ([`F-M2-002.md`](../../feature-verification/F-M2-002.md)), not
   re-demonstrated by this run — see
   `docs/qa/dogfood/automated-session-results.md` for the full
   disclosure. Two honest,
   non-blocking findings were also produced (real UX/performance
   friction, not a correctness or security defect): `eltanin run`
   carries roughly 900ms of overhead versus a ~23ms direct exec in this
   environment, and `eltanin session end` issued against an agent that
   restarted mid-session (and so lost its in-memory session state)
   returns an unhelpful generic error rather than a specific
   "no such session" message. Neither violates a stated correctness or
   security requirement, so per the founder's policy neither blocks
   this verdict — both are recorded here for a future UX/performance
   ticket. What remains genuinely unautomatable and still open (a
   developer's own subjective judgment of whether a denial was
   surprising or friction excessive; a self-reported bypass attempt,
   which by definition may leave no trace in the audit log) is recorded
   as open, non-blocking UX evidence in
   `docs/qa/dogfood/mvp-2.0-results.md` (still correctly UNPOPULATED —
   this report does not fabricate that evidence) rather than as a
   release blocker.
4. **The definitional call the prior verdict left open is now
   resolved** by the founder's own policy, applied above: E3 does not
   gate a decision-layer-only milestone whose Features never claimed
   physical enforcement. The competing "does 'Trusted Compute Session'
   as a product name imply real enforceability" reading is answered by
   this report's explicit, repeated scope disclosure
   (`UNVERIFIED_ON_BARE_METAL`, "Environment / hardware" above) — MVP
   2.0 has never claimed that enforceability, so nothing about this
   release's actual claims depends on E3.

**What this verdict does NOT authorize:** it does not by itself
constitute a merge of `next/mvp-2.0` into `main`. A separate,
genuinely founder-level question was surfaced while preparing that
promotion and is reported to the founder alongside this verdict (see
the accompanying report) rather than decided here: this repository's
`main` branch is documented (`docs/development/campaign-state.md`,
`CONTRIBUTING.md`) as the canonical MVP 1.0 mainline, PR-only, branch
protection enabled, and its starting SHA is pinned to the beginning of
MVP 1.0 implementation — MVP 1.0's own HORO-790 gate remains correctly
BLOCKED, not Done, on hardware. Promoting 161 commits of MVP 2.0 work
onto that branch is a release-topology decision (does `main` become
"MVP 1.0 + MVP 2.0 Developer Preview," or does MVP 2.0 tag/release from
a separate lineage) that this report deliberately does not make
unilaterally, per this repo's own `.claude/CLAUDE.md` §5 escalation
rule (scope/architecture decisions outside an already-accepted design).
This report does not mark HORO-797 Done and does not weaken any release
threshold in [`docs/qa/README.md`](../../README.md)'s release-gate
contract to make the evidence above look more favorable than it is.
