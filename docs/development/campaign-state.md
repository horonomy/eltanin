# Campaign State — Eltanin MVP 1.0 (HORO-772)

Durable execution-state record. Read this + Jira + `git fetch origin
--prune` at the start of every resumed session before continuing.

## Canonical facts

- Canonical repo: `horonomy/eltanin` (public), created 2026-09-10.
- Starting `main` SHA for MVP 1.0 implementation (HEAD immediately before
  the HORO-821 reconciliation PR merges): `e9ab11f8bc954c1614602ad41d9ed994be22e1db`.
- Canonical branch: `main`, PR-only (branch protection enabled, 1 required
  approval, no force-push/delete).
- Jira: continuing in project `HORO` (no dedicated `ELTN` project — see
  `bootstrap-reconciliation.md` §4).
- Fix Version: `Eltanin MVP 1.0 — Authorization Happy Path` (id `10192`);
  description updated 2026-09-12 to state the three-evidence-class model
  (see "Apple Silicon scope amendment" below).
- Goal: `Eltanin G1` (`CBLPCRLM-19`), linked to HORO-772 only. **Name/
  description still read the old NVIDIA-only wording** — no Atlassian
  connector tool exists to edit an existing Goal (confirmed empirically,
  not assumed); a `createGoalUpdate` traceability note records the
  intended canonical wording, and the exact smallest manual UI action is
  documented on HORO-1009. Not blocking — HORO-1011 proceeded regardless
  per the founder's own contingency instruction.
- Components: `Eltanin :: {Repo & Governance, Core, Backend, NVIDIA,
  Linux Platform, Device Guard, Protocol, Agent, CLI, Audit, QA, Docs}`
  (ids 10145–10156), plus `Eltanin :: Apple Silicon` (id `10163`) and
  `Eltanin :: macOS Platform` (id `10164`), added 2026-09-12 via direct
  authenticated REST (no connector tool exists for component creation
  either) and backfilled onto HORO-1010 through HORO-1015 preserving
  each ticket's pre-existing components.

## Apple Silicon scope amendment (2026-09-12)

A product/architecture scope amendment approved 2026-09-12 adds Apple
Silicon (physical MacBook Pro M3 Max) as a second real-hardware evidence
class for MVP 1.0, alongside the original Linux/NVIDIA class. The North
Star ("no protected compute without authorization") is unchanged — this
is additive scope, not a pivot away from the NVIDIA enforcement gate.

**Three evidence classes** (superseding the old two-class Fake/NVIDIA
model; see [ADR 0006](../adr/0006-cross-accelerator-capability-and-memory-model.md)):
- **E1** — Fake/simulated, deterministic CI.
- **E2** — Apple Silicon real-accelerator functional evidence (physical
  M3 Max): real Metal GPU compute, full ALLOW/DENY application-level
  flow. `DeviceEnforce`/`DeviceRevoke` are `Unsupported`/`NotEvaluated`
  by definition — never a device-level protection claim.
- **E3** — Linux/NVIDIA physical device-level enforcement (F-M1-007,
  HORO-841/844). The sole mandatory hard security gate, unreplaceable
  by E2. Apple-only-PASS is `BLOCKED ON E3`, never `READY`.

**New Feature F-M1-010 / HORO-1010** (Apple Silicon Real-Accelerator
Functional Validation), with an internal dependency chain (via Jira
issue links, authoritative over any assumption): **HORO-1011**
(capability/memory model) → blocks **HORO-1012** (Metal backend) and
**HORO-1013** (macOS platform/IPC/launch), which may run in parallel
once HORO-1011 merges → HORO-1012 blocks **HORO-1014** (native Metal
fixture) → **HORO-1015** (physical M3 Max QA, Track B scenario
`B-M1-APPLE`) starts only after HORO-1012/1013/1014 all merge to `main`.

**HORO-790 (MVP 1.0 READY gate) was rewritten** to the three-evidence-
class model: READY = E1 + E2 + E3 all PASS + all Feature QA PASS +
Track A PASS + `B-M1-APPLE` PASS + `B-M1-NVIDIA` PASS + Docs Impact
closed + Release Quality Report.

**Privileged-enforcement blast-radius safety invariant** (HORO-1018,
2026-09-12): before any privileged cgroup/eBPF/device-node/hardware
enforcement test, [`docs/qa/privileged-enforcement-testing.md`](../qa/privileged-enforcement-testing.md)
is now a mandatory pre-test gate (`.claude/CLAUDE.md` §6) — only a new
disposable workload created for the test may be denied/killed/
constrained, never the orchestrator/agent session/controlling shell/any
pre-existing process. Governs HORO-841/844/790/1015 at minimum.

## Completed

| Ticket | What | PR | Merge commit |
|---|---|---|---|
| HORO-780 | Jira metadata bootstrap (Fix Version, Goal, Components, backfill) | n/a (Jira REST) | n/a |
| HORO-781 | Canonical repo + governance scaffold (README/LICENSE-placeholder/SECURITY/CONTRIBUTING/CODEOWNERS/.gitignore/dir layout) | seed commit (pre-branch-protection, documented exception) | `9d96594` |
| HORO-781 | PR template | #1 | `e9ab11f` |
| HORO-821 | Bootstrap reconciliation doc + this campaign-state.md | #2 | `5dd6728` |
| HORO-783 | Rust workspace, CI (fmt/clippy/test/doc/deny), cargo-deny policy | #3 | `d430c9c` |
| HORO-782 | North Star, Security Model, Product Constitution, ADRs 0001–0004 | #4 | `793c522` |
| HORO-783 | Crate layout reconciled with Epic Component table (`eltanin-core/backend/protocol/agent/cli`) | #5 | `e1e71ec` |
| HORO-772 | Campaign-state.md update (prior pass) | #6 | `45c36cf` |
| HORO-825 | F-M1-001: resource domain (`Versioned<T>` envelope, `ResourceVendor`/`ResourceKind` opaque newtypes, `Capability`/`ResourceCapabilities`, `ComputeRequest`, `EnforcementResult`) | #7 | `e8896b5` |
| HORO-826 | F-M1-001: `ComputeBackend` trait contract + `BackendError` | #8 | `ea3214c` |
| HORO-827 | F-M1-001: `FakeBackend` deterministic test double | #9 | `856461f` |
| HORO-831 | F-M1-003: `WorkloadIdentity`/`ExecutionContext` trust contract (`Evidence<T>`, `IdentityComparison`) | #10 | `f2f3fd8` |
| HORO-832 | F-M1-003: Linux `/proc`-based workload context collection (`crates/eltanin-linux`) | #11 | `e190a1b` |
| HORO-833 | F-M1-003: spoof/PID-reuse/exit-race regression coverage, `ProvenanceRecord`, first Feature Verification Record, review-driven `compare_process` self-asserted-evidence fix | #12 | `dd570f3` |
| HORO-834 | F-M1-004: `PolicySet`/`PolicyDecision` default-deny policy engine, review-driven `IndeterminateEvidence` fail-closed fix | #13 | `42dfbf7` |
| HORO-835 | F-M1-004: replay/malformed-policy/multi-vector spoof regression coverage, docs-synced policy example, second Feature Verification Record, 4 review-driven test fixes | #14 | `5e99896` |
| HORO-836 | F-M1-005: `ComputeLease`/`LeaseIssuer` scoped expiring authorization artifact (`crates/eltanin-core/src/lease.rs`), review-driven `compare_executable`/`ExecutableMismatch` fix | #15 | `e822bfd` |
| HORO-837 | F-M1-005: renewal-boundary regression coverage, third Feature Verification Record | #16 | `f0457ae` |
| HORO-838 | F-M1-006: versioned local IPC protocol types (`crates/eltanin-protocol`) — `RequestId`/`ClientRequest`/`AgentResponse`/framing, opus-architect-designed, review-driven `AgentStatus` unit-variant `deny_unknown_fields` fix | #17 | `93ebfd4` |
| HORO-839 | F-M1-006: privileged local agent lifecycle — UDS listener (`BoundSocket`), `SO_PEERCRED` peer credential collection (`eltanin_linux::peer`, `rustix`-based per founder decision to preserve `#![forbid(unsafe_code)]`), bounded single-request connection handling, `RequestHandler` seam, graceful shutdown/drain, review-driven `test-support`-feature-gating and accept-loop spawn-panic fixes | #18 | `86b29bd` |
| HORO-840 | F-M1-006: policy/lease/backend integration (`eltanin-agent::authz`), lease-binding-subject decision (connecting peer process, not cgroup), `ReleaseLease` cross-client/execve-substitution discharge, `eltanin-agentd` daemon binary, `SIGTERM`/`SIGINT` wiring (`signal-hook` per founder decision D2), fourth Feature Verification Record (F-M1-006, closing HORO-788) | #19 | `323827e` |
| HORO-824 | F-M1-009: local audit & explain evidence (`crates/eltanin-audit`) — append-only NDJSON `AuditRecord` schema with hand-written `Recorded*` mirrors, best-effort-durability sink (founder decision D-A), sequence-gap detection, `eltanin-explain` reader, `eltanin-agent::authz::audit::AuditEventSink` adapter, fifth Feature Verification Record (F-M1-009), 4 review-driven fixes (gap-detection leading-edge blind spot, sequence/file-order divergence, version-skew-vs-lost-write conflation, non-UTF-8 env var silent fallback) | #20 | `ae5e2a3` |
| HORO-845 | F-M1-008 subtask 1/3: `eltanin run` CLI contract — [ADR 0005](../adr/0005-eltanin-run-process-topology.md) (supervisor process topology), argv/profile/exit/failure/sequence types (`crates/eltanin-cli`), founder decision D-B (workload-executable-identity gap accepted for MVP 1.0, HORO-988 filed), 5 review-driven fixes (exit-code overlap-claim corrections, doc/code sync test tightening, 126/127 ambiguity documented, profile control-character rejection) | #21 | `198dff9` |
| HORO-846 | F-M1-008 subtask 2/3: `eltanin run` launch/exit/cleanup lifecycle — UDS client (`crate::client`, connect-per-request), profile filesystem loader (`crate::profile`), governed-execution-context seam (`crate::context::NullContext`), signal forwarding (`crate::signals`), spawn/supervise/renew/release driver (`crate::supervise`), S0-S11 orchestrator (`crate::launch`); `eltanin-protocol::framing` gained the client-direction `encode_request`/`decode_response` mirror pair; `eltanin-agent/tests/authz_renewal.rs` pins the server-side renewal semantics the design depends on; 6 review-driven fixes (2 HIGH `Instant+Duration` overflow-panic fixes via `safe_deadline`, architecture-guard heuristic-limitation doc fix + expanded shell-pattern list, renewal-denial test strengthening, timing-margin widening, `spawn_failure_code` taxonomy note) | #22 | `d395017` |
| HORO-847 | F-M1-008 subtask 3/3: canonical Product/Business E2E scenario `E2E-F-M1-008-controlled-launch-v1` (`crates/eltanin-cli/tests/canonical_e2e.rs`, real `eltanin-agentd`+`eltanin` binaries, real UDS socket and on-disk policy, Linux-only) plus `docs/product/QUICKSTART.md` and the Track B record `docs/qa/e2e/F-M1-008-controlled-launch.md`; `docs_sync.rs` gained 5 new pinning assertions; 9 review-driven fixes plus a 10th real bug caught by CI (`eltanin-agentd` never seeded `FakeBackend` with any resource — fixed via new `PolicySet::resources()`) | #23 | `5cedf83` |
| HORO-823 | F-M1-008 rollup: single Feature Verification Record (`docs/qa/feature-verification/F-M1-008.md`) once all three subtasks landed | #24 | `fd42434` |
| HORO-814 | Claude Code project gate (`.claude/CLAUDE.md`) + Codex adapter (`AGENTS.md`) — the only concrete gap found, everything else already existed from HORO-781/782/783; 5 review-driven fixes (branch-format statement, CONTRIBUTING.md dedup, escalation-section gaps, DoD pointer) | #25 | `2f21164` |
| HORO-814 | campaign-state.md sync after PR #24/#25 | #26 | `59d6acd` |
| HORO-819 | Formalized feature-level QA verification governance (`docs/qa/README.md`, `docs/qa/feature-verification/TEMPLATE.md`) — Feature Definition, Feature inventory, release-gate contract, distilled from existing practice; 5 review-driven fixes (2 overclaims of template universality corrected, one deferred AC named, 2 inventory-table clarity fixes) | #27 | `0b5b980` |
| HORO-819 | campaign-state.md sync after PR #26/#27 | #28 | `28fccfd` |
| HORO-820 | Documentation governance (`docs/development/documentation-governance.md`) — User/Operator-vs-Contributor audience split, Change-to-Docs rule table, the only concrete gap found; amended `docs/qa/README.md`'s release-gate item 6 and added a PR-template pointer; 3 review-driven fixes (1 blocking false citation fixed by making it true, 2 medium: coverage overclaim, missing PR-template pointer) | #29 | `4cfd56c` |
| HORO-810 | Versioned MVP 1.0 QA/Security test plan (`docs/qa/test-plans/mvp-1.0.md` — 10-layer quality model, North Star invariant→test-file map, honest hardware-evidence section), `docs/qa/reports/TEMPLATE.md`, `crates/eltanin-cli/tests/qa_governance_sync.rs` (4 mechanical drift-guard tests extending the `docs_sync.rs` pattern); 4 review-driven fixes (H1 dangling-link, M1 tokenizer prefix-escape, M2 path-escape, M3 `.md`-vs-`.yaml` FVR reconciliation) | #31 | `e1493a4` |
| HORO-810 | campaign-state.md sync after PR #31 | #32 | `1de70f3` |
| HORO-811 | Track B scenario index (`docs/qa/e2e/README.md` — scenario manifest, per-Feature coverage table, release-gate notes), North Star assertions table added to `docs/qa/e2e/F-M1-008-controlled-launch.md`, `.github/workflows/ci.yml` split into named Track B (`canonical_e2e`) then Track A (`--workspace`) steps, `qa_governance_sync.rs` extended with 4 Track B drift-guard tests; 5 review-driven fixes (H1 wrong-crate citation, M2 one-directional→set-equality coverage checks, M3 `../`-escape guard, M4 `.rs`-link existence check, L5 magic-number removal) | #33 | `660c87e` |
| HORO-811 | campaign-state.md sync after PR #33 | #34 | `d8bc5a5` |
| HORO-781 | Adopted Apache License 2.0 (founder decision) — `LICENSE`/`NOTICE`, `license.workspace = true` on every crate, `deny.toml` comment reconciled, `README.md`/`bootstrap-reconciliation.md` updated (historical "License (MAJOR DECISION)" note left as written, dated resolution pointer added below it) | #35 | `3e44a16` |
| HORO-790 | Hardware-validation runbook (`docs/development/hardware-validation-runbook.md`) for F-M1-002/HORO-785, F-M1-007/HORO-789, and this ticket — GPU/kernel/driver/capability requirements, own-workstation-vs-rented-hardware guidance, exact setup/test/cleanup commands, expected evidence; `scripts/hardware-preflight-check.sh` and `scripts/hardware-evidence-capture.sh` (read-mostly, shellcheck-clean automation). Preparation only — no hardware provisioned, no evidence exists, no AC weakened | #36 | `dcb5036` |
| HORO-1018 | Privileged-enforcement-testing blast-radius governance (`docs/qa/privileged-enforcement-testing.md`) — blast-radius model, 12-point abort-on-failure preflight, 4-level safe escalation, no-spawn-then-restrict-race requirement, collateral-damage assertion checklist; `.claude/CLAUDE.md` §6 gate added; additive Jira comments on HORO-841/844/790/1015 | #38 | `1923cad` |
| HORO-1011 | F-M1-010 subtask: cross-accelerator capability/memory model — `Capability` expanded 5→9 explicit dimensions (adds `ObserveWorkload`/`ControlledLaunch`, renames the rest), `ResourceCapabilities` reshaped to a `Capability`→`SupportState` map (Supported/Partial/Unsupported/NotEvaluated), new `AcceleratorMemory` (Dedicated/Unified/NotReportable) on `ProtectedResource`; [ADR 0006](../adr/0006-cross-accelerator-capability-and-memory-model.md); design pre-reviewed by opus-architect; one real bug (stale `"enforce"` wire literal) caught by CI and fixed | #39 | `617befd` |
| HORO-1012 | F-M1-010 subtask: Apple Silicon Metal backend (`crates/eltanin-apple`) — `objc2`/`objc2-metal`-based device discovery (`AppleBackend`), `DeviceSnapshot`→`ProtectedResource` capability/memory mapping honesty (only `DiscoverResource` fully `Supported`; `enforce`/`revoke` unconditionally `Unsupported`), a single scoped `#[allow(unsafe_code)]` real Metal compute probe verified on physical Apple Silicon; [ADR 0007](../adr/0007-apple-silicon-metal-backend.md) | #41 | `ff5ff58` |
| HORO-1012 | Fix compute-probe non-macOS error's capability claim + correct ADR 0007's per-crate license claim (review-driven follow-up) | #42 | `a3a39de` |

Current `main` HEAD: `a3a39de`. F-M1-001, F-M1-003, F-M1-004, F-M1-005,
F-M1-006, F-M1-008, F-M1-009 are done. HORO-814/819/820/810/811/781/1018
(governance + license) are done. HORO-1011 (Apple Silicon capability/
memory model) and HORO-1012 (Apple Silicon Metal backend) are done.
HORO-790's hardware-validation runbook is ready and waiting on the
founder to provide real Linux/NVIDIA hardware. HORO-1013 (macOS
platform/IPC/controlled-launch adapter) is in progress — see "Next
planned action" below.

**Process note (found while resuming this campaign for HORO-1013):**
this file had not been synced after HORO-1012's PRs #41/#42 merged —
the rows above and the HEAD pointer were missing until this pass. Fixed
here rather than left for a future sync, since a stale "next planned
action" pointing at already-merged work would have misled the next
resumed session.

## Active worktrees

None.

## Dependency blockers

None for hardware-free work. Real-hardware-dependent tickets (HORO-841,
F-M1-002 real NVIDIA validation, F-M1-007 real enforcement, HORO-790,
final MVP 1.0 READY gate) are blocked pending a bare-metal Linux/NVIDIA
host — flagged as a MAJOR DECISION (external resource / cost), not yet
formally raised as its own escalation beyond the note in
`bootstrap-reconciliation.md` §6.

## Feature QA states

F-M1-003 (HORO-786), F-M1-004 (HORO-787), F-M1-005 (HORO-822),
F-M1-006 (HORO-788), F-M1-008 (HORO-823), and F-M1-009 (HORO-824): Done,
Feature Verification Record PASS — `docs/qa/feature-verification/F-M1-003.md`
(HORO-833), `F-M1-004.md` (HORO-835), `F-M1-005.md` (HORO-837),
`F-M1-006.md` (HORO-840), `F-M1-008.md` (HORO-823, HORO-845/846/847),
`F-M1-009.md` (HORO-824). F-M1-001/002/007 — no Feature Verification
Record yet. Governance/foundation work (HORO-780/781/782/783/821) is
done; F-M1-001 (HORO-784/825/826/827) is functionally complete but has
no formal record yet. F-M1-002 (real NVIDIA backend) and F-M1-007 (real
cgroup/device-BPF enforcement) are blocked on bare-metal Linux/NVIDIA
hardware access (see "Dependency blockers" below) — no hardware-free
subtask work remains identified for either as of this pass.

F-M1-010 (Apple Silicon Real-Accelerator Functional Validation,
HORO-1010): HORO-1011 (capability/memory model subtask) and HORO-1012
(Metal backend subtask) are Done, no Feature Verification Record yet
(per HORO-1010's own scope, not either subtask's — F-M1-010 PASS
requires all of HORO-1011/1012/1013/1014 merged + Track A + Track B
`B-M1-APPLE` + physical M3 Max evidence). HORO-1013 (macOS platform
adapter) is in progress — hardware-free implementation work in the
sense that no physical M3 Max provisioning is required (this session's
development environment was a real Apple Silicon host; the shared dev
machine's `cargo` lock contention on `~/.cargo/shared-target` initially
blocked all local `cargo` runs, but pointing `CARGO_TARGET_DIR` at a
private directory bypassed it — see PR #43's verification notes for the
resulting real local `clippy`/`test`/`deny`/`doc` runs, including 11
tests executing genuine `LOCAL_PEERCRED`/`LOCAL_PEERPID`/`libproc`
syscalls on this machine's own kernel. This remains a
development-environment convenience, not the HORO-1015
hardware-evidence gate — worth recording for future sessions hitting
the same shared-target contention: `CARGO_TARGET_DIR=<private-dir>
cargo <subcommand> ...` is the fix, no need to wait out the lock).

## Required human decisions outstanding

1. Bare-metal Linux/NVIDIA hardware provisioning for F-M1-002/007/HORO-841/
   MVP 1.0 READY. A complete setup/test/cleanup runbook is ready
   ([`docs/development/hardware-validation-runbook.md`](hardware-validation-runbook.md))
   so the founder's actual provisioning decision is the only remaining
   step — see that runbook's §1 for the own-workstation-vs-rented-hardware
   recommendation.

License choice for `horonomy/eltanin` (HORO-781) was resolved
2026-09-12: **Apache License 2.0**, founder decision (PR #35, `3e44a16`).

## Hardware evidence state

Not started. No representative bare-metal Linux/NVIDIA host identified
yet in this environment. A complete setup/test/cleanup runbook is
prepared — [`docs/development/hardware-validation-runbook.md`](hardware-validation-runbook.md)
— so that once a host is available, execution time is spent running
the plan, not writing it. The runbook itself contains no hardware
evidence; it is preparation only.

## Remaining release gates

HORO-790's rewritten "MVP 1.0 READY Gate" (see "Apple Silicon scope
amendment" above): E1 + E2 + E3 all PASS + all Feature QA PASS + Track A
PASS + `B-M1-APPLE` PASS + `B-M1-NVIDIA` PASS + Docs Impact closed +
Release Quality Report. E1 (Fake/CI) evidence exists throughout this
campaign's Track A suite. E2 (Apple Silicon) and E3 (Linux/NVIDIA) both
require physical hardware not yet available in this environment —
E2 needs the founder's own M3 Max (HORO-1015), E3 needs founder-provided
bare-metal Linux/NVIDIA (HORO-841, see "Dependency blockers"). Apple-
only-PASS is explicitly `BLOCKED ON E3`, never `READY`, per HORO-790's
own gate definition — an all-Apple-hardware pass would not itself
satisfy this gate.

## Lessons from this pass (process, not product)

- HORO-781's initial "Initial Repository Shape" crate list and the Epic's
  own Component table + Feature tickets' "Primary package" paths
  disagreed. Caught by independent PR review after HORO-783 shipped the
  wrong one, fixed while crates were still empty (PR #5). **Going
  forward: before scaffolding any new crate/directory, cross-check its
  name against the Jira Component table on HORO-772/780 and any Feature
  ticket that names a "Primary package" path — that's the authoritative
  source, not a Task-ticket's own initial proposal.**
- `crates/eltanin-cli/tests/launch_lifecycle.rs`'s
  `a_renewal_denial_does_not_terminate_the_workload_early` failed once
  on real GitHub Actions CI (PR #35) with a `sleep 1.7s` vs. 2s
  renewal-deadline margin — passed clean on an immediate re-run,
  confirming it's a timing-margin-sensitive flake on a shared CI
  runner, not a regression (that PR touched zero Rust source). Not
  fixed here — out of scope for a license PR — but worth a future
  ticket if it recurs: widen the margin or make the assertion
  timing-independent (e.g. assert on the renewal count/sequence rather
  than wall-clock-adjacent exit-code timing).
- A global find/replace of `Capability::Enforce` etc. (HORO-1011's
  variant rename) missed a bare wire-string JSON literal
  (`"enforce"` not preceded by `Capability::`) in
  `eltanin-backend/tests/contract.rs` — caught by CI's real test run,
  not the local `cargo check`/`clippy` pass, since both compile
  successfully against a *wrong* string constant. **Lesson: after any
  enum-variant rename touching a `#[serde(rename_all)]` type, grep for
  the old *wire* strings (quoted, snake_case) separately from the old
  *Rust identifier* — compilation proves the code is well-typed, never
  that a hand-written literal still matches.**
- This session's shared dev machine repeatedly hit extreme load (peaks
  36-67 across 37 concurrent users) during HORO-1011, causing
  `cargo test --workspace`/`cargo doc --workspace` to die silently with
  no output and no process, even when auto-backgrounded with a 590s
  timeout — not a code issue. Per-crate/per-test-file runs
  (`cargo test -p <crate> --test <file>`) mostly still succeeded and
  were used to verify every touched file individually; `cargo check
  --workspace --all-targets` and `cargo clippy --workspace --all-targets
  -- -D warnings` (both lighter than a full test run) also completed and
  were clean. The full-suite gate was deferred to GitHub Actions CI
  (unaffected by local contention) rather than fought further locally —
  this caught the real bug above. **Lesson: under sustained extreme
  local load, prefer `cargo check`/`clippy`/targeted `--test` runs plus
  real CI as the authoritative full-suite gate, rather than repeatedly
  retrying a full local `cargo test --workspace`.**

## Next planned action

F-M1-001, F-M1-003, F-M1-004, F-M1-005, F-M1-006, F-M1-008, F-M1-009 are
done. F-M1-002 (HORO-785) and F-M1-007 (HORO-789), plus HORO-790 (MVP
1.0 READY hardware proof), remain blocked on bare-metal Linux/NVIDIA
hardware access — see "Dependency blockers".

D-B (workload-executable-identity gap) was raised to the founder during
HORO-845's design and resolved: `eltanin run` stays alive as the
lease-holding supervisor ([ADR 0005](../adr/0005-eltanin-run-process-topology.md)) —
the only topology under which the already-merged lease-release mechanism
(`compare_process`/`compare_executable`) still works, since
`compare_executable` does not survive `execve()`. Named, founder-accepted
consequence: because the connecting peer is always `eltanin`'s own
binary, policy cannot discriminate on the workload's executable through
`eltanin run` in MVP 1.0 (only uid/gid/launcher-path/ancestry/cgroup).
Founder directed: accept the gap for MVP 1.0, but do **not** paper over
it — `docs/product/POLICY_EXAMPLES.md`'s headline example was corrected
with an explicit scope note (it remains true only for a workload
connecting *directly*, not via `eltanin run`) and a new `eltanin
run`-specific example was added that deliberately omits any
executable-identity condition. HORO-988 (new ticket) tracks properly
threat-modeling and closing the gap later — no mechanism pre-selected.

HORO-814 (Claude Code project gate + Codex adapter) merged as PR #25,
`2f21164` — `.claude/CLAUDE.md` and `AGENTS.md` now exist; a fresh
session should read `.claude/CLAUDE.md` first.

With all hardware-free Feature work done, the campaign worked through
the remaining Highest-priority governance Tasks under HORO-772 that
don't require bare-metal hardware:

- HORO-814 (Claude Code project gate + Codex adapter) — PR #25, `2f21164`.
- HORO-819 (feature-level QA verification/DoD) — PR #27, `0b5b980`.
  [`docs/qa/README.md`](../qa/README.md) formalizes the Feature
  Verification Record convention this campaign already follows, plus a
  template ([`docs/qa/feature-verification/TEMPLATE.md`](../qa/feature-verification/TEMPLATE.md))
  and an MVP 1.0 Feature inventory.
- HORO-820 (documentation architecture/Docs Impact governance) — PR
  #29, `4cfd56c`. [`docs/development/documentation-governance.md`](documentation-governance.md)
  states the User/Operator-vs-Contributor audience split and a
  Change-to-Docs rule table — the one concrete gap; everything else
  HORO-820 asked for already existed.

**HORO-814/819/820/810/811 are all Done.** Every Highest-priority
governance Task under HORO-772 due 2026-09-13/14 has landed, plus
HORO-810 and HORO-811 (both due 2026-10-03, done early).

HORO-810 (PR #31, `e1493a4`) shipped `docs/qa/test-plans/mvp-1.0.md`
(versioned Track A test plan), `docs/qa/reports/TEMPLATE.md`, and
`crates/eltanin-cli/tests/qa_governance_sync.rs` (4 mechanical
inventory/evidence-path drift-guard tests). Deliberately reused HORO-819's
Markdown Feature Verification Record convention rather than Jira's
suggested YAML shape, and HORO-845/847's `docs_sync.rs` `include_str!`
pinning pattern rather than inventing a new mechanism.

HORO-811 (PR #33, `660c87e`) shipped `docs/qa/e2e/README.md` (the Track B
scenario index: manifest table, per-Feature coverage table, release-gate
notes), a North Star assertions table added to
`docs/qa/e2e/F-M1-008-controlled-launch.md`, a `.github/workflows/ci.yml`
split into a named "Track B — canonical Product/Business E2E" step
(`cargo test -p eltanin-cli --test canonical_e2e`) followed by "Track A —
full hardware-free suite" (`cargo test --workspace`), and 4 more
`qa_governance_sync.rs` tests pinning the Track B index against
`canonical_e2e.rs`'s own `COVERS` const. Deliberately reused HORO-847's
existing `canonical_e2e.rs` scenario (the one real Track B journey this
repo has) and HORO-810's drift-guard test pattern — no new
scenario-automation tooling invented where none was needed.

**All hardware-independent MVP 1.0 work is now complete.** Every Feature
that can be implemented and QA-verified without physical hardware
(F-M1-001/003/004/005/006/008/009) is done, and every governance Task
under HORO-772 that doesn't require bare-metal hardware (HORO-814/819/
820/810/811) is done.

**HORO-781 (license) is resolved.** Founder decision 2026-09-12: Apache
License 2.0 (PR #35, `3e44a16`). `LICENSE` now carries the full
unmodified Apache-2.0 text; `NOTICE` carries the copyright line
(`Copyright 2026 Horonom`); the root `Cargo.toml`'s `[workspace.package]`
and every crate's `Cargo.toml` declare `license = "Apache-2.0"` (via
`license.workspace = true`); `deny.toml`'s `[licenses.private]` comment
is reconciled; `README.md`'s License section states the license
plainly. `bootstrap-reconciliation.md`'s original "License (MAJOR
DECISION)" note is left as written (accurate historical record at the
time) with a dated resolution pointer added below it, not rewritten.

**The HORO-790 hardware-validation runbook is ready** (PR #36,
`dcb5036`) — see
[`docs/development/hardware-validation-runbook.md`](hardware-validation-runbook.md).
Founder direction: obtain real hardware evidence rather than waive or
fabricate it, with the complete package prepared *before* provisioning
so the paid/physical execution window is short. The runbook covers
GPU/kernel/driver/capability requirements, the own-workstation-vs-
rented-hardware decision (a genuine bare-metal workstation is
recommended over most "cloud GPU" products, which are virtualized and
do not satisfy HORO-790's AC), exact setup/test/cleanup commands, and
two read-mostly automation scripts. It is preparation only — no
hardware has been provisioned and no hardware evidence exists; nothing
in it is fabricated or simulated execution output, and no Acceptance
Criteria on HORO-785/789/841/790 have been weakened or reinterpreted.
Jira comments (not status transitions) were added to HORO-790, HORO-785,
HORO-789, and HORO-841 pointing at it.

**Both HORO-781 and this runbook are done.** At the time this paragraph
was written (before the 2026-09-12 scope amendment) the only remaining
blocker was the founder providing bare-metal Linux/NVIDIA hardware. That
is **no longer the whole picture** — see the next paragraph and "Apple
Silicon scope amendment" above for the current state. Left as written
(accurate at the time) rather than rewritten, per this document's own
additive-history convention.

**A product/architecture scope amendment approved 2026-09-12 added
Apple Silicon as a second real-hardware evidence class** (see "Apple
Silicon scope amendment" above) — the campaign is no longer purely
blocked on Linux/NVIDIA hardware. HORO-1018 (privileged-enforcement
blast-radius governance), HORO-1011 (capability/memory model), and
HORO-1012 (Metal backend, PRs #41/#42) are all Done. **HORO-1013 (macOS
platform/IPC/controlled-launch adapter) is in progress** in its own
isolated worktree, per the parallelism this dependency graph already
allowed. HORO-1012 having merged now also unblocks HORO-1014 (native
Metal fixture); HORO-1015 (physical M3 Max QA) starts only after
HORO-1012/1013/1014 all merge — HORO-1013 is the one still outstanding.

The Linux/NVIDIA hardware blocker (HORO-841, F-M1-002/007, HORO-790's
E3 evidence) is unchanged and still requires the founder to provide
bare-metal hardware — see "Dependency blockers". This no longer stops
all forward progress: the Apple Silicon track gives hardware-free
implementation work (HORO-1012/1013/1014) to continue on independently,
per the founder's own scope-amendment directive not to let one hardware
class's unavailability idle the whole campaign.

A fresh session resuming this campaign should: (1) check Jira/`git
worktree list` for HORO-1012/1013 progress before starting new work,
(2) continue the Apple Silicon dependency graph as far as hardware-free
work allows, (3) separately raise Linux/NVIDIA hardware provisioning to
the founder (pointing at the runbook) as its own independent thread,
and (4) once a real M3 Max or Linux/NVIDIA environment is provided,
execute the relevant plan (HORO-1015's QA scenario, or the hardware-
validation runbook) directly.
