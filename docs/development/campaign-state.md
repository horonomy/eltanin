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
- Fix Version: `Eltanin MVP 1.0 — Authorization Happy Path` (id `10192`).
- Goal: `Eltanin G1` (`CBLPCRLM-19`), linked to HORO-772 only.
- Components: `Eltanin :: {Repo & Governance, Core, Backend, NVIDIA,
  Linux Platform, Device Guard, Protocol, Agent, CLI, Audit, QA, Docs}`
  (ids 10145–10156).

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

Current `main` HEAD: `660c87e`. F-M1-001, F-M1-003, F-M1-004, F-M1-005,
F-M1-006, F-M1-008, F-M1-009 are done. HORO-814/819/820/810/811
(governance) are done.

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

## Required human decisions outstanding

1. Bare-metal Linux/NVIDIA hardware provisioning for F-M1-002/007/HORO-841/
   MVP 1.0 READY (not yet formally raised as its own escalation — next
   action once hardware-free Feature work is further along).

License choice for `horonomy/eltanin` (HORO-781) was resolved
2026-09-12: **Apache License 2.0**, founder decision. See "Next planned
action" below (the Completed table above gets its HORO-781 row in the
usual campaign-state follow-up PR, once this PR's merge commit exists).

## Hardware evidence state

Not started. No representative bare-metal Linux/NVIDIA host identified
yet in this environment.

## Remaining release gates

Everything in HORO-772's "Release Gate — MVP 1.0 READY" section. Nothing
gated yet since no Feature work has started.

## Lessons from this pass (process, not product)

- HORO-781's initial "Initial Repository Shape" crate list and the Epic's
  own Component table + Feature tickets' "Primary package" paths
  disagreed. Caught by independent PR review after HORO-783 shipped the
  wrong one, fixed while crates were still empty (PR #5). **Going
  forward: before scaffolding any new crate/directory, cross-check its
  name against the Jira Component table on HORO-772/780 and any Feature
  ticket that names a "Primary package" path — that's the authoritative
  source, not a Task-ticket's own initial proposal.**

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
License 2.0. `LICENSE` now carries the full unmodified Apache-2.0 text;
`NOTICE` carries the copyright line (`Copyright 2026 Horonom`); the root
`Cargo.toml`'s `[workspace.package]` and every crate's `Cargo.toml` now
declare `license = "Apache-2.0"` (via `license.workspace = true`);
`deny.toml`'s `[licenses.private]` comment updated to explain `ignore =
true` is now about `publish = false`, not an undecided license;
`README.md`'s License section states the license plainly.
`bootstrap-reconciliation.md`'s original "License (MAJOR DECISION)" note
is left as written (it accurately recorded an open decision at the time)
with a dated resolution pointer added directly below it — historical
record, not rewritten.

**What remains — one blocker, not decidable by this campaign
autonomously:**

**Bare-metal Linux/NVIDIA hardware provisioning** (a paid external
resource — see `.claude/CLAUDE.md`'s "Escalation" section). Blocks:
F-M1-002/HORO-785 (NVIDIA protected resource discovery), F-M1-007/
HORO-789 (Linux protected-device enforcement), HORO-790 (MVP 1.0 READY
hardware proof), and by extension the final MVP 1.0 release gate in
HORO-772. No hardware-free subtask work remains identified for either
Feature — see "Dependency blockers" and "Required human decisions
outstanding" above.

The founder has stated intent to obtain real hardware evidence (not
waive or fabricate it) and asked for a complete hardware-validation
runbook prepared *before* provisioning, so the paid/physical execution
window is as short as possible. This session is preparing that runbook
as a separate, immediately following piece of work — see the next
Completed-table entry once it lands. It is preparation only: no
hardware has been provisioned and no hardware evidence exists yet;
nothing in it is fabricated or simulated execution output.

A fresh session resuming this campaign should raise hardware
provisioning to the founder (pointing at the runbook once it exists)
rather than search for further autonomous work — there is none left in
scope until the founder provides a real hardware environment.
