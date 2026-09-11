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

Current `main` HEAD: `323827e`. F-M1-001, F-M1-003, F-M1-004, F-M1-005,
F-M1-006 are done.

## Active worktrees

- `eltanin-mvp-1.0-HORO-824-audit_explain` (branch
  `mvp-1.0/HORO-824/audit_explain`), off `323827e`, in progress
  (F-M1-009 — local audit & explain evidence, `crates/eltanin-audit`).

## Dependency blockers

None for hardware-free work. Real-hardware-dependent tickets (HORO-841,
F-M1-002 real NVIDIA validation, F-M1-007 real enforcement, HORO-790,
final MVP 1.0 READY gate) are blocked pending a bare-metal Linux/NVIDIA
host — flagged as a MAJOR DECISION (external resource / cost), not yet
formally raised as its own escalation beyond the note in
`bootstrap-reconciliation.md` §6.

## Feature QA states

F-M1-003 (HORO-786), F-M1-004 (HORO-787), F-M1-005 (HORO-822), and
F-M1-006 (HORO-788): Done, Feature Verification Record PASS —
`docs/qa/feature-verification/F-M1-003.md` (HORO-833), `F-M1-004.md`
(HORO-835), `F-M1-005.md` (HORO-837), `F-M1-006.md` (HORO-840). All
other F-M1-001/002/007..009 — no Feature Verification Record yet
(F-M1-009/HORO-824 in progress in this worktree).
Governance/foundation work (HORO-780/781/782/783/821) is done;
F-M1-001 (HORO-784/825/826/827) is functionally complete but has no
formal record yet.

## Required human decisions outstanding

1. License choice for `horonomy/eltanin` (HORO-781) — repo is public with
   a placeholder LICENSE; `deny.toml` exempts our own unpublished crates
   from the license check in the meantime so CI isn't blocked by this.
2. Bare-metal Linux/NVIDIA hardware provisioning for F-M1-002/007/HORO-841/
   MVP 1.0 READY (not yet formally raised as its own escalation — next
   action once hardware-free Feature work is further along).

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

F-M1-001, F-M1-003, F-M1-004, F-M1-005, F-M1-006 are done (HORO-840
merged as PR #19, `323827e`, closing F-M1-006/HORO-788 entirely).
Currently in progress: HORO-824 (F-M1-009, Audit & Explain —
`crates/eltanin-audit`, an append-only NDJSON evidence log plus an
`eltanin-explain` reader). D-A (best-effort audit durability) was raised
to the founder and resolved: an audit write failure never changes an
already-computed ALLOW/DENY/release result — "audit is evidence, not
authority" — but is logged to stderr and counted
(`AuditFileSink::failed_writes`); sequence-gap detection distinguishes
"never issued" from "possibly lost to a persistence failure." Next after
HORO-824 merges: F-M1-008 (HORO-823, `eltanin run` CLI) — hardware-
independent and not yet started.
