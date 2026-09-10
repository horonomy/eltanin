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
| HORO-772 | This campaign-state.md update | (this PR) | _fill in on merge_ |

Current `main` HEAD (before this PR merges): `793c522`.

## Active worktrees

None (all merged and removed). Next worktree will be for HORO-784
(F-M1-001) or HORO-825 (its first subtask).

## Dependency blockers

None for hardware-free work. Real-hardware-dependent tickets (HORO-841,
F-M1-002 real NVIDIA validation, F-M1-007 real enforcement, HORO-790,
final MVP 1.0 READY gate) are blocked pending a bare-metal Linux/NVIDIA
host — flagged as a MAJOR DECISION (external resource / cost), not yet
formally raised as its own escalation beyond the note in
`bootstrap-reconciliation.md` §6.

## Feature QA states

All F-M1-001..009 — not yet started. No Feature Verification Records
exist yet. Governance/foundation work (HORO-780/781/782/783/821) is done;
this is what F-M1-001 (HORO-784) now builds on.

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

Start F-M1-001 (HORO-784, Protected Resource & Backend Abstraction) via
its subtasks HORO-825 (resource domain/identities/serialization contract)
and HORO-826 (backend capability contract). No dependency on other
Features — every other Feature depends on its domain types, so it's the
correct next unit of work.
