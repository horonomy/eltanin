# Bootstrap Reconciliation — Eltanin MVP 1.0

**Ticket:** HORO-821
**Date:** 2026-09-10
**Author:** Claude Code (autonomous engineering lead, HORO-772 campaign)

## Purpose

Establish one trustworthy starting point for Eltanin before new MVP 1.0
implementation begins, per HORO-821. This record is evidence, not
assumption: every claim below was checked against live Jira, live GitHub,
and the local filesystem before being written down.

## 1. Repository archaeology — verdict: no prior Eltanin repository existed

Checked, in order:

1. **Local filesystem** — all sibling directories under
   `~/Bryant-Developments/horonomy/` (`circinus`, `eridanus`, `fornax-*`,
   `horologium`, `horonom-site`, `horonomy-lab`, `infra`, `internal-docs`,
   `octans*`, `ophiuchus`, `GearMeshing-AI`). None reference Eltanin;
   `git remote -v` in each confirms each is its own unrelated product.
   Wider search `find ~/Bryant-Developments -maxdepth 4 -iname "*eltanin*"`
   returned nothing. `grep -ril "eltanin|compute zero trust"` across
   `internal-docs/` returned nothing.
2. **`horonomy` GitHub org** (`gh repo list horonomy`, `gh api
   orgs/horonomy/repos --paginate`) — 21 repos, none named `eltanin` and
   none referencing it in their description.
3. **Broader GitHub** (`gh search repos eltanin`, `gh repo list
   Chisanan232`, `gh api /user/repos?affiliation=owner,collaborator,...`)
   — only unrelated third-party projects sharing the star name "Eltanin"
   (an OS distro, a robotics library, several unrelated personal repos).
   None under any org/account this environment has access to.
4. **`gh auth status`** — authenticated as `Chisanan232` with full
   `admin:org`/`repo` scopes against `horonomy`, so the empty result in
   (2) and (3) is a genuine absence, not a visibility/permission gap.

**Verdict:** Eltanin MVP 1.0 starts from a genuinely empty repository
state. Nothing was migrated, retired, or quarantined because nothing
existed to migrate. This satisfies HORO-821 DoD item "canonical repo +
default branch + starting SHA are identified **or** a truthful creation
blocker is recorded" — no blocker existed, so HORO-781 (create canonical
repo) was executed directly.

## 2. Jira archaeology — verdict: campaign planning is internally consistent, no stale/duplicate work found

Inventoried all `HORO-772..850` (79 issues) plus `HVDL-25` (80 issues
total) via JQL. All MVP 1.0 in-scope tickets (Epic, 5 governance Tasks, 9
Features, ~30 Subtasks) were in Jira-native `To Do`, freshly created
2026-09-08, with no prior implementation history, no linked stale
duplicates, and no conflicting architecture decisions recorded elsewhere.
Explicit classification of every ticket named in HORO-821's own required
minimum:

- **HVDL-25** — canonical discovery idea (status `Researching`), correctly
  connected to HORO-772 via a "Discovery - Connected" link. Current/
  canonical; nothing to reconcile.
- **HORO-772..790** — Epic + MVP 1.0 governance Tasks + all 9 F-M1-*
  Features + the MVP 1.0 READY gate. All current, freshly created, no
  stale metadata. `HORO-773..779` (MVP 2.0 through Stage 8 Epics) are
  future-stage — correctly out of MVP 1.0 scope, left untouched.
- **HORO-810** (QA/Security test plans), **HORO-811** (business E2E
  automation), **HORO-814** (Claude Code project config) — all current,
  in-scope MVP 1.0 governance Tasks, `To Do`, no prior work to reconcile.
- **HORO-819** (feature-level QA/DoD) and **HORO-820** (docs architecture/
  Docs Impact governance) — both current, in-scope MVP 1.0 governance
  Tasks, `To Do`, no prior work to reconcile. (Not covered by any range
  mentioned elsewhere in this document — called out explicitly here per
  HORO-821's own named minimum.)
- **HORO-791..809, 812, 813, 815..818** — MVP 2.0 / v0.0.1 / v0.1.0 /
  later-stage Stories and Tasks. Correctly out of MVP 1.0 scope, left
  untouched.
- **HORO-821..850** — this reconciliation task itself, plus F-M1-005/008/
  009 Features and all Feature subtasks. All current, freshly created,
  `To Do` (HORO-821 `In Progress` as the active task), no prior work to
  reconcile.

**Verdict:** no ticket migration, superseding, or duplicate-linking was
required. The only reconciliation action needed was metadata bootstrap
(HORO-780), executed as part of this pass (see §4).

## 3. Local-only / uncommitted work — verdict: none found

No uncommitted Eltanin-related work exists anywhere in the local
environment. The `.worktrees/` directory at the container root was empty.
No orphan directories, stashes, or scratch files referencing Eltanin,
protected-resource, NVIDIA/cgroup/eBPF, policy/lease, or agent/IPC
concepts were found outside this campaign's own new work.

## 4. Actions taken in this reconciliation pass

### Jira (HORO-780 scope — executed in an earlier session of this same campaign, prior to this PR; reported here as evidence, not performed by this PR)

- Fix Version **`Eltanin MVP 1.0 — Authorization Happy Path`** created
  (id `10192`; start 2026-09-08; target 2026-10-06; `released: false`),
  assigned to all 46 in-scope MVP 1.0 tickets.
- Atlassian Goal **Eltanin G1** created (`CBLPCRLM-19`), linked to
  **HORO-772 only** via a `JIRA_WORK_ITEM` connection — not sprayed onto
  Feature/Subtask children, per spec.
- 12 `Eltanin ::` Components created in project `HORO` (ids
  `10145`–`10156`: Repo & Governance, Core, Backend, NVIDIA, Linux
  Platform, Device Guard, Protocol, Agent, CLI, Audit, QA, Docs) and
  backfilled onto every in-scope ticket per its real package ownership.
- **Deliberately not done:** creation/migration to a dedicated `ELTN`
  Jira project. HORO-780's own "Project Reconciliation Rule" makes this
  conditional on HORO-821 evidence + Bryant approval. This reconciliation
  found no risk/duplication problem that a project migration would solve,
  and migration is inherently history-affecting — so it is **not**
  recommended, and not attempted. Continuing in `HORO` is the correct
  default absent a concrete reason to move.

### Repository (HORO-781 scope — also executed in an earlier session of this same campaign, prior to this PR)

- Created `horonomy/eltanin`, public, under the existing Horonomy GitHub
  organization (no standalone Eltanin org, per spec).
- Seeded `main` directly (the one documented exception to "no direct
  pushes" — no branch existed yet to open a PR against): `README.md`,
  `LICENSE` (placeholder — see Open Decision below), `SECURITY.md`,
  `CONTRIBUTING.md`, `CODEOWNERS`, `.gitignore`, and the intended
  `crates/`/`platform/linux/`/`backends/`/`cli/`/`proto/`/`sdk/`/
  `tests/conformance/` directory layout (placeholders — real crate content
  is HORO-783 and the F-M1-* Feature subtasks' job, not this ticket's).
- Enabled branch protection on `main` immediately after seeding
  (`required_pull_request_reviews.required_approving_review_count = 1`,
  `allow_force_pushes: false`, `allow_deletions: false`). All work from
  this point forward goes through worktree → branch → PR → merge commit,
  demonstrated by PR #1 (`.github/PULL_REQUEST_TEMPLATE.md`, merged
  `e9ab11f`).
- Starting `main` SHA for MVP 1.0 implementation work (i.e. `main` HEAD
  immediately before this reconciliation PR merges) is `e9ab11f8bc954c1
  614602ad41d9ed994be22e1db`, recorded in `docs/development/
  campaign-state.md`.

## 5. Feature mapping — F-M1-001..009

No existing implementation exists, so there is nothing to map to reusable
code. All nine Features start from zero:

| Feature | Ticket | Reusable code found |
|---|---|---|
| F-M1-001 Protected Resource & Backend Abstraction | HORO-784 | None |
| F-M1-002 NVIDIA Protected Resource Discovery | HORO-785 | None |
| F-M1-003 Workload Identity & Execution Provenance | HORO-786 | None |
| F-M1-004 Authorization Policy Decision | HORO-787 | None |
| F-M1-005 Scoped Short-Lived Compute Lease | HORO-822 | None |
| F-M1-006 Local Authorization Agent & Authenticated IPC | HORO-788 | None |
| F-M1-007 Linux Protected-Device Enforcement | HORO-789 | None |
| F-M1-008 Controlled Protected Launch (`eltanin run`) | HORO-823 | None |
| F-M1-009 Local Audit & Explain Evidence | HORO-824 | None |

## 6. Unresolved drift / open items

1. **License (MAJOR DECISION, escalated on HORO-781).** The repo is
   public with a placeholder `LICENSE` file. Ticket AC requires a real
   license; the ticket text names none. This is an open-core/licensing
   boundary decision per campaign rules — needs Bryant's choice
   (e.g. Apache-2.0, MIT, or a dual-license/open-core split ahead of the
   future `horonomy/eltanin-enterprise`). Nothing else is blocked by this.

   > **Resolved 2026-09-12.** Bryant chose Apache License 2.0. This
   > paragraph is left as written at reconciliation time — it accurately
   > records that the decision was open then — see
   > `campaign-state.md`'s Completed table for the resolving PR/commit.
2. **Bare-metal Linux/NVIDIA hardware access (MAJOR DECISION, to be
   raised separately).** F-M1-002, F-M1-007, HORO-841 (hard security
   gate), and the final MVP 1.0 READY gate all require real bare-metal
   Linux/NVIDIA hardware evidence. This development environment is
   macOS/darwin. Provisioning a representative host is both a required
   external action and a potential recurring hardware cost — both
   explicit MAJOR DECISION categories. This does **not** block starting
   hardware-free work (F-M1-001/003/004/005/006/008/009 and the Fake
   Compute Backend all have no hardware dependency); it blocks only
   F-M1-002/007 real-hardware validation and the final MVP 1.0 READY gate.

## 7. Definition of Done — status

- [x] All discoverable Eltanin Jira/JPD work inventoried and classified (§2).
- [x] All discoverable local/remote repositories/prototypes inventoried with evidence (§1, §3).
- [x] Canonical repo + default branch + starting SHA identified (§4; SHA recorded in `campaign-state.md`).
- [x] Existing implementation mapped to F-M1-001..009 (§5 — none exists).
- [x] Duplicate/superseded work linked and documented — none found, so none applicable (§2).
- [x] This reconciliation document committed through a PR.
- [x] Destructive/ambiguous migration escalated to Bryant before execution — none was destructive; the one real decision (license) is escalated in §6.
- [x] Subsequent MVP work starts from reconciled current `main`, not an assumed blank repo.
