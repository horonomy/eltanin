# Feature-Level QA Verification & Definition of Done (HORO-819)

This document makes feature-level QA verification a mandatory
engineering rule for Eltanin, per HORO-819. It formalizes a practice
this campaign has already been following organically since F-M1-003
(see `docs/qa/feature-verification/F-M1-003.md`'s own note that it
predates this document) — this is the write-up of that practice as
documented governance, not a new process invented after the fact.

North Star: **no protected compute without authorization**
([`docs/product/NORTH_STAR.md`](../product/NORTH_STAR.md)).

## The rule

> **No Feature is Done/Ready until QA has verified the integrated
> feature behavior against its intended user/security outcome.**

The unit of verification is a **Feature** — a coherent product
capability — not an individual Jira ticket, PR, or implementation task.
A Feature may span multiple tickets and multiple PRs; every ticket
landing and CI going green is **implementation evidence only**, never a
QA verdict by itself.

## Feature Definition

In this repository, a Feature is one of the `F-M1-*` capabilities named
by an Eltanin Epic (HORO-772)'s Feature-type Jira issues — each maps to
exactly one externally meaningful outcome (e.g. "Scoped Short-Lived
Compute Lease", "Controlled Protected Launch"). A Feature may be
implemented across several subtask tickets; the QA gate below runs once
per Feature, not once per subtask.

## Feature Verification Record

Every Feature gets exactly one Feature Verification Record, in
[`docs/qa/feature-verification/`](feature-verification/), named
`<feature-id>.md` (e.g. `F-M1-006.md`). Use
[`TEMPLATE.md`](feature-verification/TEMPLATE.md) for a new record's
structure — it documents the shape every existing record already
follows, distilled from practice rather than designed in the abstract.
A record states, at minimum: the Feature's Jira ticket, its PASS/FAIL/
BLOCKED status, which subtasks/PRs implemented it and what evidence each
produced, how each acceptance criterion was verified, findings from an
independent adversarial review (if the implementation had one), and any
known limitations carried forward rather than silently closed.

The record is written once, when the last subtask implementing that
Feature lands — not once per subtask. A record's QA status is
independent of ticket/PR "Done" status: the same agent/session may
implement and then verify, but the verification step is a distinct pass
against the Feature's actual contract (its Jira ticket's Acceptance
Criteria and, where applicable, `NORTH_STAR.md`), not a restatement of
"the PR merged."

## Track A vs. Track B

- **Track A (QA/Security engineering)** — the deep unit/integration/
  adversarial-regression test suites living under each crate's own
  `tests/`. Every Feature Verification Record's "Subtasks and evidence"
  table cites the specific Track A test files that back each subtask.
  [`docs/qa/test-plans/`](test-plans/) holds the versioned, per-milestone
  Track A test plan (HORO-810) — which quality-model layers are
  REQUIRED/NOT APPLICABLE/DEFERRED, and the `NORTH_STAR.md`
  invariant-to-test-file map.
- **Track B (Product/Business E2E)** — a canonical, user-facing journey
  proving the Feature works as a real user/operator would use it, under
  [`docs/qa/e2e/`](e2e/) (see `F-M1-008-controlled-launch.md` for the
  current example). Not every Feature has a user/operator-facing
  workflow — a Feature verification record states Track B evidence as
  N/A with a reason when genuinely not applicable, rather than skipping
  the question.

## Feature inventory — MVP 1.0

| Feature | Jira Feature ticket | Subtask tickets | PR(s) | Feature Verification Record | QA status |
|---|---|---|---|---|---|
| F-M1-001 — Protected Resource & Backend Abstraction | HORO-784 | HORO-825, HORO-826, HORO-827 | #7, #8, #9 | *(none yet)* | Functionally complete, no formal record |
| F-M1-002 — NVIDIA Protected Resource Discovery | HORO-785 | — | — | *(none)* | Blocked on bare-metal NVIDIA hardware access |
| F-M1-003 — Workload Identity & Execution Provenance | HORO-786 | HORO-831, HORO-832, HORO-833 | #10, #11, #12 | [`F-M1-003.md`](feature-verification/F-M1-003.md) | PASS* |
| F-M1-004 — Authorization Policy Decision | HORO-787 | HORO-834, HORO-835 | #13, #14 | [`F-M1-004.md`](feature-verification/F-M1-004.md) | PASS |
| F-M1-005 — Scoped Short-Lived Compute Lease | HORO-822 | HORO-836, HORO-837 | #15, #16 | [`F-M1-005.md`](feature-verification/F-M1-005.md) | PASS |
| F-M1-006 — Local Authorization Agent & Authenticated IPC | HORO-788 | HORO-838, HORO-839, HORO-840 | #17, #18, #19 | [`F-M1-006.md`](feature-verification/F-M1-006.md) | PASS |
| F-M1-007 — Linux Protected-Device Enforcement | HORO-789 | — | — | *(none)* | Blocked on bare-metal Linux/NVIDIA hardware access |
| F-M1-008 — Controlled Protected Launch (`eltanin run`) | HORO-823 | HORO-845, HORO-846, HORO-847 | #21, #22, #23, #24 | [`F-M1-008.md`](feature-verification/F-M1-008.md) | PASS |
| F-M1-009 — Local Audit & Explain Evidence | HORO-824 | (implemented directly under the Feature ticket, no subtask decomposition) | #20 | [`F-M1-009.md`](feature-verification/F-M1-009.md) | PASS |

This table is a cross-reference into
[`docs/development/campaign-state.md`](../development/campaign-state.md)'s
"Completed" and "Feature QA states" sections, which remain the
authoritative, continuously-updated source — update both together, but
this table exists so a reader looking specifically for QA governance
doesn't need to reconstruct it from the campaign-state narrative.
`*` = the record's own `Status` line is more nuanced than a bare PASS;
read the linked record.

`crates/eltanin-cli/tests/qa_governance_sync.rs` mechanically checks
that this table has no orphaned Feature Verification Record, that every
linked record path exists, and that every `F-M1-00N` in
[`docs/qa/test-plans/mvp-1.0.md`](test-plans/mvp-1.0.md)'s invariant map
cites a test file that actually exists on disk — closing HORO-810's
AC that inventory/evidence-path drift is checkable in CI, not just
convention. It does **not** check that "update both together" (this
table vs. `campaign-state.md`) actually happened — that remains a PR
discipline, not a mechanical guarantee.

## Release-gate contract

A release/milestone gate (see HORO-772's "Release Gate — MVP 1.0 READY"
section) may not pass merely because every Jira ticket in scope is
Done. Before a release gate may pass:

1. every in-scope Feature exists in the inventory above;
2. every required Feature has QA status **PASS**;
3. no unresolved Feature-level Critical/High blocker contradicts the
   release claim;
4. Track A and Track B evidence (or an explicit, reasoned N/A) exist for
   every in-scope Feature;
5. hardware evidence exists for any Feature whose claim depends on
   physical enforcement (F-M1-002, F-M1-007 in this milestone);
6. documentation impact is closed for every in-scope Feature (User Docs
   / Contributor Docs / Both / an explicit reasoned None — see the PR
   template's `Docs Impact` field, and
   [`docs/development/documentation-governance.md`](../development/documentation-governance.md)
   for the audience split and Change-to-Docs rules that field enforces),
   which for a Feature specifically means: its scenario/docs examples
   agree with what was actually tested (not merely believed to), its
   documentation states unsupported/partial behavior honestly, and its
   linked documentation has been checked against `NORTH_STAR.md`;
7. a target-version test plan exists under
   [`docs/qa/test-plans/`](test-plans/) and its Track A evidence
   requirements are satisfied (HORO-810).

`qa_governance_sync.rs` mechanically catches inventory/test-path drift
(above) but does not itself decide "is this Feature's status actually
PASS" — that judgment call, and instantiating a
[Release Quality Report](reports/TEMPLATE.md) from the accumulated
evidence, both remain a human/agent verification step at gate time, not
something CI can currently render automatic end to end.

## Independence principle

The same agent/session may implement and verify a Feature during this
early-stage campaign, but the verification activity stays logically
separate from implementation completion — an independent adversarial
review subagent, reading the actual branch content rather than
implementation assumptions, is this campaign's standing practice before
every merge (see F-M1-006.md, F-M1-008.md, or F-M1-009.md's "Independent
review" section for the current pattern — the three earliest records,
F-M1-003/004/005, predate that section and fold the same findings inline
into their "AC verification"/"Known limitations" prose instead). A
future stage may formalize a dedicated QA workflow/session split; not
required for MVP 1.0's scope.

## Regression rule

A reproducible escaped defect, security bypass, or important UX
regression discovered after a Feature is marked PASS must be mapped back
to that Feature and converted into permanent automated regression
coverage where technically feasible — see, for example, F-M1-008's
Feature Verification Record for a real case: a bug in `eltanin-agentd`
(never seeding its backend with any resource) was caught by HORO-847's
canonical E2E test on real CI, not by review, and fixed with a
regression-proof code change plus the test itself standing as permanent
coverage.
