# Documentation Governance (HORO-820)

Documentation is a first-class engineering artifact here, not release
cleanup. This document states the one thing that wasn't already written
down anywhere in this repository: the audience split between the two
documentation responsibilities Eltanin maintains, and the concrete rule
for what a change must update. Everything else HORO-820 asks for
(canonical `docs/product/*`, `docs/architecture/`, `docs/adr/`,
`docs/qa/`, a mandatory `Docs Impact` PR-template field) already existed
before this document — see "What already existed" at the bottom.

## Two documentation responsibilities

### A. User / Operator / Integrator documentation

For people **using, operating, or integrating** Eltanin. Intended home:
`docs.eltanin.horonom.com` (HORO-812, not yet built — the site doesn't
exist yet at MVP 1.0 stage).

**Today, this repository is the only place User docs live**:
[`docs/product/QUICKSTART.md`](../product/QUICKSTART.md) is the current
Getting Started / usage-workflow / troubleshooting surface, and
[`docs/product/POLICY_EXAMPLES.md`](../product/POLICY_EXAMPLES.md) is
the current policy-usage guidance. Both are held to the same standard
HORO-820 sets for the eventual public site: every command they show is
mechanically pinned to a real, tested scenario (see
`crates/eltanin-cli/tests/docs_sync.rs` for the exact assertions), and
they state unsupported/partial behavior honestly (see
`QUICKSTART.md`'s "What this proves, and what it does not" section).
When HORO-812 stands up the public site, these files migrate there —
this document's rule doesn't change, only where the rendered output
lives.

### B. Product Developer / Contributor documentation

For people **building or maintaining** Eltanin itself. Version-controlled
in this repository:

```text
docs/
  product/       NORTH_STAR.md, PRODUCT_CONSTITUTION.md, SECURITY_MODEL.md,
                 CLI_CONTRACT.md, POLICY_EXAMPLES.md, QUICKSTART.md (dual-purpose — see above)
  architecture/  domain-model.md (current-state architecture)
  adr/           one file per decision, indexed in adr/README.md
  development/   this file, campaign-state.md, bootstrap-reconciliation.md
  qa/            README.md (feature-level QA governance, HORO-819),
                 feature-verification/ (one record per Feature),
                 e2e/ (Track B scenario records)
```

Durable design/architecture decisions are captured as ADRs
(`docs/adr/`); when an ADR changes *current* truth (not just historical
context), the relevant canonical doc under `docs/product/` or
`docs/architecture/` is updated in the same PR — see, for example,
ADR 0005 and its consequences reflected into `domain-model.md` and
`CLI_CONTRACT.md`.

## The Docs Impact Gate

`.github/PULL_REQUEST_TEMPLATE.md`'s `Docs Impact` field is mandatory on
every PR: `User Docs` / `Contributor Docs` / `Both` / `None — <reason>`.
`None` is not a shortcut — it requires a defensible reason, and a
reviewer should reject it on a PR that touches behavior, security,
interfaces, or architecture without one. This document is the rule for
*what counts* as a defensible reason; the PR template is the mechanism
that asks the question on every change.

## Change-to-Docs rules

| Kind of change | Must update |
|---|---|
| Feature / user-visible behavior | User/Operator docs (`QUICKSTART.md`, `POLICY_EXAMPLES.md`) if the workflow changed; the Feature Verification Record (`docs/qa/feature-verification/`); Contributor docs if architecture/contracts also changed. |
| Security semantics / threat boundary / authorization behavior | `SECURITY_MODEL.md` / `PRODUCT_CONSTITUTION.md`; the relevant Feature Verification Record's "Known limitations." |
| Architecture / design decision | An ADR (new or updated); the canonical architecture/product doc it changes, in the same PR; `.claude/CLAUDE.md`/`AGENTS.md` only if the change alters an engineering *constraint* those files state (rare). |
| API / SDK / protocol change | `docs/product/CLI_CONTRACT.md` or the equivalent protocol doc; any example/fixture the doc is byte-pinned to (see `docs_sync.rs`'s pattern); compatibility notes if the change isn't backward-compatible. |
| Internal implementation-only refactor | `Docs Impact: None` is valid **only** if it genuinely doesn't alter public behavior, an architecture contract, debugging/operations, or contributor workflow — state which of those it doesn't touch, don't just assert "internal." |

A PR that changes behavior/security/interfaces/architecture but selects
`None` without naming which of the rows above it's exempt from, and
why, should not be approved.

## Feature Definition of Done — the docs half

`docs/qa/README.md`'s release-gate item 6 (amended by this PR) states
the docs half of a Feature's Definition of Done: required User Docs
impact is complete, required Contributor Docs impact is complete,
scenario/docs examples agree with tested behavior (not merely believed
to), documentation states unsupported/partial behavior honestly, and all
linked documentation has been checked against `NORTH_STAR.md`. Every
Feature that has a Feature Verification Record
(`docs/qa/feature-verification/*.md`) already satisfies this in
practice — F-M1-008's is the clearest example, since its own subtask
(HORO-847) exists specifically to make the tested scenario and the
user-facing Quickstart the same thing. F-M1-001, F-M1-002, and F-M1-007
have no record yet (see `docs/qa/README.md`'s Feature inventory) — this
docs-DoD applies to them once one is written, not retroactively to their
current unverified state.

## Test/docs coupling and CI enforcement — current state

Where a canonical scenario and a doc's example commands can be made
byte-identical, they are — `crates/eltanin-cli/tests/docs_sync.rs`'s
pinning assertions are the working example (`POLICY_EXAMPLES.md`,
`QUICKSTART.md`). HORO-810 additionally added
`crates/eltanin-cli/tests/qa_governance_sync.rs`, which pins QA-inventory
and test-plan evidence paths against drift. Neither is a general
link/snippet/version-consistency linter across all of `docs/` — Jira's
AC asks for the latter ("CI checks links/snippets/version consistency
where technically feasible") and it still does not exist. Named as an
accepted gap, deferred to its own future ticket rather than folded into
HORO-810 (QA-evidence governance is a distinct concern from a general
documentation linter).

## What already existed before this document

- Canonical Product Constitution / North Star / Security Model / ADR /
  architecture locations — HORO-782/783.
- A PR template with a mandatory `Docs Impact` field — HORO-781/783 (see
  `.github/PULL_REQUEST_TEMPLATE.md`).
- `.claude/CLAUDE.md`/`AGENTS.md` already state the Docs Impact Gate is
  mandatory and point at the relevant canonical docs — HORO-814.
- The Feature-level QA / DoD framework this document's "Feature
  Definition of Done" section defers to — HORO-819.
- A working example of scenario-to-doc byte-pinning
  (`crates/eltanin-cli/tests/docs_sync.rs`) — HORO-845/847.

This document's actual new content is narrow: the explicit User/
Operator-vs-Contributor audience split, and the Change-to-Docs rule
table — neither existed as a single written rule anywhere before this.
