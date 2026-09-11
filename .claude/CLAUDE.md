# CLAUDE.md — Eltanin Project Gate (HORO-814)

This file is a concise mandatory gate and navigation map for a coding
agent working in `horonomy/eltanin` — not a second Product Constitution.
Canonical truth lives in the files it links to; when this file and one
of those disagree, the linked canonical file wins and this file should
be corrected.

A fresh agent session should be able to answer every question below
from this repository alone, without founder chat history.

## 1. What am I building, and what must never silently change?

North Star (read first, every session):
[`docs/product/NORTH_STAR.md`](../docs/product/NORTH_STAR.md) —
**"No protected compute without authorization."** Its "Locked
invariants" section lists what requires a MAJOR DECISION + new ADR to
change, not an ordinary PR. Full product/security context:
[`docs/product/PRODUCT_CONSTITUTION.md`](../docs/product/PRODUCT_CONSTITUTION.md),
[`docs/product/SECURITY_MODEL.md`](../docs/product/SECURITY_MODEL.md).

## 2. Which ticket/version am I implementing?

- Current campaign state, active worktrees, and "Next planned action":
  [`docs/development/campaign-state.md`](../docs/development/campaign-state.md)
  — read this before starting or resuming any work.
- Architecture decisions and their rationale:
  [`docs/adr/`](../docs/adr/README.md).
- Current-state architecture: [`docs/architecture/domain-model.md`](../docs/architecture/domain-model.md).

## 3. Engineering constraints

[`CONTRIBUTING.md`](../CONTRIBUTING.md) is authoritative for the exact
commit-message format, PR/merge workflow, and testing policy — read it,
don't infer these from a global/default convention. In particular:

- **This repo's branch format is 3-part**: `<phase>/<ticket>/<short_summary>`
  (e.g. `mvp-1.0/HORO-825/define_resource_domain`) — no `<type>` segment.
  If a broader personal/global config suggests a different branch-naming
  scheme, this repo's own `CONTRIBUTING.md` convention wins here.
- Rust is the default implementation language; C only at unavoidable FFI
  boundaries. `#![forbid(unsafe_code)]` is a workspace-wide invariant
  (present in every crate's `lib.rs`) — see the ADRs under `docs/adr/`
  for how privileged operations (signals, peer credentials) are done
  without hand-written `unsafe` (`rustix`, `signal-hook`).
- One implementation ticket maps to at most one PR, atomic Gitmoji
  commits, `main` is PR-only merged via merge commit, and new
  features/bug fixes require tests — `CONTRIBUTING.md`'s exact wording
  governs; this file does not restate it.
- Fetch and verify `origin/main` before starting new work.
- All required CI checks (rustfmt, clippy, test, cargo-deny, cargo doc)
  must be green before merge; never bypass a release gate for speed.
  Real-hardware evidence jobs are separate from normal no-GPU CI — see
  `CONTRIBUTING.md`'s "Testing" section.

## 4. Feature-level QA and Docs Impact — mandatory, not optional

- **Every Feature requires feature-level QA verification**, not just a
  green PR — see `docs/qa/feature-verification/` for the existing
  records and their format. A ticket/PR being Done or CI-green is
  implementation evidence only, not a QA verdict.
- **Track A (QA/Security engineering)** and **Track B (Product/Business
  E2E)** are the two evidence classes the PR template asks every PR to
  classify — see `docs/qa/e2e/` for existing Track B scenario records
  and `docs/product/QUICKSTART.md` for the canonical user-facing
  journey a Track B scenario should also serve as source for.
- **Every change must execute the Docs Impact Gate**: the PR template's
  `Docs Impact` field (`User Docs` / `Contributor Docs` / `Both` /
  `None — <reason>`) is mandatory, and `None` requires a defensible
  reason when the change touches behavior, security, interfaces, or
  architecture.
- A security/design decision that changes current truth must produce or
  update an ADR (`docs/adr/`) and, if it changes current-state
  documentation, the relevant canonical doc (`docs/product/`,
  `docs/architecture/`) in the same PR — not as follow-up cleanup.
- **What counts as Done/Ready**: a Feature is not Done merely because
  its implementation tickets are Done and CI is green — it needs a PASS
  Feature Verification Record (above) and, for a release gate, every
  in-scope Feature must have one. See `docs/qa/feature-verification/`
  for the current per-Feature standard this repo already follows.

## 5. Escalation — when to stop and ask the founder

Stop and ask (do not decide silently) when a change would:

- alter a `NORTH_STAR.md` locked invariant;
- expand scope into a platform/vendor/architecture the current roadmap
  stage doesn't cover (e.g. Windows, AMD, a cloud control plane) ahead
  of roadmap evidence;
- change what identity/executable/context dimension the product claims
  to authorize on (see [ADR 0005](../docs/adr/0005-eltanin-run-process-topology.md)
  and HORO-988 for a live example of this kind of decision, already
  resolved);
- require irreversible or destructive action, touch
  production/billing/credentials, or provision a paid external resource
  (e.g. bare-metal hardware access — see `campaign-state.md`'s
  "Dependency blockers" for the live case this repo is currently
  carrying) — see the global secret-handling and safe-implementation
  rules that apply to every repository this agent works in.

Ordinary implementation, test, docs, and review decisions within an
already-accepted design do not require stopping.

## 6. Other coding agents (Codex, etc.)

[`AGENTS.md`](../AGENTS.md) at the repo root is a thin adapter pointing
back to the same canonical docs this file points to. Do not fork policy
into a second, independently-maintained copy for another tool.
