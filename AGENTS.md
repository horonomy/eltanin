# AGENTS.md — Eltanin, for Codex and other coding agents

Claude Code is this repository's primary coding-agent interface; its
project gate is [`.claude/CLAUDE.md`](.claude/CLAUDE.md). This file is a
thin adapter pointing any other agent at the same canonical truth —
there is deliberately no second, independently-maintained copy of
Eltanin's product/security/workflow policy here.

Read, in order:

1. [`docs/product/NORTH_STAR.md`](docs/product/NORTH_STAR.md) — the one
   sentence this project exists to make true, and the invariants that
   require a MAJOR DECISION + ADR to change.
2. [`docs/product/PRODUCT_CONSTITUTION.md`](docs/product/PRODUCT_CONSTITUTION.md)
   and [`docs/product/SECURITY_MODEL.md`](docs/product/SECURITY_MODEL.md)
   — full product/security context.
3. [`docs/development/campaign-state.md`](docs/development/campaign-state.md)
   — current campaign state, active work, next planned action.
4. [`CONTRIBUTING.md`](CONTRIBUTING.md) — branch/commit/PR/testing
   workflow.
5. [`.claude/CLAUDE.md`](.claude/CLAUDE.md) — the full project gate:
   engineering constraints, feature-level QA and Docs Impact
   requirements, and when to stop and ask the founder instead of
   deciding silently.

Everything in `.claude/CLAUDE.md` applies regardless of which agent is
reading it — it is written agent-agnostically on purpose.
