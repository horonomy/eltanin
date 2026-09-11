<!--
Release Quality Report template (HORO-810).

Copy this file to docs/qa/reports/<version>/release-quality-report.md
(e.g. docs/qa/reports/mvp-1.0/release-quality-report.md) when a real
release/milestone gate is actually being evaluated — not before. An
instantiated report makes a factual claim about a specific commit/tag;
do not pre-fill one speculatively. Delete this comment block and every
`<!-- ... -->` hint below when instantiating.
-->

# Release Quality Report — <version>

**Commit/tag tested**: <full commit SHA or tag>.
**Test plan revision**: [`docs/qa/test-plans/<version>.md`](../test-plans/<version>.md)
<!-- link the exact test plan file this report was evaluated against -->.
**Report date**: <date>.

## Feature inventory and per-Feature QA verdict

<!-- One row per in-scope Feature. Cross-reference
     docs/qa/README.md's Feature inventory table and each Feature's
     Verification Record — do not re-derive verdicts independently. -->

| Feature | Feature Verification Record | QA status |
|---|---|---|

## Environment / hardware

<!-- What actually ran the automated suites for this report: OS,
     architecture, whether any hardware-dependent suite ran and on what
     hardware, or an explicit "no hardware evidence — see gap below." -->

## Automated suites executed

<!-- e.g. "cargo test --workspace at <commit>: N passed, 0 failed,
     M suites" plus any Track B (docs/qa/e2e/) runs and their result. -->

## Manual checks (if any)

<!-- State none if none were needed — don't leave this section silently
     empty without saying so. -->

## Failed / skipped / deferred, and why

<!-- Reference docs/qa/test-plans/<version>.md's "Open gaps summary"
     rather than re-deriving a new list — this section should be short
     if that document is current. -->

## Known risks

## Critical/High blockers

<!-- If none, say so explicitly rather than leaving blank. -->

## Final QA/Security recommendation

<!-- GO / NO-GO / CONDITIONAL, with the one-sentence reason. -->
