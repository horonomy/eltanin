<!--
Template for a Feature Verification Record (HORO-819).

Copy this file to `<feature-id>.md` (e.g. `F-M1-010.md`) in this
directory once the last subtask implementing that Feature lands. Delete
this comment block and every `<!-- ... -->` hint below; keep section
headings. See docs/qa/README.md for what this record is for and the
release-gate contract it feeds. F-M1-006.md, F-M1-008.md, and F-M1-009.md
follow this exact shape — read one of them (F-M1-006.md and F-M1-009.md
are good examples of a multi-subtask and a single-subtask Feature
respectively) rather than guessing from this template alone. The three
earliest records (F-M1-003/004/005) predate this template: they close
with an extra "Verdict" section this template omits, and fold
independent-review findings inline into "AC verification"/"Known
limitations" rather than under their own heading — a new record should
follow this template's shape, not theirs.
-->

# Feature Verification Record — <feature-id>: <Feature name>

**Feature ticket**: <Jira Feature ticket, e.g. HORO-823>.
**Status**: PASS | FAIL | BLOCKED.
<!-- If PASS but with a materially reduced scope (e.g. hardware-independent
     only), say so here, e.g. "PASS (hardware-independent scope — see
     'Known limitations' below)." -->
**QA status source**: this record, following the format established by
<!-- cite the 1-2 nearest-precedent existing records, e.g. "F-M1-006.md
     (HORO-840), F-M1-009.md (HORO-824)" -->.

## Subtasks and evidence

| Subtask | What it delivered | PR | Evidence |
|---|---|---|---|
<!-- One row per subtask ticket. "Evidence" names the actual test
     file(s)/module(s) that back this subtask's claims — not "tests
     pass," the specific files a reader could go open. -->

## AC verification (<subtask or Feature ticket the AC came from>)

<!-- One bullet per acceptance criterion from the Feature's Jira ticket
     (and/or its subtasks'). Each bullet: state the criterion, then name
     the specific test(s) that verify it and, in one sentence, what they
     actually exercise (not just the test name). -->

- **<AC statement>.** `<test_file.rs>::<test_fn_name>` <what it proves>.
- **<Feature Verification Record can be evaluated independently.>** This
  document. <!-- keep this bullet; every existing record has it -->

## Independent review

<!-- If an adversarial review subagent ran before merge (this campaign's
     standing practice — see docs/qa/README.md's "Independence
     principle"), summarize its findings here, ranked by severity, each
     with what was found and how it was fixed (or why it was accepted as
     a known limitation instead). If a subtask had its own review
     already documented in its own PR/Jira comment, a short pointer plus
     a summary is enough — don't re-litigate it in full here. -->

## Known limitations (carried forward, not silently closed)

<!-- Every deliberate scope boundary, deferred mechanism, or accepted
     trade-off this Feature ships with. Silence here is read as "no
     limitations exist" — if one does, name it, even if it was already
     named in a design doc or ADR; this is the one place QA expects to
     find the full list in one place. -->
