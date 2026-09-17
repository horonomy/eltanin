# MVP 2.0 Developer Dogfood Session — Results (HORO-797)

**UNPOPULATED — pending a real dogfood session.**

No human multi-hour developer dogfood session has been run yet. Every
metric field below is a placeholder. Do not fill in any field with an
invented, estimated, or "plausible-looking" number — populate this
document only from the actual evidence a real session produces per
[`mvp-2.0-developer-session.md`](mvp-2.0-developer-session.md).

## Session metadata

| Field | Value |
|---|---|
| Date/time run | UNPOPULATED — pending a real dogfood session |
| Operator (founder) | UNPOPULATED — pending a real dogfood session |
| Platform (Linux / macOS, real hardware or `FakeBackend`) | UNPOPULATED — pending a real dogfood session |
| Session duration (wall clock) | UNPOPULATED — pending a real dogfood session |
| `eltanin` / `eltanin-agentd` build (git commit) | UNPOPULATED — pending a real dogfood session |
| Gates active (`ELTANIN_AGENT_SESSION_REQUIRED` / `_APPROVAL_REQUIRED` / `_REVOCATION_REQUIRED`) | UNPOPULATED — pending a real dogfood session |
| Raw audit log path used | UNPOPULATED — pending a real dogfood session |

## Machine-derived metrics (from `scripts/dogfood-metrics.sh`)

Paste the script's "Category breakdown" output here verbatim once the
session has run. Every count below is UNPOPULATED until then — do not
estimate them from the feature verification records or from this
procedure's own worked examples.

| RecordedOutcome | Count |
|---|---|
| `granted` (ordinary) | UNPOPULATED — pending a real dogfood session |
| `granted_by_delegation` | UNPOPULATED — pending a real dogfood session (expected 0 today — delegation is not operator-configurable via `eltanin-agentd`, see procedure §0) |
| `would_grant` (shadow mode) | UNPOPULATED — pending a real dogfood session (expected 0 unless `ELTANIN_AGENT_MODE=shadow` was used) |
| `policy_denied` | UNPOPULATED — pending a real dogfood session |
| `session_required` | UNPOPULATED — pending a real dogfood session |
| `approval_required` | UNPOPULATED — pending a real dogfood session |
| `approval_denied` | UNPOPULATED — pending a real dogfood session |
| `step_up_required` | UNPOPULATED — pending a real dogfood session (expected 0 today — risk layer is not operator-configurable via `eltanin-agentd`, see procedure §0) |
| `risk_denied` | UNPOPULATED — pending a real dogfood session (expected 0 today — see procedure §0) |
| `delegation_refused` | UNPOPULATED — pending a real dogfood session (expected 0 today — see procedure §0) |
| `delegation_indeterminate` | UNPOPULATED — pending a real dogfood session (expected 0 today — see procedure §0) |
| Total decision records | UNPOPULATED — pending a real dogfood session |
| Total agent-emitted events (e.g. rotation markers) | UNPOPULATED — pending a real dogfood session |
| Unreadable/malformed lines | UNPOPULATED — pending a real dogfood session |
| Wall-clock span (first to last event) | UNPOPULATED — pending a real dogfood session |

## Human-judged metrics

These require a human reading the session's own notes and the raw audit
log — `dogfood-metrics.sh` cannot compute them (see the procedure's
metric-to-surface mapping table, §8).

### Prompts / step-ups the developer actually saw

UNPOPULATED — pending a real dogfood session. (Record: how many times
did the developer see an approval prompt or step-up requirement land in
their actual workflow, and did they understand why, in the moment,
without consulting `eltanin explain`?)

### False blocks

**Count**: UNPOPULATED — pending a real dogfood session.

**Which denials were judged false, and why**: UNPOPULATED — pending a
real dogfood session. For each one: the command that was denied, the
`RecordedDecisionReason`/`RecordedOutcome` the raw log recorded for it,
and the specific reason the developer judged the denial to be wrong
(e.g. a policy rule that was stricter than intended, a profile
misconfiguration, a stale approval that should have still matched).

### Bypass attempts

**Count**: UNPOPULATED — pending a real dogfood session.

**Description of each**: UNPOPULATED — pending a real dogfood session.
Self-reported honestly, including any bypass that *succeeded* — a
successful bypass may leave no trace in the audit log at all (it never
reached the agent), so this field cannot be reconstructed from the log
after the fact and depends entirely on the developer's own account.

### Latency / overhead

**`time eltanin run --profile <name> -- <command>`** (wrapped): UNPOPULATED — pending a real dogfood session.

**Same command run directly** (no `eltanin run`): UNPOPULATED — pending a real dogfood session.

**Perceived overhead** (developer's own qualitative assessment — did it
feel slow, did it interrupt flow): UNPOPULATED — pending a real dogfood
session.

*Note*: no built-in latency instrumentation exists in the audit schema
today — this is a deliberately deferred gap, not an oversight. See the
procedure document's "Deferred: no built-in latency instrumentation"
section for why a schema-level latency field was not added as part of
this ticket.

### Unexpected allow/deny behavior

**Count**: UNPOPULATED — pending a real dogfood session.

**Description of each**: UNPOPULATED — pending a real dogfood session.
For each: what the developer expected to happen, what actually
happened, and the `RecordedOutcome`/`RecordedDecisionReason` the raw log
shows for it.

### Seeded trust-transition event (procedure §4)

**What was seeded**: UNPOPULATED — pending a real dogfood session.

**Observed reaction** (denial + recorded outcome, or an unexpected
silent allow — the latter is a stop-the-session finding per the
procedure, not an ordinary results row): UNPOPULATED — pending a real
dogfood session.

**Recovery confirmed** (re-approval succeeded, work resumed): UNPOPULATED — pending a real dogfood session.

### Session-end / revocation confirmation

**Leases confirmed revoked at session end**: UNPOPULATED — pending a
real dogfood session.

## Overall assessment

UNPOPULATED — pending a real dogfood session. Do not draft a PASS/FAIL/
CONCERNS verdict for HORO-797's dogfood evidence until every field above
is populated from a real session.
