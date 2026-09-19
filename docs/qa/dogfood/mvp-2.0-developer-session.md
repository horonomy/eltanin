# MVP 2.0 Developer Dogfood Session — Procedure (HORO-797)

**Status of this document**: a procedure only. **No dogfood session has
been run.** This document defines exactly what a human founder should
do to run a real, multi-hour developer session under Eltanin's trust
boundary and produce the evidence
[`mvp-2.0-results.md`](mvp-2.0-results.md) records. No agent may run
this session on the founder's behalf, and no agent may fabricate or
estimate the metrics this procedure produces — they exist only once a
human has actually run it.

## Why this session exists

HORO-797 is the MVP 2.0 release-readiness gate. Every one of the six
MVP 2.0 Features (F-M2-001..006) has a PASS Feature Verification Record
against isolated integration tests (`docs/qa/feature-verification/`),
but none of them has been exercised together, continuously, by a real
developer doing real work, under real trust-boundary pressure. This
session is that evidence: prompts/step-ups a developer actually saw,
denials that turned out to be wrong (false blocks), attempts to work
around the boundary (bypass attempts), the perceived and measured
overhead of `eltanin run` versus running a workload directly, and any
allow/deny outcome that surprised the person running it.

## 0. What this session can and cannot exercise today

Read this before starting — it changes what "seeded event" (§4) can
actually mean in this session.

**Updated by HORO-1278.** Two things changed since this document was
first written, and both matter to this session:

1. **The Trusted Compute Session bug that would have broken this
   session outright is fixed.** `eltanin session start` used to anchor
   the session to its own short-lived process, so it died the instant
   that process exited — every later `eltanin run`/`session list` in
   this same procedure would have seen no active session, making
   `ELTANIN_AGENT_SESSION_REQUIRED=1` a deny-all. This is now fixed
   (session identity is resolved from the terminal's own POSIX session
   id, never the connecting CLI peer — see
   [ADR 0015](../adr/0015-trusted-compute-session-anchor-and-binding.md)).
   §1/§2's instructions below already describe the correct, now-real
   behavior.
2. **F-M2-003 (Bounded Compute Delegation) and F-M2-004 (Risk-Based
   Step-Up) are now operator-configurable**, closed as part of
   HORO-1278's scope: `eltanin-agentd`'s `configure_gates` (see
   `crates/eltanin-agent/src/bin/eltanin-agentd.rs`) now also reads
   `ELTANIN_AGENT_GATE_CONFIG`, a JSON file naming a `delegation` and/or
   `step_up` section (see `crates/eltanin-agent/src/authz/gate_config.rs`
   and `docs/product/CLI_CONTRACT.md` for the exact schema). §1's
   startup command below includes it. **This does require the approval
   pairing** (`ELTANIN_AGENT_APPROVAL_REQUIRED` + `_APPROVAL_STORE`,
   both already part of this session's setup) — delegation/step-up
   cannot be enabled independently of approvals.

**Practical consequence for this session, now that all six Features are
reachable**: a launcher-identity change (§4) can now genuinely surface
as `StepUpRequired`/`RiskDenied` if the seeded event matches a
configured risk signal (e.g. an untrusted execution path), not only as
a plain `ApprovalRequired` refusal — which of the two you actually see
depends on exactly which signal your seeded event trips and how
`gate-config.json` (§1) maps it. Read the real `eltanin explain --chain`
output for the seeded event rather than assuming which path fired.
Delegation (F-M2-003) is exercisable too if the session's workload
spawns a bounded descendant process through `eltanin run` — see §3's
workload guidance.

If your `gate-config.json` leaves `step_up`/`delegation` unconfigured
(a valid choice — they're optional sections), the old caveat still
applies for that section only: its `RecordedOutcome` variants will
correctly read zero, and that's a configuration choice, not a defect.
Record in `mvp-2.0-results.md` exactly which sections you configured.

## 1. Environment setup

Pick (or create) a private working directory, e.g. `$HOME/eltanin-dogfood/`,
and a private socket directory (the agent refuses to bind into a
world-writable directory):

```sh
mkdir -m 0700 -p $HOME/eltanin-dogfood/sock
```

Write a real policy naming your own uid (see
`docs/product/POLICY_EXAMPLES.md`'s "Worked example: `eltanin run`" for
the exact shape) and a profile pointing at the resource(s) you'll
actually use for the session (real GPU/local-model resources your
workload touches, not just `fake`/`gpu-0` if you have real hardware
wired to a real backend — see `docs/qa/feature-verification/F-M1-010.md`
for the Apple Silicon path, or `POLICY_EXAMPLES.md` for `FakeBackend`
if you don't).

(Optional but recommended, now that HORO-1278 closed the config gap)
write a `gate-config.json` to exercise F-M2-003/004 as well — see
`docs/product/CLI_CONTRACT.md`'s `ELTANIN_AGENT_GATE_CONFIG` section for
the exact schema; a minimal example enabling step-up on an untrusted
path prefix:

```json
{
  "version": 7,
  "payload": {
    "step_up": {
      "dispositions": { "untrusted_execution_path": "step_up" },
      "untrusted_path_prefixes": ["/tmp/", "/var/tmp/"]
    }
  }
}
```

Start the agent with the full MVP 2.0 trust boundary turned on — this is
the point of the session, so do not skip any of these:

```sh
ELTANIN_AGENT_SOCKET=$HOME/eltanin-dogfood/sock/agent.sock \
ELTANIN_AGENT_SOCKET_MODE=0600 \
ELTANIN_AGENT_POLICY=$HOME/eltanin-dogfood/policy.json \
ELTANIN_AGENT_LEASE_TTL_SECS=3600 \
ELTANIN_AUDIT_LOG=$HOME/eltanin-dogfood/audit.ndjson \
ELTANIN_AGENT_SESSION_REQUIRED=1 \
ELTANIN_AGENT_APPROVAL_REQUIRED=1 \
ELTANIN_AGENT_APPROVAL_STORE=$HOME/eltanin-dogfood/approvals.json \
ELTANIN_AGENT_REVOCATION_REQUIRED=1 \
ELTANIN_AGENT_GATE_CONFIG=$HOME/eltanin-dogfood/gate-config.json \
eltanin-agentd
```

(Omit the `ELTANIN_AGENT_GATE_CONFIG` line entirely if you don't want to
exercise F-M2-003/004 this session — it's optional, not required for a
valid run.)

Notes:

- `ELTANIN_AGENT_REVOCATION_REQUIRED=1` only admits resources whose
  backend actually supports `DeviceRevoke` — if your real backend
  doesn't yet, leave this unset rather than making every request
  `PolicyDenied` for the wrong reason; note whichever choice you made in
  the results template.
- Leave `ELTANIN_AGENT_MODE` unset (defaults to `enforce`) — this
  session is exercising real enforcement, not shadow observation.
- Keep this terminal open and visible for the whole session; its stderr
  is the only place a write failure to the audit log would surface
  (`AuditFileSink::failed_writes`, see `sink.rs`'s durability-is-best-
  -effort docs) — a founder-visible stall/error here is itself dogfood
  evidence.

In a **second terminal** (the one you'll actually work in for the whole
session — Trusted Compute Session membership is derived server-side
from the connecting peer's own POSIX session id, kernel-observed at
request time, never a client-supplied token; a subshell or a fresh
process group started outside that terminal's session is simply not a
member, and `eltanin session start`/`eltanin run` invoked from two
different session ids will not see each other's session at all. Do not
switch terminals, and do not run `session start` and the workload from
two separately-launched shells expecting them to share one session,
unless you intend to test that a non-member is correctly refused):

```sh
export ELTANIN_AGENT_SOCKET=$HOME/eltanin-dogfood/sock/agent.sock
export ELTANIN_PROFILE_DIR=$HOME/eltanin-dogfood/profiles
```

Confirm the gates are actually active before starting real work:

```sh
eltanin status
```

should report `enforcement mode: enforce`, `session required: yes`,
`approval required: yes`, and whatever you chose for revocation. If any
of these silently reads `NO`, stop and fix the environment — the whole
session's evidence is only meaningful if the boundary was actually live.

## 2. Session start

```sh
eltanin session start --profile <your-profile> --ttl <duration>
```

Use a `--ttl` that safely covers the planned session length (this
session is multi-hour — pick something like `8h`, not the default
demo's `2h`, so a lease/session expiry mid-session isn't confused with
a deliberate trust transition in §4). Confirm the session actually
resolved via `eltanin status` or a `eltanin session list` before
starting real work.

## 3. Representative multi-hour workload

Run your actual development work for this session **through `eltanin
run`**, not around it — every workload that would, in production, touch
protected compute:

- A coding agent session (Claude Code, or whatever you actually use)
  invoking sub-agents that spawn build/test processes.
- Normal container builds/runs.
- A local AI model invocation (whatever local inference you actually
  run day to day) via `eltanin run --profile <name> -- <command>`.
- Ordinary non-agent developer commands that happen to touch the same
  protected resource, so the session captures real background friction,
  not just agent-initiated calls.

Work normally. Do not pre-plan every command to "look clean" for this
report — the entire point is to surface real friction, including
friction you'd normally route around without thinking about it. If a
command is denied and you don't understand why, that is exactly what
`eltanin explain`/`eltanin-explain` and this session's results template
exist to capture — don't silently retry until it works and forget it
happened.

## 4. Deliberate trust-transition injection (at least one)

Partway through the session (not at the very start — you want at least
one clean stretch of ordinary approved work first), seed **at least
one** real trust-boundary transition and confirm the system reacts as
documented:

**Recommended**: swap the `eltanin` launcher binary mid-session.

1. Note the current binary's path (`which eltanin`) and keep a backup
   copy.
2. Replace it with a different (but still valid) build — even
   recompiling with a trivial change is enough, since F-M2-002's
   remembered-approval matching keys on `LauncherDigest` (see
   `crates/eltanin-core/src/approval.rs`'s `ChangedDimension`), so any
   byte-for-byte-different binary at the same path changes what the
   approval store remembers.
3. Run the same profile/command you had previously `--remember`-approved.

**Expected reaction**: the request is refused — `ApprovalRequired`/
`ApprovalDenied` if you left `step_up` unconfigured, or possibly
`StepUpRequired`/`RiskDenied` if your `gate-config.json` (§1) maps this
launcher's changed path/identity to a configured risk signal (see §0).
`eltanin explain --pid <pid>` names which one actually fired, and the
raw audit log records the corresponding `RecordedOutcome` for it. If instead the swapped binary is silently
admitted, that is a **false negative** — the single most important
possible finding of this whole session — stop, do not continue the
session normally, and escalate to the founder/security review
immediately rather than filing it as an ordinary results-template row.

Optional additional seeded events, if time allows: end the session
(`eltanin session end`) and issue a request from the *same* terminal
without restarting it (expect `SessionRequired`/`NoTrustedSession`);
open a second terminal and try to reuse the first terminal's approval
without ever calling `eltanin session start` there (expect refusal,
proving session admission isn't satisfied by "any session exists
somewhere").

## 5. Recovery

After the seeded denial in §4:

```sh
eltanin approve --profile <profile> --remember
```

(or `--once` if you deliberately want to exercise the other disposition
instead — per `ApprovalDisposition::Once`'s own doc comment, `Once`
lives only in agent memory with a short TTL and is consumed on its
first successful matched use, unlike `--remember`, which is durable
until explicitly `forget`ten or invalidated by a material change).
Confirm the
identical command that was just denied now succeeds, and that ordinary
work resumes without further unexpected friction.

## 6. Session end

```sh
eltanin session end
```

Then confirm leases actually revoked rather than merely reporting
success:

- `eltanin status` (no crash, sane enforcement mode still reported).
- The audit log's last several entries for a `SessionTerminated`
  `RecordedOutcome` and, if any lease was still outstanding when the
  session ended, a cascaded `Released`/revocation entry for it — do not
  just trust the CLI's exit code; read the raw log (§7) to confirm.

## 7. Evidence capture

Run, in order, once the session above is complete:

```sh
# Recent activity, human-readable, best-effort ordering only — a sanity
# read, not the source of any metric in the results template.
eltanin audit --limit 500 --log $HOME/eltanin-dogfood/audit.ndjson

# Full decision record for the seeded denial in §4 and any other
# surprising outcome you noted during the session — replace <pid> with
# the pid `eltanin run` printed at the time.
eltanin explain --log $HOME/eltanin-dogfood/audit.ndjson --pid <pid> --chain

# The metrics this session actually needs — reads the RAW log, never
# the two commands above's rendered output (see script header for why).
scripts/dogfood-metrics.sh $HOME/eltanin-dogfood/audit.ndjson
```

Copy `scripts/dogfood-metrics.sh`'s "Category breakdown" section
straight into `mvp-2.0-results.md`'s machine-derived fields. Then fill
in every human-judged field in that template by hand, from your own
notes taken *during* the session (see §8's table for which fields those
are) — do not reconstruct them after the fact from memory alone; keep a
running scratch note open throughout §3 for exactly this purpose.

## 8. Metric-to-surface mapping

| Metric | Surface that captures it | Machine-derivable via `dogfood-metrics.sh`? |
|---|---|---|
| Count of approval prompts / step-ups seen | Raw audit log `RecordedOutcome::ApprovalRequired`/`StepUpRequired` | **Yes** (step-up reads 0 only if `gate-config.json`'s `step_up` section was left unconfigured — see §0) |
| Count of risk-denials | Raw audit log `RecordedOutcome::RiskDenied` | **Yes** (0 only if `step_up` unconfigured or no seeded signal mapped to `deny`) |
| Count of delegation refusals | Raw audit log `RecordedOutcome::DelegationRefused`/`DelegationIndeterminate` | **Yes** (0 only if `gate-config.json`'s `delegation` section was left unconfigured, or no bounded-descendant workload was run — see §0/§3) |
| Count of grants (ordinary + delegated) | Raw audit log `RecordedOutcome::Granted`/`GrantedByDelegation` | **Yes** |
| Session wall-clock duration | Raw audit log first/last `recorded_at` | **Yes** |
| False-block count, and *why* each was judged false | A denial the developer determined, after reading `eltanin explain`, should not have been denied | **No — human judgment required.** The log can tell you a denial happened and its `RecordedDecisionReason`/`RecordedOutcome`; it cannot tell you whether the policy/config that produced it was *wrong*. Tally by hand during/after the session. |
| Bypass-attempt count, and description | Any point the developer tried to route around `eltanin run` (running the workload directly, editing the policy mid-session to self-approve, etc.) | **No — human judgment/self-report required.** A bypass attempt that *succeeded* may leave no trace in this audit log at all, by definition (it never went through the agent) — this is a genuine blind spot, not merely "hard," and must be self-reported honestly. |
| Latency / overhead of `eltanin run` vs. direct execution | Wall-clock-wrapping `eltanin run` invocations externally | **No — deferred, see below.** |
| Unexpected allow/deny count, and description | Any outcome that surprised the developer relative to their own mental model of the policy | **Partially.** The log proves *what* happened; whether it was *unexpected* is a human judgment call, though a surprising outcome is often visible in the log as a `RecordedDecisionReason` the developer didn't anticipate (e.g. `ExplicitDeny` firing from a rule they forgot existed). |
| Audit-log write failures | `AuditFileSink::failed_writes` (only visible via agent stderr, not the log itself — a failed write is definitionally missing from the log) / `LogScan::gaps` in `eltanin-explain`'s own gap detection | **Partially** — `dogfood-metrics.sh` does not compute gaps (that logic lives in `eltanin_audit::explain::detect_gaps` and isn't duplicated here); run `eltanin-explain`'s own gap-aware selectors, or note visibly from the agent's stderr, if a write failure is suspected. |

### Deferred: no built-in latency instrumentation

This session's audit schema (`DOMAIN_SCHEMA_VERSION` 7 as of HORO-1278's
session-refusal audit-fidelity bump) does not carry a latency/overhead
field, and none was added for this ticket. Adding one to `AuditRecord`
would bump `DOMAIN_SCHEMA_VERSION` again — a real schema change that
invalidates every durable `Approval` on disk (ADR 0010's `recall()`
schema-version check, the same effect every one of this campaign's
schema bumps already had) — which is a product decision for a future
ticket, not something QA instrumentation should smuggle in as a side
effect of this dogfood session. Measure latency/overhead externally
instead:

```sh
time eltanin run --profile <name> -- <command>
```

against the same command run directly (without `eltanin run`), and
record both numbers by hand in the results template. This gap is named
here deliberately, not silently worked around.
