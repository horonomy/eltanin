# MVP 2.0 Automated Real-Machine Dogfood Session — Results (HORO-797)

**Status of this document**: a real, executed automated run — distinct
from [`mvp-2.0-results.md`](mvp-2.0-results.md), which stays
UNPOPULATED and reserved for a genuine human multi-hour session. This
document exists because a 2026-09-19 founder policy update reclassified
subjective human dogfood as non-blocking for a Developer
Preview/prerelease and directed the strongest automatable real-machine
dogfood be run and recorded instead — see
[`docs/qa/reports/mvp-2.0/release-quality-report.md`](../reports/mvp-2.0/release-quality-report.md)'s
Verdict for how this evidence is used in the release decision.

This session used real `eltanin-agentd`/`eltanin` binaries, a real
Unix-domain socket, real process spawn/kill/restart, and a real raw
NDJSON audit log — nothing here is mocked except the GPU device itself,
which uses `FakeBackend` (a scripted double, in the Release Quality
Report's own terminology), since no NVIDIA/Apple hardware is available
in this execution environment; see the Release Quality Report's E3
discussion for why that does not affect this evidence's validity for
MVP 2.0's decision-layer scope.

## Session metadata

| Field | Value |
|---|---|
| Date/time run | 2026-09-19T11:52:08Z – 2026-09-19T11:54:36Z (UTC) |
| Operator | Automated — `scripts/automated-dogfood-session.sh`, run under this campaign's autonomous release-readiness directive |
| Platform | macOS (Apple Silicon), real `eltanin-agentd`/`eltanin` binaries, `FakeBackend` GPU |
| Session duration (wall clock) | ~1.5 minutes end-to-end script run; audit log's own recorded span was 73s (`session start` through `session end`) |
| `eltanin` / `eltanin-agentd` build (git commit) | `db9673344d4ebaf17c293981be90e605730a0cbf` (`origin/next/mvp-2.0`) |
| Gates active | `ELTANIN_AGENT_SESSION_REQUIRED=1`, `ELTANIN_AGENT_APPROVAL_REQUIRED=1` + `_STORE`, `ELTANIN_AGENT_GATE_CONFIG` (step-up on `untrusted_execution_path`); revocation left unset (`FakeBackend` does not support `DeviceRevoke`) |
| Raw audit log | Ephemeral `/tmp/eltanin-automated-dogfood.*/audit.ndjson`; full script output preserved in this PR's CI log and in the "Full script output" section below |

## What this run exercised (maps to the founder's automatable-dogfood list)

| Requested item | Exercised how | Result |
|---|---|---|
| Real local install / real CLI invocations | Real `eltanin`/`eltanin-agentd` binaries built from source, invoked via real `exec`, not a test harness mock | Done |
| A real long-running session | `eltanin session start --ttl 1h`, held across 50+ separate CLI invocations sharing one POSIX session id | Session persisted correctly across every invocation |
| Approval flows | First real request denied (`ApprovalRequired`), then `eltanin approve --remember`, then all subsequent requests admitted with no further prompt | Behaves as F-M2-002 documents |
| Allow/deny flows | Approval-required → approve → granted (allow path) exercised directly; a second policy rule denying a different resource (`gpu-1`) exercised with a remembered approval already in place, isolating the policy engine's own deny decision from the approval gate | Allow path: correct. Deny path: correct (`policy_denied` recorded). The policy's `uid == 0` deny-root rule specifically was **not** exercised — running as root is out of scope for this harness. |
| False-block probes | Two probes: (1) a request the configured policy explicitly allows, issued after approval, asserted Granted; (2) a request the configured policy explicitly denies, issued *after* approving it, asserted denied by the policy engine (not merely by the approval gate) | **PASS** on both — the allow rule was not falsely blocked, and the deny rule was not falsely bypassed by having an approval on file |
| Repeated invocation / session persistence | 50 sequential real `eltanin run` invocations after the initial approval | 50/50 succeeded, 0 unexplained denials |
| Failure/recovery | `kill -9` on the live agent process mid-session, then a request attempted with no agent running, then agent restarted | Fail-closed while agent was down (no fail-open); agent correctly reported live enforcement state after restart |
| Latency measurements | External wall-clock `time`-equivalent wrapping, 20 iterations each, `eltanin run` vs. direct exec (this session's audit schema deliberately carries no latency field — see the procedure doc's "Deferred: no built-in latency instrumentation") | See below — real, disclosed overhead finding |
| Audit trail verification | `scripts/dogfood-metrics.sh` run against the real raw NDJSON log | 0 unreadable/malformed lines across 157 decision records |
| Normal developer workflow simulation | Approve once, then run repeatedly without further friction — the low-friction "approve once per context" shape F-M2-002 is designed to produce | Matches design intent |

## Machine-derived metrics (`scripts/dogfood-metrics.sh` output, verbatim)

```
=== Dogfood audit-log metrics ===
readable decision records: 154
readable agent-emitted events: 0
unreadable/malformed lines: 0

--- Session wall-clock span ---
wall-clock span (secs):  73

--- RecordedOutcome tally (decision records) ---
  73 released
  73 granted
   3 status_reported
   3 approval_recorded
   1 session_not_found
   1 session_listed
   1 session_established
   1 policy_denied
   1 approval_required

--- Category breakdown ---
approval_required:          1
step_up_required:           0
risk_denied:                0
delegation_refused:         0
delegation_indeterminate:   0
granted (incl. delegation): 73
would_grant (shadow mode):  0
policy_denied:              1
all other outcomes:         82
```

The single `approval_required` is the expected first-ever request
(before any approval existed) — not an unexplained denial. The single
`policy_denied` is the deliberate policy-discrimination probe (§ above)
firing correctly. `session_not_found` (1) is the `eltanin session end`
issued against the restarted agent, which lost its in-memory session
state on restart (see "Findings" below). The seeded launcher-swap step
(below) is not reflected in this tally because it was inconclusive on
this host and produced no additional denial to count.

## Latency (external wall-clock, `eltanin run` vs. direct exec, n=20 each)

| | min | median | p95 |
|---|---|---|---|
| `eltanin run --profile fake-gpu-0 -- /usr/bin/true` | 891ms | 909ms | 925ms |
| Direct `/usr/bin/true` | 22ms | 23ms | 24ms |

## Seeded trust-transition injection (launcher binary swap)

Per the procedure's §4 "Recommended" scenario: after establishing a
remembered approval, a byte-different `eltanin` binary should be
substituted and the same previously-approved command re-run, expecting
`ApprovalRequired` (no remembered approval matches the new
`LauncherDigest`).

**This step's result on this host is honestly inconclusive, not a
security finding either way.** Placing ANY freshly-built or freshly-copied
`eltanin` binary at a new path on this specific execution host caused
the process to hang indefinitely at `dyld` startup (confirmed via
`sample` — stuck in `_dyld_start`, never reaching `main`), independent
of the binary's content, size, or code-signature validity: this
reproduced identically for (a) an independently rebuilt binary with a
trivial one-line source change, both freshly signed and re-signed ad
hoc, and (b) an unmodified byte-for-byte copy of the running binary
with no quarantine attribute. This is a macOS Gatekeeper/dyld
first-launch artifact of this host/session, unrelated to `eltanin`'s
own logic. A lower-effort fallback (a thin shell wrapper `exec`-ing the
original binary) avoids the hang but, because `exec` replaces the
process image, does not actually change the `LauncherDigest` the agent
observes — so its "admission" result is the *correct* outcome for what
it actually tested (an unchanged digest), not a false negative, and is
recorded as `NOT_EXERCISED_NO_ALT_BIN` rather than misreported as a
security failure.

**This does not leave the underlying security invariant unverified.**
`LauncherDigest`-change detection (`ChangedDimension::LauncherDigest`)
is proven by this codebase's own real Track A regression tests — see
[`F-M2-002.md`](../feature-verification/F-M2-002.md) — which exercise
the same code path directly without needing a second OS-level process
launch. This dogfood run simply could not *additionally* re-demonstrate
it end-to-end on this specific host; that gap is disclosed here rather
than silently worked around or misreported.

Recovery (approval-required → approve → granted) was still verified
directly with the real binary, independent of the launcher-swap step:
after an approval, `eltanin run` succeeded, confirming the ordinary
recovery path works.

## Findings (honest, recorded per the founder's explicit instruction — non-blocking unless they violate a stated correctness/security requirement)

1. **`eltanin run` overhead is roughly 900ms versus ~23ms direct** in
   this environment (~38x). This is real, measured, UX/performance
   friction, not a correctness or security defect — no requirement
   anywhere in `docs/product/` bounds acceptable `eltanin run` latency.
   Recorded here for a future performance ticket, does not block this
   release.
2. **`eltanin session end` against a daemon that restarted mid-session
   returns a generic "internal agent error" rather than a specific
   "no active session" message.** The underlying behavior is correct
   and fail-closed (a restarted agent has no in-memory record of the
   pre-restart session, so nothing is spuriously kept alive or
   spuriously granted) — this is a diagnostic-message quality gap, not
   a security or correctness defect. Recorded for a future UX ticket.
3. **Session/lease state does not survive an agent process restart.**
   Observed directly by killing and restarting the agent mid-session.
   This is consistent with `eltanin-agentd`'s documented design (no
   durable session-state store exists in MVP 2.0's scope) and is not a
   new discovery, but this run is the first time it was directly
   exercised end-to-end rather than only reasoned about from source.

## What this run does NOT provide, and why (genuinely non-automatable, per the founder's own policy)

- **Self-reported bypass attempts.** A successful bypass may, by
  definition, leave no trace in the audit log — this requires a human's
  own honest account of trying to route around the boundary, which an
  automated script cannot meaningfully simulate without begging the
  question (a scripted "bypass attempt" only proves what the script
  itself decided to try). Left open in `mvp-2.0-results.md`.
- **Subjective "was this surprising / was this excessive friction"
  judgment.** The log proves what happened; whether a real developer's
  mental model predicted it is inherently a human judgment call. Left
  open in `mvp-2.0-results.md`.

Both remaining gaps are UX evidence only, not a security or correctness
gap, and per the founder's 2026-09-19 policy do not block a Developer
Preview/prerelease.
