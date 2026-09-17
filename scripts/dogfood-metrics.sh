#!/usr/bin/env bash
# dogfood-metrics.sh — tally RecordedOutcome variants and session
# wall-clock duration from a *raw* Eltanin audit log (HORO-797).
#
# This reads the append-only NDJSON audit log that `eltanin-agentd`
# writes when `ELTANIN_AUDIT_LOG` is set (see
# `crates/eltanin-audit/src/sink.rs`), never `eltanin audit`'s or
# `eltanin explain`'s rendered output — both of those CLIs document
# their own display ordering/formatting as "best-effort, not
# authoritative" (see `crates/eltanin-cli/src/audit.rs`'s module docs),
# so they are not a stable machine-parseable source. The raw log is:
# one `Versioned<LogEntry>` JSON document per line, where `LogEntry` is
# internally tagged on `"record"` ("decision" | "agent") — see
# `crates/eltanin-audit/src/record.rs`.
#
# Handles bounded-retention rotation (AC6, HORO-824): if
# `<path>.1` exists, it holds the older generation and is read first, in
# the same order `crates/eltanin-audit/src/explain.rs::read_log` reads
# it — see that module's doc comment "Reading across a rotation".
#
# Usage:
#   scripts/dogfood-metrics.sh <path-to-audit-log>
#   scripts/dogfood-metrics.sh "$ELTANIN_AUDIT_LOG"
#
# Requires: jq.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <path-to-raw-audit-log>" >&2
  exit 2
fi

LOG_PATH="$1"
ROTATED_PATH="${LOG_PATH}.1"

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required but not found on PATH" >&2
  exit 2
fi

if [[ ! -e "$LOG_PATH" ]]; then
  echo "error: audit log not found at $LOG_PATH" >&2
  exit 1
fi

# Concatenate generations in write order: the rotated (older) generation
# first, then the live (current) one — matching
# `eltanin_audit::explain::read_log`'s own read order exactly, so this
# script's tallies agree with `eltanin audit`/`eltanin-explain` on which
# generation a given event id came from.
TMP_COMBINED="$(mktemp)"

if [[ -e "$ROTATED_PATH" ]]; then
  cat "$ROTATED_PATH" "$LOG_PATH" > "$TMP_COMBINED"
  echo "note: rotation detected — reading $ROTATED_PATH (older generation) then $LOG_PATH (current)" >&2
else
  cp "$LOG_PATH" "$TMP_COMBINED"
fi

if [[ ! -s "$TMP_COMBINED" ]]; then
  echo "audit log is empty — no records to tally"
  exit 0
fi

# Every line is `{"version": N, "payload": {"record": "decision"|"agent", ...}}`.
# Decision lines carry `payload.outcome.outcome` (the RecordedOutcome
# variant, snake_case per its `#[serde(tag = "outcome")]`); agent-event
# lines carry `payload.event.event` (the RecordedAgentEvent variant).
# Malformed lines (wrong schema version, truncated write) are counted
# and reported separately rather than silently dropped or aborting the
# whole tally — mirroring `LogScan::unreadable`'s "never silently skip"
# stance, though this script does not attempt `UnsupportedVersion`
# recovery the way `eltanin_audit::explain` does; it only distinguishes
# "parsed" from "did not parse as JSON."
VALID_JSON="$(mktemp)"
INVALID_COUNT=0
trap 'rm -f "$TMP_COMBINED" "$VALID_JSON"' EXIT

while IFS= read -r line; do
  [[ -z "${line// }" ]] && continue
  if jq -e . >/dev/null 2>&1 <<<"$line"; then
    echo "$line" >> "$VALID_JSON"
  else
    INVALID_COUNT=$((INVALID_COUNT + 1))
  fi
done < "$TMP_COMBINED"

# Count decisions/agent-events explicitly via jq rather than `grep -c`
# (whose exit status is 1, not just its printed count, when a pattern
# matches zero lines — a real difference in the all-lines-malformed
# case, where `$VALID_JSON` exists but is empty). Guard the empty case
# up front so `jq -s` is never asked to summarize zero documents in a
# way whose absence of output could be misread as "zero denials
# happened" rather than "nothing parsed at all."
if [[ -s "$VALID_JSON" ]]; then
  DECISION_COUNT=$(jq -s '[.[] | select(.payload.record == "decision")] | length' "$VALID_JSON")
  AGENT_COUNT=$(jq -s '[.[] | select(.payload.record == "agent")] | length' "$VALID_JSON")
else
  DECISION_COUNT=0
  AGENT_COUNT=0
fi

echo "=== Dogfood audit-log metrics ==="
echo "source: $LOG_PATH"
if [[ -e "$ROTATED_PATH" ]]; then
  echo "rotated generation included: $ROTATED_PATH"
fi
echo "readable decision records: $DECISION_COUNT"
echo "readable agent-emitted events: $AGENT_COUNT"
echo "unreadable/malformed lines: $INVALID_COUNT"
if [[ "$DECISION_COUNT" -eq 0 && "$AGENT_COUNT" -eq 0 ]]; then
  echo
  echo "WARNING: zero readable lines parsed from this log ($INVALID_COUNT unreadable)."
  echo "Every count below is genuinely zero because nothing parsed — this is NOT"
  echo "evidence that no denials/grants occurred during the session."
fi
echo

echo "--- Session wall-clock span ---"
jq -s '
  map(.payload.recorded_at.unix_secs) as $times
  | if ($times | length) == 0 then
      {first: null, last: null, duration_secs: null}
    else
      {first: ($times | min), last: ($times | max), duration_secs: (($times | max) - ($times | min))}
    end
' "$VALID_JSON" | jq -r '
  if .first == null then
    "no timestamped records found"
  else
    "first event (unix_secs): \(.first)\nlast event (unix_secs):  \(.last)\nwall-clock span (secs):  \(.duration_secs)\nwall-clock span (h:m:s): " +
    (.duration_secs as $d | ($d / 3600 | floor | tostring) + "h " + (($d % 3600 / 60) | floor | tostring) + "m " + ($d % 60 | tostring) + "s")
  end
'
echo

echo "--- RecordedOutcome tally (decision records) ---"
if [[ "$DECISION_COUNT" -eq 0 ]]; then
  echo "(no decision records)"
else
  jq -r '
    select(.payload.record == "decision")
    | .payload.outcome.outcome
  ' "$VALID_JSON" | sort | uniq -c | sort -rn
fi
echo

echo "--- RecordedAgentEvent tally (agent-emitted events) ---"
if [[ "$AGENT_COUNT" -eq 0 ]]; then
  echo "(no agent events)"
else
  jq -r '
    select(.payload.record == "agent")
    | .payload.event.event
  ' "$VALID_JSON" | sort | uniq -c | sort -rn
fi
echo

echo "--- Category breakdown (for pasting into the results template) ---"
if [[ "$DECISION_COUNT" -eq 0 ]]; then
  jq -n -r '
    ["approval_required","step_up_required","risk_denied","delegation_refused",
     "delegation_indeterminate","granted (incl. delegation)","would_grant (shadow mode)",
     "policy_denied","all other outcomes"]
    | .[] | . + ": 0"
  '
else
jq -r '
  select(.payload.record == "decision")
  | .payload.outcome.outcome
' "$VALID_JSON" | sort | uniq -c | sort -rn | awk '
  BEGIN {
    approval=0; stepup=0; risk_denied=0; delegation_refused=0; delegation_indeterminate=0;
    granted=0; would_grant=0; policy_denied=0; other=0;
  }
  {
    count=$1; $1=""; sub(/^ /, "", $0); outcome=$0;
    if (outcome == "approval_required") approval+=count;
    else if (outcome == "step_up_required") stepup+=count;
    else if (outcome == "risk_denied") risk_denied+=count;
    else if (outcome == "delegation_refused") delegation_refused+=count;
    else if (outcome == "delegation_indeterminate") delegation_indeterminate+=count;
    else if (outcome == "granted" || outcome == "granted_by_delegation") granted+=count;
    else if (outcome == "would_grant") would_grant+=count;
    else if (outcome == "policy_denied") policy_denied+=count;
    else other+=count;
  }
  END {
    printf "approval_required:          %d\n", approval;
    printf "step_up_required:           %d\n", stepup;
    printf "risk_denied:                %d\n", risk_denied;
    printf "delegation_refused:         %d\n", delegation_refused;
    printf "delegation_indeterminate:   %d\n", delegation_indeterminate;
    printf "granted (incl. delegation): %d\n", granted;
    printf "would_grant (shadow mode):  %d\n", would_grant;
    printf "policy_denied:              %d\n", policy_denied;
    printf "all other outcomes:         %d\n", other;
  }
'
fi
echo
echo "NOTE: this script counts every RecordedOutcome the agent itself"
echo "classified. It cannot tell you which denials were FALSE blocks,"
echo "which prompts were BYPASS ATTEMPTS, or measure request latency —"
echo "those require human judgment or external wall-clock wrapping. See"
echo "docs/qa/dogfood/mvp-2.0-developer-session.md's metric-to-surface"
echo "mapping table."
