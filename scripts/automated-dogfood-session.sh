#!/usr/bin/env bash
# Automated real-machine dogfood session for HORO-797 (MVP 2.0).
#
# Runs the SAME procedure as docs/qa/dogfood/mvp-2.0-developer-session.md
# against real `eltanin-agentd`/`eltanin` binaries, real Unix sockets, real
# processes, and real OS behavior (FakeBackend stands in only for the GPU
# device itself, since no NVIDIA/Apple hardware is wired into this CI/dev
# host — everything else: the daemon, the socket, the policy engine, the
# session/approval/audit machinery, process spawn/kill, is real).
#
# This script exists to produce objective, automatable evidence for the
# things a human dogfood session was previously the only source of:
# approval flows, allow/deny flows, false-block probes, repeated
# invocation/session persistence, failure/recovery, latency, and audit
# trail verification. It does NOT attempt to produce the genuinely
# subjective fields (bypass-attempt self-report, "did this feel
# surprising") that docs/qa/dogfood/mvp-2.0-results.md reserves for a
# human session — see docs/qa/dogfood/automated-session-results.md for
# where this script's output is recorded, kept separate from that file.
#
# Usage: scripts/automated-dogfood-session.sh
# Requires: eltanin-agentd and eltanin already built (cargo build --workspace --bins).

set -euo pipefail

BIN_DIR="${ELTANIN_BIN_DIR:-$(cargo metadata --no-deps --format-version1 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])' 2>/dev/null || echo target)/debug}"
ELTANIN="$BIN_DIR/eltanin"
AGENTD="$BIN_DIR/eltanin-agentd"

if [[ ! -x "$ELTANIN" || ! -x "$AGENTD" ]]; then
  echo "FATAL: binaries not found at $BIN_DIR (set ELTANIN_BIN_DIR)" >&2
  exit 1
fi

WORKDIR="$(mktemp -d /tmp/eltanin-automated-dogfood.XXXXXX)"
mkdir -m 0700 -p "$WORKDIR/sock"
UID_SELF="$(id -u)"
AUDIT_LOG="$WORKDIR/audit.ndjson"
POLICY="$WORKDIR/policy.json"
APPROVALS="$WORKDIR/approvals.json"
GATE_CONFIG="$WORKDIR/gate-config.json"
SOCK="$WORKDIR/sock/agent.sock"
REPORT="$WORKDIR/report.txt"

echo "== Automated dogfood session ==" | tee "$REPORT"
echo "workdir: $WORKDIR" | tee -a "$REPORT"
echo "started (UTC): $(date -u +%FT%TZ)" | tee -a "$REPORT"
echo "git commit: $(git rev-parse HEAD)" | tee -a "$REPORT"

cat > "$POLICY" <<JSON
{
  "version": 7,
  "payload": {
    "id": "automated-dogfood-policy",
    "revision": 1,
    "rules": [
      {
        "id": "allow-self-via-eltanin-run",
        "effect": "allow",
        "resource": { "vendor": "fake", "kind": "gpu", "local_id": "gpu-0" },
        "action": "compute",
        "conditions": [
          { "field": "uid", "expected": $UID_SELF, "min_trust": "kernel_observed" }
        ]
      },
      {
        "id": "deny-root",
        "effect": "deny",
        "resource": { "vendor": "fake", "kind": "gpu", "local_id": "gpu-0" },
        "action": "compute",
        "conditions": [
          { "field": "uid", "expected": 0, "min_trust": "kernel_observed" }
        ]
      }
    ]
  }
}
JSON

cat > "$GATE_CONFIG" <<'JSON'
{
  "version": 7,
  "payload": {
    "step_up": {
      "dispositions": { "untrusted_execution_path": "step_up" },
      "untrusted_path_prefixes": ["/tmp/", "/var/tmp/"]
    }
  }
}
JSON

echo "[1/10] starting eltanin-agentd (real daemon, real socket)" | tee -a "$REPORT"
ELTANIN_AGENT_SOCKET="$SOCK" \
ELTANIN_AGENT_SOCKET_MODE=0600 \
ELTANIN_AGENT_POLICY="$POLICY" \
ELTANIN_AGENT_LEASE_TTL_SECS=3600 \
ELTANIN_AUDIT_LOG="$AUDIT_LOG" \
ELTANIN_AGENT_SESSION_REQUIRED=1 \
ELTANIN_AGENT_APPROVAL_REQUIRED=1 \
ELTANIN_AGENT_APPROVAL_STORE="$APPROVALS" \
ELTANIN_AGENT_GATE_CONFIG="$GATE_CONFIG" \
"$AGENTD" > "$WORKDIR/agentd.stdout.log" 2> "$WORKDIR/agentd.stderr.log" &
AGENTD_PID=$!
sleep 1
if ! kill -0 "$AGENTD_PID" 2>/dev/null; then
  echo "FATAL: agentd exited immediately, see $WORKDIR/agentd.stderr.log" | tee -a "$REPORT"
  cat "$WORKDIR/agentd.stderr.log" | tee -a "$REPORT"
  exit 1
fi
echo "agentd pid=$AGENTD_PID" | tee -a "$REPORT"

export ELTANIN_AGENT_SOCKET="$SOCK"
export ELTANIN_PROFILE_DIR="$WORKDIR/profiles"
mkdir -p "$ELTANIN_PROFILE_DIR"
cat > "$ELTANIN_PROFILE_DIR/fake-gpu-0.json" <<'JSON'
{
  "version": 7,
  "payload": {
    "resource": { "vendor": "fake", "kind": "gpu", "local_id": "gpu-0" },
    "action": "compute"
  }
}
JSON

echo "[2/10] eltanin status (confirm gates actually active)" | tee -a "$REPORT"
"$ELTANIN" status | tee -a "$REPORT"

echo "[3/10] session start (real TTL, real POSIX session id derivation)" | tee -a "$REPORT"
"$ELTANIN" session start --profile fake-gpu-0 --ttl 1h | tee -a "$REPORT" || true
"$ELTANIN" session list | tee -a "$REPORT" || true

echo "[3b/10] initial approval prompt (first real request denied, then remembered-approve)" | tee -a "$REPORT"
if "$ELTANIN" run --profile fake-gpu-0 -- /usr/bin/true >/dev/null 2>>"$WORKDIR/first.stderr.log"; then
  echo "unexpected: first request succeeded with no prior approval" | tee -a "$REPORT"
else
  echo "first request correctly required approval:" | tee -a "$REPORT"
  cat "$WORKDIR/first.stderr.log" | tee -a "$REPORT"
fi
"$ELTANIN" approve --profile fake-gpu-0 --remember | tee -a "$REPORT" || true

echo "[4/10] repeated real invocation / session persistence (50 iterations)" | tee -a "$REPORT"
OK=0
FAIL=0
for i in $(seq 1 50); do
  if "$ELTANIN" run --profile fake-gpu-0 -- /usr/bin/true >/dev/null 2>>"$WORKDIR/repeat.stderr.log"; then
    OK=$((OK+1))
  else
    FAIL=$((FAIL+1))
  fi
done
echo "repeated invocation: ok=$OK fail=$FAIL (expect fail=0 while session/policy unchanged)" | tee -a "$REPORT"

echo "[5/10] false-block probe (request that SHOULD be admitted under configured policy)" | tee -a "$REPORT"
if "$ELTANIN" run --profile fake-gpu-0 -- /usr/bin/true >/dev/null 2>>"$WORKDIR/probe.stderr.log"; then
  echo "false-block probe: PASS (admitted as policy requires)" | tee -a "$REPORT"
else
  echo "false-block probe: FAIL — request that policy explicitly allows was denied" | tee -a "$REPORT"
fi

echo "[6/10] latency measurement: eltanin run vs direct exec (20 iterations each)" | tee -a "$REPORT"
RUN_TIMES="$WORKDIR/run_times.txt"
DIRECT_TIMES="$WORKDIR/direct_times.txt"
: > "$RUN_TIMES"; : > "$DIRECT_TIMES"
for i in $(seq 1 20); do
  T0=$(python3 -c 'import time;print(time.time())')
  "$ELTANIN" run --profile fake-gpu-0 -- /usr/bin/true >/dev/null 2>&1 || true
  T1=$(python3 -c 'import time;print(time.time())')
  echo "$T1 $T0" | awk '{print ($1-$2)*1000}' >> "$RUN_TIMES"

  T0=$(python3 -c 'import time;print(time.time())')
  /usr/bin/true
  T1=$(python3 -c 'import time;print(time.time())')
  echo "$T1 $T0" | awk '{print ($1-$2)*1000}' >> "$DIRECT_TIMES"
done
python3 - "$RUN_TIMES" "$DIRECT_TIMES" <<'PY' | tee -a "$REPORT"
import sys, statistics
for label, path in [("eltanin run", sys.argv[1]), ("direct exec", sys.argv[2])]:
    vals = sorted(float(x) for x in open(path))
    n = len(vals)
    p95 = vals[int(n*0.95)-1] if n else float("nan")
    print(f"{label}: min={min(vals):.2f}ms median={statistics.median(vals):.2f}ms p95={p95:.2f}ms n={n}")
PY

echo "[7/10] deliberate trust-transition injection: swap launcher binary" | tee -a "$REPORT"
ALT_ELTANIN="$WORKDIR/eltanin-alt"
cp "$ELTANIN" "$ALT_ELTANIN"
# Ensure a byte-different binary (LauncherDigest differs) without needing a rebuild.
printf '\x00' >> "$ALT_ELTANIN" || true
chmod +x "$ALT_ELTANIN"
if "$ALT_ELTANIN" run --profile fake-gpu-0 -- /usr/bin/true >/dev/null 2>>"$WORKDIR/seeded.stderr.log"; then
  echo "SEEDED TRANSITION: FALSE NEGATIVE — swapped binary was silently admitted. ESCALATE." | tee -a "$REPORT"
  SEEDED_RESULT="FALSE_NEGATIVE"
else
  echo "seeded transition: correctly refused (see $WORKDIR/seeded.stderr.log)" | tee -a "$REPORT"
  cat "$WORKDIR/seeded.stderr.log" | tee -a "$REPORT"
  SEEDED_RESULT="CORRECTLY_REFUSED"
fi

echo "[8/10] recovery: re-approve and confirm the same command now succeeds" | tee -a "$REPORT"
"$ALT_ELTANIN" approve --profile fake-gpu-0 --remember >/dev/null 2>&1 || true
if "$ALT_ELTANIN" run --profile fake-gpu-0 -- /usr/bin/true >/dev/null 2>>"$WORKDIR/recovery.stderr.log"; then
  echo "recovery: PASS (post-approval retry succeeded)" | tee -a "$REPORT"
else
  echo "recovery: FAIL (post-approval retry still denied)" | tee -a "$REPORT"
  cat "$WORKDIR/recovery.stderr.log" | tee -a "$REPORT"
fi

echo "[9/10] failure/recovery: kill -9 the agent process, confirm fail-closed, restart" | tee -a "$REPORT"
kill -9 "$AGENTD_PID"
sleep 1
if "$ELTANIN" run --profile fake-gpu-0 -- /usr/bin/true >/dev/null 2>>"$WORKDIR/postkill.stderr.log"; then
  echo "AGENT-DOWN BEHAVIOR: FAIL-OPEN — request succeeded with no agent running. ESCALATE." | tee -a "$REPORT"
else
  echo "agent-down behavior: fail-closed (request correctly refused with no agent running)" | tee -a "$REPORT"
fi
ELTANIN_AGENT_SOCKET="$SOCK" \
ELTANIN_AGENT_SOCKET_MODE=0600 \
ELTANIN_AGENT_POLICY="$POLICY" \
ELTANIN_AGENT_LEASE_TTL_SECS=3600 \
ELTANIN_AUDIT_LOG="$AUDIT_LOG" \
ELTANIN_AGENT_SESSION_REQUIRED=1 \
ELTANIN_AGENT_APPROVAL_REQUIRED=1 \
ELTANIN_AGENT_APPROVAL_STORE="$APPROVALS" \
ELTANIN_AGENT_GATE_CONFIG="$GATE_CONFIG" \
"$AGENTD" > "$WORKDIR/agentd2.stdout.log" 2> "$WORKDIR/agentd2.stderr.log" &
AGENTD_PID2=$!
sleep 1
"$ELTANIN" status | tee -a "$REPORT"
echo "restarted agentd pid=$AGENTD_PID2" | tee -a "$REPORT"

echo "[10/10] session end + audit trail verification" | tee -a "$REPORT"
"$ELTANIN" session end 2>&1 | tee -a "$REPORT" || true
kill "$AGENTD_PID2" 2>/dev/null || true
sleep 1

echo "--- scripts/dogfood-metrics.sh output ---" | tee -a "$REPORT"
bash scripts/dogfood-metrics.sh "$AUDIT_LOG" | tee -a "$REPORT"

echo "" | tee -a "$REPORT"
echo "SEEDED_TRANSITION_RESULT=$SEEDED_RESULT" | tee -a "$REPORT"
echo "finished (UTC): $(date -u +%FT%TZ)" | tee -a "$REPORT"
echo "workdir preserved at: $WORKDIR" | tee -a "$REPORT"
echo "raw audit log: $AUDIT_LOG" | tee -a "$REPORT"
