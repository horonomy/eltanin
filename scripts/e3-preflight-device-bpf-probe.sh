#!/usr/bin/env bash
# E3 Stage-1 preflight probe: cgroup v2 BPF_CGROUP_DEVICE functional
# behavior (HORO-841 spike harness / HORO-790 Stage-1 preflight).
#
# WHAT THIS PROVES
#
# `BPF_PROG_TYPE_CGROUP_DEVICE` semantics (deny-before-open, allow after
# authorization, and clean attach/detach lifecycle) are a generic Linux
# kernel primitive — they do not require an NVIDIA GPU, or any real
# accelerator hardware at all, to investigate. This script answers
# several of HORO-841's "Required Investigation" bullets (deny-before-
# open behavior, program/attach lifecycle and cleanup, root/capability
# requirements) against a harmless synthetic device on ANY Linux host
# with cgroup v2 + eBPF — including a cheap GPU-free cloud VM/container.
#
# WHAT THIS DOES NOT PROVE
#
# This is NOT NVIDIA-specific and NOT a final HORO-790 E3 certification
# run. It never touches /dev/nvidia* or any real accelerator. Every
# result this script produces is labeled E3_PREFLIGHT_ONLY, never
# E3_PASS — see docs/development/hardware-validation-runbook.md's
# two-stage strategy section. It also does not yet prove already-open-
# handle/revoke behavior (see "KNOWN GAP" below) — that needs a
# dedicated sacrificial helper holding an open handle across a policy
# swap, tracked as the next increment, not claimed done here.
#
# BLAST-RADIUS COMPLIANCE (docs/qa/privileged-enforcement-testing.md)
#
# This script implements that document's Level 1 ("harmless canary in
# a disposable cgroup") pattern:
#   - the only process ever governed is a fresh canary this script
#     spawns for each phase (never the calling shell, this script's own
#     PID, or any pre-existing process);
#   - each canary is placed into its own freshly created leaf cgroup,
#     verified empty of any other PID before attach, and torn down
#     after that phase;
#   - the canary blocks on a FIFO gate immediately after spawn and is
#     moved into the governing cgroup *before* being released to
#     perform the one governed action — this is the "stop-before-
#     exec-then-release" no-spawn-then-restrict-race pattern;
#   - the BPF program is scoped to that one cgroup only
#     (`bpftool cgroup attach <path> device`), never a system-wide
#     attach point;
#   - a trap-based watchdog outside every governed cgroup guarantees
#     cleanup (process kill, cgroup removal, BPF detach/unpin) on any
#     exit path, including failure, and cleanup is idempotent;
#   - a hard timeout force-cleans regardless of outcome;
#   - the synthetic device node this script creates duplicates
#     /dev/null's major/minor (1,3) at a private path — opening it
#     behaves exactly like /dev/null; no real device, driver, or
#     hardware is touched, so a wrong assertion anywhere in this script
#     has zero collateral-damage surface.
#
# KNOWN GAP (disclosed, not hidden): already-open-handle/revoke
# behavior — does a device access already open before a policy swap
# survive a subsequent deny attach, or get cut off? — is NOT tested by
# this script. Per privileged-enforcement-testing.md's "Already-open-
# handle / revoke testing" section, that needs a dedicated sacrificial
# helper that holds an open file descriptor across the policy swap and
# reports whether it was cut off; this script's canaries perform one
# open-attempt-then-exit each, which cannot answer that question. This
# is the next increment (see TODO near the bottom).
#
# NOT YET EXECUTED ON REAL HARDWARE: this script was authored and
# reviewed on macOS, where none of its mechanisms (cgroup v2, eBPF,
# mknod-of-a-device-node) exist to test against. It is shellcheck-clean
# and logically reviewed, but has not been run end-to-end on a real
# Linux host. Treat its first real run as validating the script itself,
# not only the kernel behavior it investigates — read its findings
# carefully rather than assuming PASS.
#
# Usage: sudo bash scripts/e3-preflight-device-bpf-probe.sh [--json]
#
# Requires: Linux, cgroup v2 unified hierarchy, bpftool, clang (BPF
# target support), root (or CAP_SYS_ADMIN + CAP_BPF/CAP_PERFMON — see
# docs/development/hardware-validation-runbook.md §5). Exits non-zero
# and makes no changes if any precondition is unmet.

set -uo pipefail

JSON=0
if [[ "${1:-}" == "--json" ]]; then
  JSON=1
fi

RUN_ID="eltanin-e3-preflight-$(date -u +%Y%m%dT%H%M%SZ)-$$"
WORK_DIR=""
RESULT_STATUS="NOT_STARTED"
declare -a FINDINGS=()
declare -a ACTIVE_CGROUPS=()   # cgroups created this run, for cleanup
declare -a ACTIVE_PIDS=()      # canary PIDs spawned this run, for cleanup
declare -a ACTIVE_BPF_PINS=()  # pinned BPF program paths, for cleanup

finding() {
  # finding <PASS|FAIL|INFO> <name> <detail>
  FINDINGS+=("$1|$2|$3")
}

print_results() {
  if [[ "$JSON" -eq 1 ]]; then
    printf '{"evidence_class":"E3_PREFLIGHT_ONLY","run_id":"%s","result":"%s","findings":[' "$RUN_ID" "$RESULT_STATUS"
    local first=1
    for f in "${FINDINGS[@]}"; do
      IFS='|' read -r status name detail <<<"$f"
      [[ $first -eq 0 ]] && printf ','
      first=0
      esc="${detail//\"/\\\"}"
      printf '{"status":"%s","name":"%s","detail":"%s"}' "$status" "$name" "$esc"
    done
    printf ']}\n'
  else
    echo "=================================================================="
    echo "E3 Stage-1 preflight probe — evidence_class=E3_PREFLIGHT_ONLY"
    echo "run_id=$RUN_ID  result=$RESULT_STATUS"
    echo "=================================================================="
    for f in "${FINDINGS[@]}"; do
      IFS='|' read -r status name detail <<<"$f"
      printf '%-5s %-32s %s\n' "$status" "$name" "$detail"
    done
    echo "=================================================================="
    echo "This result is E3_PREFLIGHT_ONLY. It never becomes E3_PASS on its"
    echo "own merit, regardless of outcome — see"
    echo "docs/development/hardware-validation-runbook.md's two-stage"
    echo "strategy section for what still requires real bare-metal NVIDIA"
    echo "hardware (HORO-790's final gate)."
  fi
}

# --- Watchdog / cleanup (must run on every exit path, idempotent) -------
#
# Lives in this script's own trap, i.e. outside every governed cgroup at
# all times (a governed cgroup only ever contains one canary's PID,
# never this script's own PID) — satisfies "the watchdog must live
# outside the governed scope."

cleanup() {
  local exit_code=$?
  set +e

  for pid in "${ACTIVE_PIDS[@]:-}"; do
    [[ -z "$pid" ]] && continue
    kill -TERM "$pid" 2>/dev/null
  done
  sleep 0.2
  for pid in "${ACTIVE_PIDS[@]:-}"; do
    [[ -z "$pid" ]] && continue
    kill -KILL "$pid" 2>/dev/null
  done

  for pin in "${ACTIVE_BPF_PINS[@]:-}"; do
    [[ -z "$pin" ]] && continue
    for cg in "${ACTIVE_CGROUPS[@]:-}"; do
      [[ -z "$cg" || ! -d "$cg" ]] && continue
      bpftool cgroup detach "$cg" device pinned "$pin" 2>/dev/null || true
    done
    rm -f "$pin" 2>/dev/null || true
  done

  for cg in "${ACTIVE_CGROUPS[@]:-}"; do
    [[ -z "$cg" || ! -d "$cg" ]] && continue
    if [[ -s "$cg/cgroup.procs" ]]; then
      finding INFO "cleanup.cgroup_not_empty" "$cg still has member PIDs at cleanup — recorded, not silently ignored"
    fi
    rmdir "$cg" 2>/dev/null || true
  done

  rm -rf "/sys/fs/bpf/$RUN_ID" 2>/dev/null || true
  [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]] && rm -rf "$WORK_DIR"

  print_results
  exit "$exit_code"
}

trap cleanup EXIT INT TERM
# Hard timeout: force-clean regardless of outcome (checklist item 7).
( sleep 120; kill -ALRM $$ 2>/dev/null ) & disown
trap 'echo "TIMEOUT after 120s — forcing cleanup" >&2; RESULT_STATUS="ABORTED_TIMEOUT"; exit 124' ALRM

# --- Preconditions (abort, do not degrade, on any failure) --------------

abort() {
  finding FAIL "precondition.$1" "$2"
  RESULT_STATUS="ABORTED_PRECONDITION"
  exit 1
}

[[ "$(uname -s)" == "Linux" ]] || abort "os" "requires Linux, found $(uname -s) — this probe cannot run on this host at all"
[[ "$(id -u)" -eq 0 ]] || abort "privilege" "requires root (or CAP_SYS_ADMIN + CAP_BPF/CAP_PERFMON) to load/attach a cgroup-scoped BPF program; re-run with sudo"
[[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" == "cgroup2fs" ]] || abort "cgroup_v2" "cgroup v2 unified hierarchy not mounted at /sys/fs/cgroup — see hardware-preflight-check.sh"
command -v bpftool >/dev/null 2>&1 || abort "bpftool" "bpftool not found on PATH — install linux-tools-common/linux-tools-\$(uname -r) (Debian/Ubuntu) or bpftool (Fedora)"
command -v clang >/dev/null 2>&1 || abort "clang" "clang not found on PATH — needed to compile the tiny BPF_CGROUP_DEVICE probe program (clang -target bpf)"

finding INFO "precondition.identity" "uid=$(id -u) host=$(hostname) kernel=$(uname -r)"

WORK_DIR="$(mktemp -d "/tmp/${RUN_ID}.XXXXXX")" || abort "workdir" "mktemp -d failed"

# --- Synthetic device node — clones /dev/null's (1,3) major/minor at a
# private path. This is NOT a new driver and NOT a real accelerator
# device; opening it behaves exactly like /dev/null. Chosen specifically
# so a wrong assertion anywhere in this script has zero collateral-
# damage surface.

PROBE_DEV="$WORK_DIR/probe-null"
mknod "$PROBE_DEV" c 1 3 || abort "mknod" "failed to create synthetic device node at $PROBE_DEV"
chmod 666 "$PROBE_DEV"
finding PASS "device.synthetic_node_created" "$PROBE_DEV (char 1:3, clones /dev/null — no real hardware)"

# --- BPF program sources -------------------------------------------------
#
# Verdict contract (linux/bpf.h's bpf_cgroup_dev_ctx): return 0 to
# deny, non-zero to allow. HORO-842's real implementation is what makes
# the allow-set data-driven from authorized resource state; these two
# probe programs are deliberately the minimal fixed-verdict case needed
# to prove the deny-before-open / allow-after-authorization transition.

cat >"$WORK_DIR/deny.bpf.c" <<'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("cgroup/dev")
int probe_deny(struct bpf_cgroup_dev_ctx *ctx) {
    return 0; /* deny every access */
}

char _license[] SEC("license") = "GPL";
EOF

cat >"$WORK_DIR/allow.bpf.c" <<'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("cgroup/dev")
int probe_allow(struct bpf_cgroup_dev_ctx *ctx) {
    return 1; /* allow every access -- scope is this one disposable
                 cgroup only, never a system-wide attach */
}

char _license[] SEC("license") = "GPL";
EOF

build() {
  # build <name> — compiles $WORK_DIR/<name>.bpf.c, returns 0/1
  local name="$1"
  clang -O2 -target bpf -c "$WORK_DIR/$name.bpf.c" -o "$WORK_DIR/$name.o" \
    2>"$WORK_DIR/$name.clang.log" \
    || { finding FAIL "bpf.$name.compile" "clang failed — see $WORK_DIR/$name.clang.log"; return 1; }
  finding PASS "bpf.$name.compiled" "$WORK_DIR/$name.o"
  return 0
}

# --- run_phase: spawn a fresh canary in its own fresh cgroup, gate it on
# a FIFO, attach the given BPF program, release the canary to perform
# exactly one open() attempt, wait for it to exit, and read its verdict
# from a result file. Fully self-contained per phase — no shared
# coprocess state between phases, which is what keeps this correct and
# reviewable instead of racy.

run_phase() {
  # run_phase <phase-name> <bpf-object> <program-name> <expect: OPEN_OK|OPEN_DENIED>
  local phase="$1" obj="$2" prog="$3" expect="$4"
  local cg="/sys/fs/cgroup/${RUN_ID}-${phase}"
  local pin_dir="/sys/fs/bpf/${RUN_ID}-${phase}"
  local fifo="$WORK_DIR/${phase}.fifo"
  local result_file="$WORK_DIR/${phase}.result"
  local canary_pid=""

  mkdir "$cg" || { finding FAIL "$phase.cgroup_create" "failed to create $cg"; return 1; }
  ACTIVE_CGROUPS+=("$cg")
  if [[ -s "$cg/cgroup.procs" ]]; then
    finding FAIL "$phase.cgroup_not_empty" "freshly created $cg is non-empty immediately after creation"
    return 1
  fi

  local self_cgroup
  self_cgroup="$(awk -F: '{print $3}' /proc/self/cgroup)"
  if [[ "$self_cgroup" == "/${RUN_ID}-${phase}" ]]; then
    finding FAIL "$phase.orchestrator_in_target_cgroup" "this script's own process is inside the target cgroup — refusing"
    return 1
  fi

  mkfifo "$fifo" || { finding FAIL "$phase.mkfifo" "failed to create $fifo"; return 1; }

  # Canary: blocks on the FIFO (does nothing else), then performs
  # exactly one open() attempt via `dd` (a real external program, so
  # the syscall is unambiguous — not a shell builtin), writes a single
  # verdict word to result_file, and exits.
  (
    read -r _ <"$fifo"
    if dd if="$PROBE_DEV" of=/dev/null bs=1 count=0 >/dev/null 2>&1; then
      echo "OPEN_OK" >"$result_file"
    else
      echo "OPEN_DENIED" >"$result_file"
    fi
  ) &
  canary_pid=$!
  ACTIVE_PIDS+=("$canary_pid")

  # Move the canary into its cgroup BEFORE releasing the FIFO gate — it
  # has done nothing but block on a read so far, so there is no window
  # where the governed action (the open() attempt) happens ungoverned.
  echo "$canary_pid" >"$cg/cgroup.procs" || { finding FAIL "$phase.cgroup_attach" "failed to move canary $canary_pid into $cg/cgroup.procs"; return 1; }
  if [[ "$(cat "$cg/cgroup.procs")" != "$canary_pid" ]]; then
    finding FAIL "$phase.cgroup_membership" "cgroup.procs does not contain exactly canary pid $canary_pid after attach"
    return 1
  fi

  if ! build "$obj"; then
    return 1
  fi
  mkdir -p "$pin_dir" || { finding FAIL "$phase.bpf_pin_dir" "failed to create $pin_dir"; return 1; }
  bpftool prog loadall "$WORK_DIR/$obj.o" "$pin_dir" type cgroup_device \
    2>"$WORK_DIR/$phase.load.log" \
    || { finding FAIL "$phase.bpf_load" "bpftool prog load failed — see $WORK_DIR/$phase.load.log"; return 1; }
  local pinned_path="$pin_dir/$prog"
  ACTIVE_BPF_PINS+=("$pinned_path")

  bpftool cgroup attach "$cg" device pinned "$pinned_path" \
    2>"$WORK_DIR/$phase.attach.log" \
    || { finding FAIL "$phase.bpf_attach" "bpftool cgroup attach failed — see $WORK_DIR/$phase.attach.log"; return 1; }
  finding PASS "$phase.attached" "BPF_CGROUP_DEVICE program '$prog' attached to $cg"

  # Release the canary now that enforcement is attached, then wait for
  # its single open() attempt to complete.
  echo go >"$fifo"
  wait "$canary_pid" 2>/dev/null

  local actual="MISSING_RESULT"
  [[ -f "$result_file" ]] && actual="$(cat "$result_file")"

  if [[ "$actual" == "$expect" ]]; then
    finding PASS "$phase.verdict" "expected=$expect actual=$actual"
  else
    finding FAIL "$phase.verdict" "expected=$expect actual=$actual"
  fi

  bpftool cgroup detach "$cg" device pinned "$pinned_path" 2>/dev/null || true
  rmdir "$cg" 2>/dev/null || true
  return 0
}

# --- Phase A: deny-by-default — assert deny-before-open -----------------

run_phase "deny" "deny" "probe_deny" "OPEN_DENIED"

# --- Phase B: allow — assert access succeeds once authorized ------------

run_phase "allow" "allow" "probe_allow" "OPEN_OK"

# --- Already-open-handle/revoke behavior: TODO, not this script ---------

finding INFO "already_open_handle.not_tested" "See 'KNOWN GAP' header comment — needs a dedicated sacrificial helper holding an open FD across a policy swap, per privileged-enforcement-testing.md; not implemented in this probe. Do not treat Phase A/B PASS as covering this."

if [[ "${RESULT_STATUS}" == "NOT_STARTED" ]]; then
  RESULT_STATUS="RAN_TO_COMPLETION_SEE_FINDINGS"
fi
exit 0
