#!/usr/bin/env bash
# E3 Stage-2 one-shot bare-metal runner (HORO-790 / F-M1-002 / F-M1-007).
#
# GOAL: once provisioned on a candidate host, the paid/physical window
# should reduce to one command: provision -> bootstrap (already done by
# the time this runs) -> `bash scripts/e3-bare-metal-oneshot.sh` -> read
# the evidence bundle it prints -> cleanup -> terminate. This script is
# that one command's orchestration; it does not replace the manual
# driver/toolchain setup in docs/development/hardware-validation-runbook.md
# §6 (deliberately not automated there — see that section's own
# rationale: package names and driver-branch numbers drift, an
# unattended installer is more likely to silently do the wrong thing on
# a host nobody has seen before than five reviewed copy-paste commands).
# Run this AFTER §6's setup steps have completed and
# hardware-preflight-check.sh reports FAIL=0.
#
# WHAT THIS SCRIPT WILL AND WILL NOT PROVE TODAY
#
# `crates/eltanin-nvidia` and `ebpf/eltanin-device-guard` do not exist
# in this workspace yet (HORO-828/829/841/842/843/844 are all To Do —
# see the root Cargo.toml's own comment). This script therefore runs
# everything that DOES exist and is meaningful on real bare metal today
# (workspace baseline build/test, the generic Stage-1 device-BPF
# functional probe from HORO-841's prep work — which is equally valid
# evidence on real bare metal, not just a VM), and explicitly SKIPS —
# never fakes — the NVIDIA-specific and device-guard hardware-gated
# suites until those crates exist, detected via `cargo metadata`. A run
# with any SKIPPED step is NOT a HORO-790 E3_PASS run; it is progress
# evidence only. The final summary says so explicitly and refuses to
# print an E3_PASS verdict unless every suite HORO-790's AC lists
# actually ran and passed.
#
# BLAST-RADIUS COMPLIANCE: this script's own device-BPF step is exactly
# scripts/e3-preflight-device-bpf-probe.sh, unchanged — see that
# script's header for the full compliance mapping. Any future addition
# here that attaches real cgroup/eBPF/device-node enforcement must
# satisfy docs/qa/privileged-enforcement-testing.md first, the same as
# every other privileged test in this repository.
#
# NOT YET EXECUTED ON REAL HARDWARE — see the same disclosure on
# scripts/e3-preflight-device-bpf-probe.sh. This script's own
# orchestration logic (evidence bundling, skip-detection, exit-code
# aggregation) has only been reviewed, not run end-to-end on Linux.
#
# Usage: bash scripts/e3-bare-metal-oneshot.sh [--json] [--allow-preflight-only]
#
#   --allow-preflight-only   proceed even if hardware-preflight-check.sh
#                            reports evidence_class=E3_PREFLIGHT_ONLY
#                            (i.e. this host is virtualized). Without
#                            this flag, the script refuses to run its
#                            "certification" suites on a non-bare-metal
#                            host at all, to make it structurally hard
#                            to accidentally produce evidence that looks
#                            like E3_PASS from a VM. Preflight iteration
#                            on a VM should call
#                            e3-preflight-device-bpf-probe.sh directly
#                            instead of this script.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

JSON=0
ALLOW_PREFLIGHT_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --json) JSON=1 ;;
    --allow-preflight-only) ALLOW_PREFLIGHT_ONLY=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

START_TS="$(date -u +%FT%TZ)"
declare -a STEP_RESULTS=()  # "name|status|detail" where status is PASS|FAIL|SKIPPED
OVERALL_OK=1

step_result() {
  # step_result <name> <PASS|FAIL|SKIPPED> <detail>
  STEP_RESULTS+=("$1|$2|$3")
  [[ "$2" == "FAIL" ]] && OVERALL_OK=0
}

echo "=================================================================="
echo "E3 Stage-2 one-shot runner — starting $START_TS on $(hostname)"
echo "=================================================================="

# --- Step 0: preflight, and the E3_PASS_ELIGIBLE gate --------------------

PREFLIGHT_JSON="$(bash scripts/hardware-preflight-check.sh --json)"
PREFLIGHT_EXIT=$?
EVIDENCE_CLASS="$(echo "$PREFLIGHT_JSON" | grep -o '"evidence_class":"[^"]*"' | cut -d'"' -f4)"
echo "Preflight evidence_class: ${EVIDENCE_CLASS:-unknown}"

if [[ "$PREFLIGHT_EXIT" -ne 0 ]]; then
  step_result "preflight" "FAIL" "hardware-preflight-check.sh reported FAIL>0 — fix before running certification suites (see its own output above)"
  echo "$PREFLIGHT_JSON"
  echo "ABORTING before touching any Eltanin code or enforcement mechanism."
  exit 1
fi
step_result "preflight" "PASS" "evidence_class=$EVIDENCE_CLASS"

if [[ "$EVIDENCE_CLASS" != "E3_PASS_ELIGIBLE" && "$ALLOW_PREFLIGHT_ONLY" -ne 1 ]]; then
  echo "This host is not E3_PASS_ELIGIBLE (evidence_class=$EVIDENCE_CLASS)."
  echo "Refusing to run certification suites here — that would risk producing"
  echo "output that looks like final E3 evidence from a virtualized host,"
  echo "which HORO-790's AC explicitly disqualifies. Re-run with"
  echo "--allow-preflight-only if you specifically want Stage-1 iteration,"
  echo "or use scripts/e3-preflight-device-bpf-probe.sh directly."
  exit 1
fi

EVIDENCE_DIR_LINE="$(bash scripts/hardware-evidence-capture.sh 2>&1 | tee /dev/stderr | grep '^Writing evidence to:')"
EVIDENCE_DIR="${EVIDENCE_DIR_LINE#"Writing evidence to: "}"
if [[ -z "$EVIDENCE_DIR" || ! -d "$EVIDENCE_DIR" ]]; then
  step_result "evidence_dir" "FAIL" "could not determine evidence directory from hardware-evidence-capture.sh output"
  exit 1
fi
step_result "evidence_dir" "PASS" "$EVIDENCE_DIR"

# --- Step 1: hardware-free workspace baseline — must be green before ----
# anything hardware-specific is trustworthy.

if cargo build --workspace --all-targets >"$EVIDENCE_DIR/build.log" 2>&1 \
   && cargo test --workspace >"$EVIDENCE_DIR/test-workspace.log" 2>&1; then
  step_result "baseline.build_and_test" "PASS" "see build.log, test-workspace.log"
else
  step_result "baseline.build_and_test" "FAIL" "see build.log, test-workspace.log in $EVIDENCE_DIR"
fi

# --- Step 2: generic device-BPF functional probe — valid on real bare ---
# metal too, not only a VM (HORO-841 prep, evidence_class stays
# E3_PREFLIGHT_ONLY for this specific step regardless of host, since it
# never touches a real NVIDIA device node — see that script's own
# header for why this is still useful evidence to (re-)capture here).

if command -v bpftool >/dev/null 2>&1 && command -v clang >/dev/null 2>&1; then
  # shellcheck disable=SC2024 # redirect fds are opened by this (non-sudo)
  # shell and inherited by the sudo'd child, so this is not the
  # "sudo cmd > root-owned-file" permission trap SC2024 warns about.
  if sudo bash scripts/e3-preflight-device-bpf-probe.sh --json >"$EVIDENCE_DIR/device-bpf-probe.json" 2>"$EVIDENCE_DIR/device-bpf-probe.log"; then
    step_result "device_bpf_probe" "PASS" "see device-bpf-probe.json"
  else
    step_result "device_bpf_probe" "FAIL" "see device-bpf-probe.json, device-bpf-probe.log"
  fi
else
  step_result "device_bpf_probe" "SKIPPED" "bpftool/clang not installed on this host — install per hardware-validation-runbook.md §6 step 4"
fi

# --- Step 3: NVIDIA discovery hardware integration — only if the crate --
# exists yet (HORO-828/829, F-M1-002). Detect via cargo metadata; never
# fabricate a PASS for a crate that isn't in the workspace.

if cargo metadata --no-deps --format-version 1 2>/dev/null | grep -q '"name":"eltanin-nvidia"'; then
  if cargo test -p eltanin-nvidia --test hardware_integration -- --ignored --nocapture \
       >"$EVIDENCE_DIR/nvidia-hardware-integration.log" 2>&1; then
    step_result "nvidia.hardware_integration" "PASS" "see nvidia-hardware-integration.log"
  else
    step_result "nvidia.hardware_integration" "FAIL" "see nvidia-hardware-integration.log"
  fi
else
  step_result "nvidia.hardware_integration" "SKIPPED" "crates/eltanin-nvidia does not exist in this workspace yet (HORO-828/829 To Do)"
fi

# --- Step 4: device-guard hardware integration — only if that crate -----
# exists yet (HORO-841/842/843, F-M1-007).

if cargo metadata --no-deps --format-version 1 2>/dev/null | grep -q '"name":"eltanin-device-guard"'; then
  if cargo test -p eltanin-device-guard --test hardware_integration -- --ignored --nocapture \
       >"$EVIDENCE_DIR/device-guard-hardware-integration.log" 2>&1; then
    step_result "device_guard.hardware_integration" "PASS" "see device-guard-hardware-integration.log"
  else
    step_result "device_guard.hardware_integration" "FAIL" "see device-guard-hardware-integration.log"
  fi
else
  step_result "device_guard.hardware_integration" "SKIPPED" "ebpf/eltanin-device-guard does not exist in this workspace yet (HORO-841/842/843 To Do)"
fi

# --- Step 5: HORO-790 end-to-end canonical scenario — only once it -----
# exists (the proposed canonical_e2e_hardware.rs twin, runbook §7d).

if [[ -f "crates/eltanin-cli/tests/canonical_e2e_hardware.rs" ]]; then
  if cargo test -p eltanin-cli --test canonical_e2e_hardware -- --ignored --nocapture \
       >"$EVIDENCE_DIR/canonical-e2e-hardware.log" 2>&1; then
    step_result "canonical_e2e_hardware" "PASS" "see canonical-e2e-hardware.log"
  else
    step_result "canonical_e2e_hardware" "FAIL" "see canonical-e2e-hardware.log"
  fi
else
  step_result "canonical_e2e_hardware" "SKIPPED" "crates/eltanin-cli/tests/canonical_e2e_hardware.rs does not exist yet"
fi

# --- Summary --------------------------------------------------------------

ANY_SKIPPED=0
for r in "${STEP_RESULTS[@]}"; do
  IFS='|' read -r _ status _ <<<"$r"
  [[ "$status" == "SKIPPED" ]] && ANY_SKIPPED=1
done

if [[ "$OVERALL_OK" -eq 1 && "$ANY_SKIPPED" -eq 0 && "$EVIDENCE_CLASS" == "E3_PASS_ELIGIBLE" ]]; then
  VERDICT="E3_PASS_CANDIDATE"
elif [[ "$OVERALL_OK" -eq 1 ]]; then
  VERDICT="PARTIAL_EVIDENCE_ONLY"
else
  VERDICT="FAIL"
fi

{
  echo "run_started=$START_TS"
  echo "evidence_class=$EVIDENCE_CLASS"
  echo "verdict=$VERDICT"
  echo
  for r in "${STEP_RESULTS[@]}"; do
    IFS='|' read -r name status detail <<<"$r"
    printf '%-32s %-8s %s\n' "$name" "$status" "$detail"
  done
} | tee "$EVIDENCE_DIR/oneshot-summary.txt"

if [[ "$JSON" -eq 1 ]]; then
  printf '{"verdict":"%s","evidence_class":"%s","evidence_dir":"%s","steps":[' "$VERDICT" "$EVIDENCE_CLASS" "$EVIDENCE_DIR"
  first=1
  for r in "${STEP_RESULTS[@]}"; do
    IFS='|' read -r name status detail <<<"$r"
    [[ $first -eq 0 ]] && printf ','
    first=0
    esc="${detail//\"/\\\"}"
    printf '{"name":"%s","status":"%s","detail":"%s"}' "$name" "$status" "$esc"
  done
  printf ']}\n' | tee "$EVIDENCE_DIR/oneshot-summary.json"
fi

echo
echo "Evidence bundle: $EVIDENCE_DIR"
echo "VERDICT=$VERDICT"
if [[ "$VERDICT" != "E3_PASS_CANDIDATE" ]]; then
  echo "This run is NOT a HORO-790 E3_PASS verdict. Any SKIPPED step means"
  echo "the corresponding Jira ticket(s) have not landed yet; a FAIL step"
  echo "means real evidence contradicted an assumption — fix the underlying"
  echo "issue (do not weaken the AC) and re-run. Promote a genuine"
  echo "E3_PASS_CANDIDATE run into docs/qa/reports/ (see TEMPLATE.md) only"
  echo "after independent review, per HORO-790's own Acceptance Criteria."
fi

[[ "$OVERALL_OK" -eq 1 ]] && exit 0 || exit 1
