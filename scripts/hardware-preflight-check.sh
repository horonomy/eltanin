#!/usr/bin/env bash
# Hardware validation pre-flight check (HORO-790 / F-M1-002 / F-M1-007).
#
# Read-only. Installs nothing, modifies nothing, needs no sudo for the
# checks themselves (a few commands report more detail when run as root
# — the script notes that inline rather than re-execing itself as root).
# Safe to run repeatedly on any candidate Linux host to see whether it
# qualifies before spending any setup effort on it.
#
# Usage: bash scripts/hardware-preflight-check.sh [--json]
#
# See docs/development/hardware-validation-runbook.md for what each
# check means and what to do about a FAIL.

set -uo pipefail

JSON=0
if [[ "${1:-}" == "--json" ]]; then
  JSON=1
fi

PASS=0
FAIL=0
WARN=0
declare -a RESULTS=()

record() {
  # record <status: PASS|FAIL|WARN> <check name> <detail>
  local status="$1" name="$2" detail="$3"
  RESULTS+=("${status}|${name}|${detail}")
  case "$status" in
    PASS) PASS=$((PASS + 1)) ;;
    FAIL) FAIL=$((FAIL + 1)) ;;
    WARN) WARN=$((WARN + 1)) ;;
  esac
}

# --- 1. Operating system / kernel -------------------------------------

if [[ "$(uname -s)" != "Linux" ]]; then
  record FAIL "os.kernel" "$(uname -s) — this runbook requires Linux (bare-metal), not $(uname -s)"
else
  KVER="$(uname -r)"
  KMAJOR="$(echo "$KVER" | cut -d. -f1)"
  KMINOR="$(echo "$KVER" | cut -d. -f2)"
  if [[ "$KMAJOR" -gt 4 || ("$KMAJOR" -eq 4 && "$KMINOR" -ge 15) ]]; then
    record PASS "os.kernel" "Linux $KVER (>= 4.15, has BPF_PROG_TYPE_CGROUP_DEVICE support in principle)"
  else
    record FAIL "os.kernel" "Linux $KVER (< 4.15 — no cgroup v2 device-BPF support at all; use a current LTS kernel)"
  fi
fi

# --- 2. cgroup v2 unified hierarchy ------------------------------------

CGROUP_FSTYPE="$(stat -fc %T /sys/fs/cgroup/ 2>/dev/null || echo unknown)"
if [[ "$CGROUP_FSTYPE" == "cgroup2fs" ]]; then
  record PASS "cgroup.unified" "cgroup v2 unified hierarchy mounted at /sys/fs/cgroup"
elif [[ -d /sys/fs/cgroup/unified ]]; then
  record WARN "cgroup.unified" "cgroup v2 present only as a 'hybrid' mount at /sys/fs/cgroup/unified — device-BPF still works there, but prefer a distro with unified-by-default (systemd >= 247) to match production"
else
  record FAIL "cgroup.unified" "no cgroup v2 (unified or hybrid) filesystem found — legacy cgroup v1-only host, device-BPF is not usable"
fi

# --- 3. Kernel config: CGROUP_BPF / BPF_SYSCALL ------------------------

KCONFIG=""
if [[ -r "/boot/config-$(uname -r)" ]]; then
  KCONFIG="/boot/config-$(uname -r)"
elif [[ -r /proc/config.gz ]]; then
  KCONFIG="/proc/config.gz"
fi

if [[ -n "$KCONFIG" ]]; then
  if [[ "$KCONFIG" == *.gz ]]; then
    CFG_CONTENT="$(zcat "$KCONFIG" 2>/dev/null)"
  else
    CFG_CONTENT="$(cat "$KCONFIG" 2>/dev/null)"
  fi
  if echo "$CFG_CONTENT" | grep -q '^CONFIG_CGROUP_BPF=y' \
     && echo "$CFG_CONTENT" | grep -q '^CONFIG_BPF_SYSCALL=y'; then
    record PASS "kernel.config" "CONFIG_CGROUP_BPF=y and CONFIG_BPF_SYSCALL=y both set"
  else
    record FAIL "kernel.config" "CONFIG_CGROUP_BPF or CONFIG_BPF_SYSCALL missing/not 'y' in $KCONFIG"
  fi
else
  record WARN "kernel.config" "could not read a kernel config file (/boot/config-\$(uname -r) or /proc/config.gz) — most current distro kernels ship both enabled, but this could not be confirmed automatically; verify manually or trust bpftool's probe below"
fi

# --- 4. bpftool feature probe (best confirmation available) -----------

if command -v bpftool >/dev/null 2>&1; then
  PROBE_OUT="$(bpftool feature probe 2>/dev/null || true)"
  if echo "$PROBE_OUT" | grep -qi "cgroup_device"; then
    record PASS "bpftool.cgroup_device" "bpftool reports cgroup_device program type support"
  else
    record WARN "bpftool.cgroup_device" "bpftool ran but did not clearly report cgroup_device support in its output — inspect 'bpftool feature probe' manually (some bpftool builds format this differently across versions)"
  fi
else
  record WARN "bpftool.missing" "bpftool not installed — install linux-tools-common/linux-tools-\$(uname -r) (Debian/Ubuntu) or bpftool (Fedora) for a direct probe; kernel.config above is the fallback signal"
fi

# --- 5. NVIDIA driver / nvidia-smi -------------------------------------

if command -v nvidia-smi >/dev/null 2>&1; then
  SMI_OUT="$(nvidia-smi --query-gpu=name,driver_version,pci.bus_id,uuid --format=csv,noheader 2>/dev/null || true)"
  if [[ -n "$SMI_OUT" ]]; then
    record PASS "nvidia.driver" "nvidia-smi reports: ${SMI_OUT}"
  else
    record FAIL "nvidia.driver" "nvidia-smi is installed but returned no GPU — driver loaded but no device visible (check 'lspci -nn | grep -i nvidia' and dmesg for driver load errors)"
  fi
else
  record FAIL "nvidia.driver" "nvidia-smi not found — proprietary NVIDIA driver not installed (nouveau does not count; NVML requires the proprietary driver)"
fi

# --- 6. NVIDIA device nodes ---------------------------------------------

NVIDIA_NODES="$(ls /dev/nvidia* 2>/dev/null || true)"
if [[ -n "$NVIDIA_NODES" ]]; then
  record PASS "nvidia.device_nodes" "$(echo "$NVIDIA_NODES" | tr '\n' ' ')"
else
  record FAIL "nvidia.device_nodes" "no /dev/nvidia* device nodes present"
fi

# --- 7. Root / capabilities (informational — exact minimal set is what
#        HORO-841's spike itself determines; this just reports today's
#        identity so results are reproducible) -------------------------

if [[ "$(id -u)" -eq 0 ]]; then
  record PASS "privilege.identity" "running as root (uid 0) — sufficient for the validation spike; capability minimization is a later hardening pass (HORO-842/843), not this check's job"
else
  record WARN "privilege.identity" "running as uid $(id -u), not root — cgroup/BPF attach and possibly /dev/nvidia* access will need sudo/root for the validation spike; re-run relevant steps with sudo"
fi

# --- 8. Rust toolchain ---------------------------------------------------

if command -v cargo >/dev/null 2>&1; then
  record PASS "rust.cargo" "$(cargo --version)"
else
  record WARN "rust.cargo" "cargo not found on PATH — install via https://rustup.rs before building the workspace"
fi

# --- 9. Virtualization detection (E3_PASS vs. E3_PREFLIGHT_ONLY gate) ---
#
# HORO-790's AC is explicit: VM-only, container-only, or GPU-passthrough
# -only evidence does not satisfy the final E3 bare-metal gate. This
# check is what makes that a mechanically-checked fact about the host
# running this script, not something a human has to remember to assert.
# See docs/development/hardware-validation-runbook.md's two-stage
# strategy section for what EVIDENCE_CLASS means downstream.

VIRT_TYPE="unknown"
if command -v systemd-detect-virt >/dev/null 2>&1; then
  # systemd-detect-virt exits non-zero when it detects "none" (bare
  # metal) — capture output regardless of exit status.
  VIRT_TYPE="$(systemd-detect-virt 2>/dev/null || true)"
  [[ -z "$VIRT_TYPE" ]] && VIRT_TYPE="none"
  if [[ "$VIRT_TYPE" == "none" ]]; then
    record PASS "virt.detect" "systemd-detect-virt: none (bare metal) — eligible for E3_PASS evidence"
  else
    record WARN "virt.detect" "systemd-detect-virt: ${VIRT_TYPE} — this host is virtualized; any evidence captured here can only be labeled E3_PREFLIGHT_ONLY, never E3_PASS (HORO-790 AC excludes VM/container/passthrough-only evidence)"
  fi
else
  VIRT_TYPE="undetermined"
  record WARN "virt.detect" "systemd-detect-virt not installed — bare-metal status could not be mechanically confirmed; treat this host as E3_PREFLIGHT_ONLY until confirmed otherwise (check /sys/class/dmi/id/product_name and /proc/cpuinfo 'hypervisor' flag manually, or install systemd's detect-virt)"
fi

if [[ "$VIRT_TYPE" == "none" ]]; then
  EVIDENCE_CLASS="E3_PASS_ELIGIBLE"
else
  EVIDENCE_CLASS="E3_PREFLIGHT_ONLY"
fi

# --- Summary -------------------------------------------------------------

if [[ "$JSON" -eq 1 ]]; then
  printf '{"pass":%d,"warn":%d,"fail":%d,"evidence_class":"%s","virt_type":"%s","checks":[' \
    "$PASS" "$WARN" "$FAIL" "$EVIDENCE_CLASS" "$VIRT_TYPE"
  first=1
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r status name detail <<<"$r"
    [[ $first -eq 0 ]] && printf ','
    first=0
    esc_detail="${detail//\"/\\\"}"
    printf '{"status":"%s","name":"%s","detail":"%s"}' "$status" "$name" "$esc_detail"
  done
  printf ']}\n'
else
  echo "Hardware pre-flight check — $(date -u +%FT%TZ) on $(hostname)"
  echo "=================================================================="
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r status name detail <<<"$r"
    printf '%-5s %-28s %s\n' "$status" "$name" "$detail"
  done
  echo "=================================================================="
  echo "PASS=$PASS WARN=$WARN FAIL=$FAIL"
  echo "EVIDENCE_CLASS=$EVIDENCE_CLASS (virt_type=$VIRT_TYPE)"
  if [[ "$EVIDENCE_CLASS" != "E3_PASS_ELIGIBLE" ]]; then
    echo "This host cannot produce final E3_PASS evidence for HORO-790 —"
    echo "only E3_PREFLIGHT_ONLY. Use it for Stage-1 preflight/spike-harness"
    echo "iteration only; the final bare-metal certification run still"
    echo "requires a genuinely non-virtualized host (see runbook §1)."
  fi
  if [[ "$FAIL" -gt 0 ]]; then
    echo
    echo "This host does not yet satisfy the hardware-validation prerequisites."
    echo "See docs/development/hardware-validation-runbook.md for remediation per FAIL line."
    exit 1
  fi
fi
