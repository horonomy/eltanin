#!/usr/bin/env bash
# Hardware validation evidence capture (HORO-790 / F-M1-002 / F-M1-007).
#
# Collects the environment/config facts HORO-790's "Evidence to Capture"
# list names, into one timestamped directory. Read-mostly: the only
# writes are the new evidence directory and the files inside it. Does
# not run any Eltanin test itself — run those separately (see
# docs/development/hardware-validation-runbook.md §7) and copy/redirect
# their output into the same directory so one directory holds the whole
# evidence bundle for one validation run.
#
# Usage: bash scripts/hardware-evidence-capture.sh [output-dir]
#   output-dir defaults to evidence/<UTC timestamp>-<hostname>/

set -uo pipefail

OUT_DIR="${1:-evidence/$(date -u +%Y%m%dT%H%M%SZ)-$(hostname -s 2>/dev/null || hostname)}"
mkdir -p "$OUT_DIR"
echo "Writing evidence to: $OUT_DIR"

capture() {
  # capture <filename> <command...>
  local file="$1"; shift
  {
    echo "\$ $*"
    echo "--- captured $(date -u +%FT%TZ) ---"
    "$@" 2>&1
  } >"$OUT_DIR/$file" || echo "  (command failed or unavailable — see $OUT_DIR/$file)"
}

capture "os-release.txt" cat /etc/os-release
capture "uname.txt" uname -a
capture "kernel-cmdline.txt" cat /proc/cmdline
capture "cgroup-mount.txt" mount | grep -i cgroup
capture "cgroup-fstype.txt" stat -fc '%T %n' /sys/fs/cgroup/
capture "bpftool-feature-probe.txt" bpftool feature probe
capture "lspci-nvidia.txt" bash -c "lspci -nn | grep -i nvidia"
capture "nvidia-smi-query.txt" nvidia-smi --query-gpu=name,driver_version,pci.bus_id,uuid,memory.total,compute_cap --format=csv
capture "nvidia-smi-full.txt" nvidia-smi
capture "nvidia-device-nodes.txt" bash -c "ls -la /dev/nvidia*"
capture "cpuinfo.txt" cat /proc/cpuinfo
capture "meminfo.txt" cat /proc/meminfo
capture "id.txt" id
capture "rustc-version.txt" rustc --version
capture "cargo-version.txt" cargo --version

# Kernel config, if readable — same sources the preflight check tries.
if [[ -r "/boot/config-$(uname -r)" ]]; then
  capture "kernel-config-relevant.txt" bash -c "grep -E 'CONFIG_CGROUP_BPF|CONFIG_BPF_SYSCALL' /boot/config-$(uname -r)"
elif [[ -r /proc/config.gz ]]; then
  capture "kernel-config-relevant.txt" bash -c "zcat /proc/config.gz | grep -E 'CONFIG_CGROUP_BPF|CONFIG_BPF_SYSCALL'"
fi

echo
echo "Evidence directory populated: $OUT_DIR"
echo "Next: copy/redirect each hardware-gated test run's own stdout/stderr"
echo "(e.g. 'cargo test ... -- --ignored --nocapture > $OUT_DIR/<test-name>.log 2>&1')"
echo "into this same directory so it holds the complete bundle for one run,"
echo "then reference it from a docs/qa/reports/ Release Quality Report"
echo "(see docs/qa/reports/TEMPLATE.md)."
