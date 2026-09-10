# ADR 0001: Linux/NVIDIA-first scope, cgroup v2 device-BPF as the enforcement substrate

## Status

Accepted (MVP 1.0).

## Context

Eltanin needs a real, kernel-enforced boundary for protected compute
access on at least one platform to prove the North Star ("no protected
compute without authorization") is more than an API-level claim. The
options considered for the enforcement mechanism:

1. **cgroup v2 device-BPF** (`BPF_PROG_TYPE_CGROUP_DEVICE` /
   `BPF_CGROUP_DEVICE`) — kernel-level, denies device-file `open()`/access
   with `EPERM`, attached per-cgroup.
2. **CUDA API interception** (wrapping the CUDA driver/runtime API).
3. **`LD_PRELOAD`-based library interposition.**
4. **udev/device-node permission manipulation** (chmod/chown device nodes
   dynamically).

## Decision

Use **cgroup v2 device-BPF** as the enforcement substrate for MVP 1.0, on
**bare-metal Linux** with **NVIDIA** GPUs only.

Options 2 and 3 are explicitly rejected as the *primary* security
boundary: both operate in the same privilege domain as the workload being
constrained and can be bypassed by any workload that statically links,
calls the driver directly, or unloads/circumvents the interposed library.
They may be revisited later as defense-in-depth *signal collection*, but
never as the sole enforcement root — see
[`docs/product/PRODUCT_CONSTITUTION.md`](../product/PRODUCT_CONSTITUTION.md).

Option 4 (device-node permission manipulation) is not chosen as primary
because it is racy (a TOCTOU window between permission change and
workload open) and does not compose cleanly with per-workload (rather
than per-host) scoping the way a cgroup-scoped BPF program does.

Linux is chosen over Windows/macOS because cgroup v2 device-BPF is a
Linux-only kernel primitive with no equivalent security substrate on
those platforms with this MVP's timeline. NVIDIA is chosen because it
dominates the target compute workload (ML/AI GPU compute) and exposes a
documented device-node model (per-GPU nodes plus system-wide control/UVM
nodes) that this MVP's Feature discovery (F-M1-002) can map.

## Consequences

- F-M1-007 (Linux Protected-Device Enforcement) implements against this
  substrate, not CUDA hooks.
- HORO-841 (hard security gate) must validate the *exact* node/major/
  minor lifecycle, already-open-handle behavior, and cgroup
  movement/escape behavior on real hardware **before** F-M1-007's real
  implementation claims any enforcement guarantee — this ADR does not by
  itself prove the guarantee holds; it only fixes the mechanism to
  validate.
- AMD/Intel and Windows/macOS support are out of scope for MVP 1.0 by
  construction of this decision, not merely by product-scoping choice —
  a different enforcement substrate would need its own ADR for those
  platforms.
