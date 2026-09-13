# Hardware Validation Runbook — F-M1-002 / F-M1-007 / HORO-790

**Status: preparation only. No hardware has been provisioned. No
hardware evidence exists yet — nothing below is a report of results;
it is a plan for obtaining them.** This document exists so that once a
real bare-metal Linux/NVIDIA environment is available, the actual paid
or scheduled hardware time is spent executing, not figuring out what to
run.

Covers three Jira items that all depend on the same physical
environment:

- **F-M1-002 / HORO-785** — NVIDIA Protected Resource Discovery (real
  NVML backend).
- **F-M1-007 / HORO-789** — Linux Protected-Device Enforcement (real
  cgroup v2 device-BPF), including its mandatory first step
  **HORO-841** (the enforcement-boundary spike).
- **HORO-790** — MVP 1.0 READY: the end-to-end proof that ties both of
  the above together on the same physical host.

Do not weaken or reinterpret any Acceptance Criteria on HORO-785,
HORO-789, HORO-841, or HORO-790 to fit what this runbook finds
convenient. If real hardware evidence contradicts an assumption this
document makes, the document is wrong and gets corrected — the Jira AC
is not.

## Two-stage strategy: E3 Stage-1 preflight vs. Stage-2 bare-metal certification

Founder directive (2026-09-13): do not let HORO-790 sit indefinitely
blocked on scarce/paid bare-metal time. The E3 security standard itself
is unchanged — **final E3 still requires a physical bare-metal
Linux/NVIDIA host with a physically attached supported GPU; VM,
container, and GPU-passthrough evidence still cannot satisfy it** (see
§1's virtualization trap, unchanged). What changes is sequencing: split
hardware validation into two stages so the only work that actually
needs paid/scarce time is the part that mechanically *requires* real
bare-metal, and everything else — including a great deal of real
kernel-primitive investigation HORO-841 needs — is eliminated for free
first.

**Stage 1 — E3 PREFLIGHT.** Everything that remains semantically valid
under virtualization runs on the cheapest available Linux environment
(a GPU-free VM/container is sufficient for most of it; a
virtualized-GPU cloud instance only where NVIDIA discovery specifically
needs a GPU present). This eliminates ordinary software/tooling/
environment defects before any paid bare-metal clock starts. Every
artifact this stage produces — every script's `--json` output, every
`hardware-evidence-capture.sh` bundle's `evidence-class.json` — is
labeled `EVIDENCE_CLASS=E3_PREFLIGHT_ONLY`. **Never relabel or cite
Stage-1 output as `E3_PASS`.** Concretely, in this repository today:

- `bash scripts/hardware-preflight-check.sh [--json]` — now also runs
  `systemd-detect-virt` and stamps `evidence_class` /
  `virt_type` in its output: `E3_PASS_ELIGIBLE` only when the host is
  mechanically confirmed non-virtualized (`virt_type=none`),
  `E3_PREFLIGHT_ONLY` otherwise. This is a precondition check, not a
  certification — it tells you which class of evidence *this host* is
  even capable of producing, before you invest setup effort in it.
- `bash scripts/e3-preflight-device-bpf-probe.sh` (root required, Linux
  only) — a disposable, blast-radius-compliant (see
  `docs/qa/privileged-enforcement-testing.md`) functional probe of
  `BPF_PROG_TYPE_CGROUP_DEVICE`: deny-before-open and allow-after-
  authorization, against a synthetic device node that clones
  `/dev/null`'s major/minor (never a real device, never real hardware).
  This is possible without any GPU at all because cgroup v2 device-BPF
  semantics are a generic kernel primitive, not an NVIDIA-specific one
  — it directly answers several of HORO-841's "Required Investigation"
  bullets (deny-before-open behavior, attach/detach lifecycle, the
  root/capability set that actually worked on the target kernel) for
  the cost of a few minutes on any current-kernel Linux VM. It does
  **not** test already-open-handle/revoke behavior yet (disclosed as a
  known gap in the script's own header) and it never touches
  `/dev/nvidia*` or proves anything about a real GPU discovery/telemetry
  path — that half of HORO-841/HORO-785 still needs Stage 1b or Stage 2.
  Run it, read its findings, and file real bugs/ADR updates for
  anything it gets wrong before ever renting bare-metal time.
- **Stage 1b (not yet built, correctly out of scope for this pass)**:
  once `crates/eltanin-nvidia` exists (HORO-828/829, F-M1-002), its
  hardware-free unit tests run in normal CI as always, and its real
  NVML/discovery integration test can be preflighted on a cheap
  virtualized-GPU cloud instance (NVML/`nvidia-smi` work fine under GPU
  passthrough — only the *enforcement* claim requires bare metal, not
  discovery/telemetry). That preflight run is still `E3_PREFLIGHT_ONLY`
  for the same virtualization reason.
- `bash scripts/hardware-evidence-capture.sh [output-dir]` — every
  bundle it writes now includes an `evidence-class.json` stamp (virt
  type + resulting evidence class) alongside the existing environment
  captures, so a Stage-1 bundle can never later be mistaken for Stage-2
  certification evidence just because it lives in the same
  `evidence/` directory structure.

**Stage 2 — E3 BARE-METAL CERTIFICATION.** Only what Stage 1 cannot
prove: real physical device-node enforcement, authorized minimal device
access, unauthorized denial before meaningful compute, cleanup/revoke/
open-handle semantics, and exact physical GPU/kernel/driver/NVML
evidence — run on a genuinely non-virtualized host per §1 below,
confirmed by `hardware-preflight-check.sh` reporting
`E3_PASS_ELIGIBLE` (i.e. `systemd-detect-virt: none`) before any setup
effort is spent. §6–§12 below are already written as this stage's
one-shot runbook (setup → build → run → evidence → cleanup); the target
is that once HORO-828/829/841/842/843/844 land (informed and de-risked
by Stage-1 findings), the paid/physical window is spent executing that
existing sequence, not inventing it live. See "F. Exact eventual
bare-metal one-shot command" below for the single command this window
should reduce to once those tickets land.

### Provider strategy (cheapest technically valid option first)

In order — do not skip to a paid option before ruling out the free
ones:

1. **A founder-owned or borrowed physical NVIDIA workstation.**
   Unambiguously bare-metal by construction (§1's own recommendation),
   zero incremental cost, no billed-clock pressure on HORO-841's
   open-ended spike work. This is the recommended path if one exists —
   see the open question below.
2. **An inexpensive temporary/used supported NVIDIA GPU added to an
   existing Linux-capable PC.** Per §2, a Pascal-generation (2016)
   GTX 10-series card or newer consumer card is sufficient — there is
   no compute-capability requirement, only "on a currently-supported
   production driver branch." Secondhand Pascal/Turing consumer cards
   are commodity-cheap; this converts a one-time hardware purchase into
   a permanent, zero-marginal-cost bare-metal validation host, avoiding
   recurring rental cost for HORO-844's later adversarial/regression
   suite too.
3. **An hourly dedicated bare-metal Linux/NVIDIA provider** — a genuine
   dedicated/colo physical server product, never a "GPU cloud instance"
   SKU (§1's virtualization trap applies in full). Priced per provider
   at execution time; this runbook does not fabricate a number here
   (see "D. Expected paid duration/cost" below for why).
4. **An ordinary GPU VM/Pod, for Stage-1 preflight only, never for
   Stage-2/final E3 certification.** Useful only for Stage 1b's
   NVML/discovery preflight (item above) where a GPU specifically needs
   to be present; never cite its output as `E3_PASS`.

**Open question for the founder** (this runbook cannot answer it from
source alone — see the "B" item below): does a Linux-capable PC exist
today with a Pascal-generation-or-newer NVIDIA card already installed,
or available to install one into? If yes, option 1/2 above likely make
this ticket's hardware blocker free to resolve. If no, which of options
2/3 should be priced and actioned.

## 0. What already exists vs. what this runbook is preparing for

Read this before anything else — it changes how you should sequence
the hardware window.

**Already implemented, hardware-free, in `main` today:**
- The vendor-neutral domain core, policy engine, lease/provenance model,
  local agent/IPC, audit trail, and `eltanin run` launch path — all of
  F-M1-001/003/004/005/006/008/009 — running against a deterministic
  `FakeBackend`, with CI passing on every PR.
- [ADR 0001](../adr/0001-linux-nvidia-cgroup-ebpf-enforcement.md) (decided
  the enforcement substrate: cgroup v2 device-BPF, not CUDA
  interception/`LD_PRELOAD`) and [ADR 0004](../adr/0004-local-ipc-and-nvml-ffi-boundary.md)
  (decided NVML lives behind a single FFI boundary in a not-yet-created
  `eltanin-nvidia` crate, dynamically loaded — no compile-time NVML
  header dependency).
- `docs/product/SECURITY_MODEL.md`'s "Threat levels" section, which
  states every enforcement claim as **provisional, pending hardware
  validation** — this runbook's whole job is to make that section real.

**Not implemented yet — this is the actual gap real hardware closes:**
- `crates/eltanin-nvidia` does not exist. HORO-828 (safe NVML
  loading/device identity), HORO-829 (telemetry/process-attribution
  mapping), and HORO-830 (real-hardware integration evidence) are all
  `To Do`.
- `ebpf/eltanin-device-guard` does not exist. HORO-841 (the mandatory
  spike), HORO-842 (BPF guard + loader), HORO-843 (agent integration),
  and HORO-844 (adversarial/regression suite) are all `To Do`.
- Because of the above, **the "exact test commands" in §7 below cannot
  all be real `cargo test` invocations today** — some are commands you
  can run right now against this repository as it exists, and some are
  a proposed convention for commands that will exist once the
  corresponding subtask lands. Both kinds are labeled explicitly; do
  not run the second kind expecting it to work before that code exists.

**Sequencing recommendation** (this is what makes the physical window
short): implement as much of HORO-828/829 and HORO-841's *spike
harness* (scripts/tooling, not conclusions) as possible against the
Fake backend and mocked `/dev/nvidia*`/cgroup interfaces first, on this
existing macOS/CI development flow, so the only things left for the
real machine are: (a) does NVML actually enumerate this real GPU the
way the mock assumed, (b) does the real kernel actually accept and
enforce the BPF program the way the spike's design assumes, and (c) the
final HORO-790 end-to-end run. Everything that can be TDD'd against a
mock should be, before the physical/paid clock starts.

## 1. Which environment: your own workstation, or rented hardware?

**Recommendation: your own Linux/NVIDIA workstation, if it meets §2–§5
below, is the better choice — not a fallback.**

Reasons, concretely:

- **It is unambiguously bare-metal.** HORO-790's Acceptance Criteria are
  explicit: *"VM-only, simulator-only, container-only or
  GPU-passthrough-only evidence does not satisfy MVP 1.0 READY."* A
  personal workstation with a physically installed GPU trivially
  satisfies this by construction. Renting hardware does not
  automatically satisfy it — see the warning below.
- **No paid-window time pressure.** Iteration (build, run spike, find the
  spike's assumption was wrong, adjust, rebuild) is exactly the loop
  HORO-841 describes, and it's open-ended by nature — a spike is
  investigation, not a fixed-duration task. A billed rental clock turns
  ordinary debugging into a cost decision it doesn't need to be.
- **Full root access with no provider abuse-policy friction.** Some cloud
  GPU providers restrict or flag raw BPF program loading, custom kernel
  module behavior, or non-standard cgroup manipulation as suspicious
  activity. A personal machine has none of that friction.

**If you rent instead, the critical trap to avoid:** almost every
"cloud GPU instance" (AWS, GCP, Azure, Lambda Cloud, most others'
standard GPU VM SKUs) is a **virtualized** guest — the GPU is exposed to
it via hypervisor passthrough (SR-IOV/vGPU or full PCI passthrough).
That is **exactly** the "GPU-passthrough-only evidence" HORO-790's AC
excludes, regardless of how "bare-metal-like" the marketing language is.
A rental only counts if it is a genuine **dedicated physical server**
with no hypervisor underneath your OS — e.g. a dedicated/colo server
product (the kind where you get the literal physical box, not a VM
carved out of one), not a "GPU cloud instance" product. Confirm this
explicitly with the provider before paying for anything; when in doubt,
`systemd-detect-virt` reporting anything other than `none` on the
target host is disqualifying for HORO-790's final gate (it may still be
fine for earlier, non-gating dev/debug iteration, just not for the
READY proof itself).

## 2. Minimum supported NVIDIA GPU requirements

- Any NVIDIA GPU currently supported by a production NVIDIA Linux
  driver branch. HORO-785's scope is discovery/telemetry plus one
  representative enforcement path, not a compute-class or performance
  claim — there is no minimum "compute capability" requirement from the
  Eltanin side.
- Practically: prefer Pascal-generation (GTX 10-series, 2016) or newer
  consumer cards, or any current datacenter card (T4/A-series/L-series/
  H-series/B-series/RTX-Enterprise), so the host lands on a *current*
  production driver branch without legacy-branch friction. As of this
  document's writing (September 2026) NVIDIA's current production
  branch is the 595.x series, with a 615.x "New Feature Branch" also
  active — re-check [nvidia.com/en-us/drivers](https://www.nvidia.com/en-us/drivers/)
  or [endoflife.date/nvidia](https://endoflife.date/nvidia) at execution
  time, since branches rotate; don't treat these specific numbers as
  durable.
- One GPU is sufficient — HORO-790 explicitly asks for **one
  representative** device, not a compatibility fleet (that's the
  separate, later "Representative Hardware Matrix" work, out of scope
  here).
- Evidence to record about the GPU itself (see §9): exact model, PCI
  bus id, and UUID — `nvidia-smi --query-gpu=name,pci.bus_id,uuid
  --format=csv`.

## 3. Required Linux distribution/kernel constraints

- **Kernel >= 4.15** is the hard floor: `BPF_PROG_TYPE_CGROUP_DEVICE`
  (the cgroup v2 device-BPF mechanism ADR 0001 commits to) landed in
  that release (upstream commit `ebc614f687369f9df99828572b1d85a7c2de3d92`).
  Anything older has no equivalent at all.
- **Recommended in practice: a current LTS kernel, 5.15+ (ideally 6.x)**
  — not because the mechanism needs it, but because (a) cgroup v2 as
  the *unified, default* hierarchy (rather than v1 or a "hybrid" mount)
  became the systemd default around systemd 247/248, which current LTS
  distro releases ship; older kernels/distros may still default to
  cgroup v1 and require manual unified-hierarchy migration, adding
  variables you don't want during a spike; and (b) BPF verifier/tooling
  maturity is meaningfully better on recent kernels.
- **Concretely recommended distros**: Ubuntu 22.04 LTS or 24.04 LTS,
  or a current Debian/Fedora release — anything that mounts cgroup v2
  unified by default. Verify with `stat -fc %T /sys/fs/cgroup/` →
  expect `cgroup2fs` (see the pre-flight script in §11).
- Cgroup v2's device access control has **no `cgroup.controllers` entry
  to check** (unlike v1's `devices` controller) — it is implemented
  entirely via a BPF program of type `BPF_CGROUP_DEVICE` attached to a
  cgroup, with no separate enable/disable knob. Verify capability via
  `bpftool feature probe` (look for cgroup_device program-type support)
  and via kernel config (`CONFIG_CGROUP_BPF=y`, `CONFIG_BPF_SYSCALL=y`),
  not via a controller-list file.

## 4. Required NVIDIA driver / CUDA versions

- **Driver**: the current proprietary NVIDIA Linux driver (any
  currently-supported production branch — see §2). Nouveau (the
  open-source reverse-engineered driver) does **not** work — NVML
  requires the proprietary driver.
- **CUDA toolkit: not required for F-M1-002 (NVML discovery).** HORO-785's
  own scope explicitly says "dynamically discover/load NVML," which
  means dlopen-style runtime loading (e.g. via a Rust
  `libloading`-based wrapper) against `libnvidia-ml.so`, which ships
  with the *driver* package, not the CUDA toolkit. The CUDA toolkit only
  ships `nvml.h` and a link-time *stub* — not needed when loading
  dynamically at runtime.
- **CUDA toolkit is needed only if** you choose Option B for the
  representative compute workload in §7's HORO-790 scenario (building
  an NVIDIA `cuda-samples` binary from source). The recommended Option A
  (a `pip`-installed PyTorch wheel) bundles its own CUDA runtime and
  needs no system CUDA toolkit or `nvcc` at all.

## 5. Required root/sudo/capabilities

- **Loading and attaching a `BPF_CGROUP_DEVICE` program** needs, at
  minimum, `CAP_SYS_ADMIN` on all supported kernels, or — on newer
  kernels with the more granular BPF capability model — a
  `CAP_BPF` + `CAP_PERFMON` (+ possibly `CAP_NET_ADMIN`, depending on
  the exact attach path) combination for program load, though cgroup
  attach itself may still require `CAP_SYS_ADMIN` depending on kernel
  version and distro hardening config. **The exact minimal set for your
  actual target kernel is precisely what HORO-841's spike (its own AC:
  "Privilege/capability requirements... recorded from evidence") is
  supposed to determine empirically** — do not treat any capability
  list here, including this one, as the final answer before that
  evidence exists.
- **Practical recommendation for the validation window**: run the spike
  itself as root. Capability minimization is HORO-842/843's hardening
  job (the production agent should run with the narrowest set HORO-841
  proves sufficient), not something to solve during exploratory spike
  work — solving both at once needlessly slows down the spike.
- **Cgroup creation/process movement** also needs root, or a properly
  delegated systemd cgroup scope (`systemd-run --scope`
  with `Delegate=yes`) — root is simplest for the validation window.
- **`/dev/nvidia*` access** needs root, or membership in whatever group
  the distro's NVIDIA packaging assigns those device nodes to (commonly
  `video` or a distro-specific group) — check with `ls -la /dev/nvidia*`.

## 6. Exact setup commands

Run in this order on the target host. Distro-specific package names are
for Ubuntu/Debian; adjust for other distros (the commands are copyable
as a reference sequence, not a single opaque script, because package
manager specifics and driver-branch numbers genuinely vary by distro
and drift over time — see the automated, distro-agnostic **checks** in
§11 instead for what to verify after each step).

```bash
# 1. Confirm the kernel/cgroup baseline before touching drivers.
uname -r
stat -fc %T /sys/fs/cgroup/          # expect: cgroup2fs

# 2. Install the NVIDIA driver (Ubuntu/Debian — installs the
#    distro-recommended production branch automatically).
sudo apt update
ubuntu-drivers devices               # see what it recommends
sudo ubuntu-drivers autoinstall      # or: sudo apt install nvidia-driver-<branch>
sudo reboot

# 3. After reboot, confirm the driver loaded and the GPU is visible.
nvidia-smi
lspci -nn | grep -i nvidia
ls -la /dev/nvidia*

# 4. Install bpftool for direct BPF capability probing/debugging.
sudo apt install -y linux-tools-common "linux-tools-$(uname -r)"
bpftool feature probe | grep -i cgroup_device

# 5. Install the Rust toolchain (this repo pins channel = "stable" via
#    rust-toolchain.toml, no specific version pin).
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup component add rustfmt clippy

# 6. Clone the repo and sanity-check the hardware-free baseline first —
#    if this doesn't pass, nothing downstream will be trustworthy.
git clone https://github.com/horonomy/eltanin.git
cd eltanin
cargo build --workspace --all-targets
cargo test --workspace

# 7. (Only if using compute-workload Option A in §7) Python + PyTorch,
#    no system CUDA toolkit needed — PyTorch's wheel bundles its own
#    CUDA runtime.
sudo apt install -y python3 python3-venv
python3 -m venv .venv-hardware-eval
source .venv-hardware-eval/bin/activate
pip install torch --index-url https://download.pytorch.org/whl/cu121  # match to a CUDA runtime <= your driver's max supported CUDA version; check https://pytorch.org/get-started/locally/ at execution time
```

## 7. Exact test commands

### 7a. Runnable today (no hardware-specific Eltanin code exists yet)

```bash
# Hardware-free sanity baseline — must pass before anything else is
# meaningful. This is exactly what CI already runs.
cargo test --workspace

# Environment-only verification (no Eltanin code involved at all) —
# see the automated version of this in §11.
bash scripts/hardware-preflight-check.sh
```

### 7b. F-M1-002 / HORO-785 — once HORO-828/829/830 land

**Proposed convention** (not yet real — nothing under this heading
exists in the repo today): a `crates/eltanin-nvidia` crate with its
unit tests running normally in CI against mocked NVML responses, plus a
real-hardware integration test explicitly gated so it never runs in
normal (no-GPU) CI — per HORO-785's own AC ("real-hardware integration
test is separately tagged/gated"):

```bash
# Hardware-free unit tests (should already be part of normal CI once
# this crate exists) — run this first as a regression baseline.
cargo test -p eltanin-nvidia

# The real-hardware integration test, `#[ignore = "requires real
# NVIDIA hardware"]`-gated so cargo test --workspace alone never runs
# it:
cargo test -p eltanin-nvidia --test hardware_integration -- --ignored --nocapture
```

### 7c. F-M1-007 / HORO-789, including the HORO-841 spike

**HORO-841 is explicitly a spike** — its own AC asks for "reproducible
spike scripts/tests," not a finished feature. Before any implementation
commitment, write small, disposable probe programs/scripts (not
necessarily `cargo test` at all — a raw C or Rust program calling
`bpf()`/`setns()`/cgroup file operations directly may be faster to
iterate on for pure investigation) that answer each bullet in HORO-841's
"Required Investigation" list, and capture their output as evidence
(§9). Once HORO-842/843/844 turn that into real implementation:

```bash
# Hardware-free unit/mock tests for the guard's pure logic.
cargo test -p eltanin-device-guard

# The real-hardware enforcement integration test — same
# `#[ignore]`-gating convention as F-M1-002:
cargo test -p eltanin-device-guard --test hardware_integration -- --ignored --nocapture
```

### 7d. HORO-790 — the end-to-end proof

**Proposed convention**: a hardware-gated twin of the existing
`crates/eltanin-cli/tests/canonical_e2e.rs` (the Track B scenario
HORO-847 already built against `FakeBackend`), reusing its exact
7-step scenario shape but wired to the real NVIDIA backend and real
device-guard enforcement instead of the fake:

```bash
cargo test -p eltanin-cli --test canonical_e2e_hardware -- --ignored --nocapture
```

This exercises, on the real host: agent start with the real NVIDIA
backend discovering the real GPU → an authorized `eltanin run` workload
succeeding (real compute, not merely a lease being issued) → an
unauthorized launch being denied *before* it can touch the GPU → repeat
for the lifecycle cases HORO-790 names (process exit, lease expiry,
agent restart where supported, backend error).

**For the actual "real compute succeeds" leg**, use one of:

- **Option A (recommended, no CUDA toolkit needed)**: a workload that
  runs `python3 -c "import torch; x = torch.rand(2048, 2048, device='cuda'); print((x @ x).sum().item())"`
  inside the `.venv-hardware-eval` from §6 step 7 — a real GPU matrix
  multiply, minimal and fast.
- **Option B**: build and run NVIDIA's open-source
  [`cuda-samples`](https://github.com/NVIDIA/cuda-samples) `deviceQuery`
  and `vectorAdd` binaries (requires the CUDA toolkit + `nvcc`; use only
  if you'd rather avoid Python).

Either way, the workload must be launched *through* `eltanin run` (not
invoked directly) for the ALLOW leg, and the same command attempted
*without* a valid authorization path for the DENY leg, matching HORO-790's
test scenario steps verbatim.

## 8. Expected runtime per step

Estimates, not measurements — nothing has run yet. Treat these as
planning inputs for scheduling a rented window, not commitments.

| Step | Estimated time |
|---|---|
| Driver install + reboot (§6 steps 1–3) | 10–20 min |
| bpftool + Rust toolchain install (§6 steps 4–5) | 5–10 min |
| Clone + hardware-free baseline build/test (§6 step 6) | 5–15 min, machine-dependent |
| Python/PyTorch setup (§6 step 7, if using Option A) | 5–10 min (network-dependent download) |
| `hardware-preflight-check.sh` (§11) | < 5 seconds |
| HORO-828/829 NVML discovery hardware integration test, once it exists | seconds, once written |
| HORO-841 spike investigation itself | **not a fixed duration** — this is exploratory investigation against each "Required Investigation" bullet, budget an open-ended session (realistically several hours across one or more sittings), not a single test run |
| HORO-842/843/844 device-guard hardware integration tests, once they exist | seconds to low minutes per test, once written |
| HORO-790 end-to-end scenario, once it exists | under a minute, matching `canonical_e2e.rs`'s existing fake-backend runtime order of magnitude |
| Evidence capture (§11 script) | < 10 seconds |
| Cleanup (§10) | 5–10 min |

The dominant, genuinely unpredictable cost is the HORO-841 spike
itself — everything else here is mechanical and fast. This is exactly
why §0's sequencing recommendation (build and rehearse as much spike
tooling as possible against mocks first) matters most for keeping any
paid/scheduled window short.

## 9. Expected evidence/artifacts/logs

Directly from HORO-790's own "Evidence to Capture" list (verbatim
scope, not reinterpreted), plus HORO-841's spike-specific asks:

- Exact OS/kernel/NVIDIA driver/GPU model, and explicit confirmation of
  bare-metal (non-virtualized) status (`systemd-detect-virt` → `none`).
- Commands/config/policy used for each run.
- The authorization decision and policy version for each leg (ALLOW/
  DENY).
- Workload/process/cgroup provenance (what `eltanin-audit`/`eltanin-explain`
  already records for the fake-backend path today — same schema,
  real data).
- Enforcement result/error (device-BPF verdict, `EPERM` or success).
- GPU-side evidence that allowed compute actually ran and denied
  compute did not (e.g. the PyTorch/`cuda-samples` workload's own
  stdout, plus `nvidia-smi` process-attribution output captured during
  the ALLOW leg).
- Machine-readable automated test results (`cargo test ... -- --format
  json` where the harness supports it, or captured stdout otherwise).
- Full logs sufficient for independent reproduction — not summaries.
- HORO-841 specifically: the exact required NVIDIA device-node set
  (major/minor tuples) discovered, proof of new-open-vs-already-open-
  handle behavior (not assumed), and the capability/privilege set that
  actually worked (superseding §5's "run as root for now" once proven
  narrower).

**Where it goes**: one directory per validation run,
`evidence/<UTC-timestamp>-<hostname>/` (created automatically by
§11's capture script), holding every command's raw output. Once a run
is judged complete and correct, promote its summary into a
`docs/qa/reports/` instance following
[`docs/qa/reports/TEMPLATE.md`](../qa/reports/TEMPLATE.md) — HORO-790's
own AC requires this Release Quality Report be "committed/linked," not
left as a local directory only you can see. Redact anything genuinely
sensitive (real hostnames/IPs beyond what's needed for reproducibility)
before committing, but do not omit anything HORO-790's evidence list
requires.

## 10. Cleanup commands

**On a personal, permanent workstation** (the recommended path — light
cleanup, keep the driver/toolchain installed for next time):

```bash
# Remove any test cgroups created during the spike (adjust the path to
# whatever HORO-841's actual spike scripts create).
sudo rmdir /sys/fs/cgroup/eltanin-hardware-spike 2>/dev/null || true

# Detach/unload any BPF programs the spike attached, if not already
# torn down by the spike script itself (bpftool cgroup detach / prog
# lists what's currently attached — inspect before removing anything
# on a shared machine).
bpftool cgroup tree
bpftool prog list | grep -i cgroup_device

# Remove the temporary Python venv, if created for Option A's compute
# workload.
rm -rf .venv-hardware-eval

# Remove any temporary sockets/policy files the spike or hardware-gated
# tests left under /tmp or /run.
rm -f /tmp/eltanin-hardware-*.sock /tmp/eltanin-hardware-*.json 2>/dev/null || true
```

**On rented dedicated hardware**: follow the provider's full
deprovisioning/reimage process, and confirm no SSH keys, this
repository's clone, or any evidence-directory copy is left on the
returned host before releasing it.

## 11. Automation

Three scripts, all committed alongside this document
(`scripts/hardware-preflight-check.sh`,
`scripts/hardware-evidence-capture.sh`,
`scripts/e3-preflight-device-bpf-probe.sh`). The first two are
read-mostly by design — they check and record, they don't install or
modify system state, so they're safe to run on any candidate host
without a "did this just change something" question. The third
(the device-BPF functional probe) does create and tear down its own
disposable cgroups/processes/BPF programs, but never touches anything
that pre-existed its own run — see its own header comment and
`docs/qa/privileged-enforcement-testing.md` for the blast-radius
guarantees this implies. The setup steps that do modify system
state (§6) stay as explicit, reviewable commands rather than a single
opaque install script, because package names and driver-branch numbers
genuinely drift across distros and time — an unattended installer here
is more likely to silently do the wrong thing on a host you haven't
seen yet than a human reading five copy-pasted commands.

```bash
# Before spending any setup effort on a candidate host: does it even
# qualify, and which evidence class can it even produce?
bash scripts/hardware-preflight-check.sh
# or, for machine-readable output:
bash scripts/hardware-preflight-check.sh --json

# Stage-1 preflight: functional cgroup v2 device-BPF investigation,
# no GPU required, always E3_PREFLIGHT_ONLY:
sudo bash scripts/e3-preflight-device-bpf-probe.sh --json

# After setup (§6) and after running whichever hardware-gated tests
# exist at the time (§7), capture the full evidence bundle for the run:
bash scripts/hardware-evidence-capture.sh
# each hardware-gated test's own output should also be redirected into
# the same directory the script just created/printed, e.g.:
#   cargo test -p eltanin-nvidia --test hardware_integration -- --ignored --nocapture \
#     > "evidence/<the-directory-just-printed>/nvidia-hardware-integration.log" 2>&1
```

## 12. One end-to-end copyable sequence

Everything above, concatenated into the order you'd actually run it,
for a fresh qualifying host:

```bash
# 0. Does this host even qualify? (safe, no changes made)
git clone https://github.com/horonomy/eltanin.git && cd eltanin
bash scripts/hardware-preflight-check.sh || echo "fix FAILs above before continuing"

# 1. Driver + tooling setup (§6)
sudo apt update
sudo ubuntu-drivers autoinstall
sudo reboot
# --- reconnect after reboot ---
cd eltanin
nvidia-smi && lspci -nn | grep -i nvidia && ls -la /dev/nvidia*
sudo apt install -y linux-tools-common "linux-tools-$(uname -r)" python3 python3-venv
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup component add rustfmt clippy

# 2. Re-check now that setup is done.
bash scripts/hardware-preflight-check.sh

# 3. Hardware-free baseline must be green before anything hardware-specific.
cargo build --workspace --all-targets
cargo test --workspace

# 4. Compute-workload environment (Option A).
python3 -m venv .venv-hardware-eval
source .venv-hardware-eval/bin/activate
pip install torch --index-url https://download.pytorch.org/whl/cu121
python3 -c "import torch; x = torch.rand(2048, 2048, device='cuda'); print((x @ x).sum().item())"

# 5. Start an evidence bundle for this run.
EVIDENCE_DIR_LINE=$(bash scripts/hardware-evidence-capture.sh | tee /dev/stderr | grep '^Writing evidence to:')
EVIDENCE_DIR=${EVIDENCE_DIR_LINE#"Writing evidence to: "}

# 6. Once HORO-828/829/841/842/843/844 have landed, run the real
#    hardware-gated suites, each redirected into the evidence bundle:
cargo test -p eltanin-nvidia --test hardware_integration -- --ignored --nocapture \
  > "$EVIDENCE_DIR/nvidia-hardware-integration.log" 2>&1
cargo test -p eltanin-device-guard --test hardware_integration -- --ignored --nocapture \
  > "$EVIDENCE_DIR/device-guard-hardware-integration.log" 2>&1
cargo test -p eltanin-cli --test canonical_e2e_hardware -- --ignored --nocapture \
  > "$EVIDENCE_DIR/canonical-e2e-hardware.log" 2>&1

# 7. Promote the run into a committed Release Quality Report
#    (docs/qa/reports/TEMPLATE.md), then clean up (§10).
```
