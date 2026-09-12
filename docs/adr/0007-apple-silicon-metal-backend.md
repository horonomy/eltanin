# ADR 0007: Apple Silicon Metal backend — crate boundary, binding choice, capability/memory mapping

## Status

Accepted (MVP 1.0 — Apple Silicon scope amendment).

## Context

[ADR 0006](0006-cross-accelerator-capability-and-memory-model.md)
introduced the nine-dimension `Capability`/`SupportState` model and the
`AcceleratorMemory` type so a backend can be functionally compatible
with a platform (E2 evidence) without that ever being read as
device-level protection (E3 evidence). ADR 0006 changed the vocabulary;
it did not implement a backend that speaks it. F-M1-010/HORO-1012 is the
first ticket that actually discovers a physical Apple Silicon Metal
device through supported APIs and reports it via that vocabulary — this
ADR records the boundary and binding decisions that implementation made.

Three decisions needed to be made before writing any Metal-calling code:
where the boundary between vendor-neutral and Apple-specific code sits,
what Rust binding to Metal to use, and how a Metal device's real
attributes map onto ADR 0006's vocabulary.

## Decision — crate boundary

A new workspace member, `crates/eltanin-apple`, holds all
Objective-C/Metal-specific code. Named after the vendor
(`eltanin-apple`), matching this workspace's existing convention
(`eltanin-nvidia`, not `eltanin-cuda`) rather than naming the API
surface (`eltanin-metal`) — the crate boundary is "the Apple vendor
adapter," not "a Metal wrapper library," which matters if a future
Apple-Silicon-specific capability needs a non-Metal API.

`crates/eltanin-apple` implements `eltanin_backend::contract::ComputeBackend`
(`AppleBackend`), exactly the seam the Fake backend and the eventual
NVIDIA backend also implement — no new trait, no new backend-specific
method on `ComputeBackend` itself. It depends on `eltanin-core` and
`eltanin-backend`; neither depends back on it, mirroring the dependency
direction `crates/eltanin-backend/tests/architecture_no_vendor_leak.rs`
already enforces for NVIDIA, now extended (in the same PR) to ban
`metal`/`mtl`/`objc`/`apple`/`darwin` from `eltanin-core`'s and
`eltanin-backend`'s own source.

`crates/eltanin-apple` stays a normal, non-excluded workspace member —
its `objc2`/`objc2-foundation`/`objc2-metal` dependencies are target-gated
to `cfg(target_os = "macos")` in its own `Cargo.toml`, so they never enter
a non-macOS build's dependency graph, but the crate itself still
participates in `cargo {clippy,test,doc} --workspace` on every CI
runner, including this repository's `ubuntu-latest` jobs. Excluding the
crate from the workspace instead (as one alternative) was rejected: it
would silently drop it from every existing CI gate rather than
compiling its non-macOS fallback path there.

## Decision — Rust/Metal binding

Use `objc2` + `objc2-foundation` + `objc2-metal` (the `objc2` project's
generated, maintained Metal bindings), not the `metal` crate (the
gfx-rs-maintained wrapper) and not a hand-rolled FFI/Swift sidecar.

- **The `metal` crate is self-declared deprecated** in favor of
  `objc2-metal`, and sits on the unmaintained `objc` 0.2 crate rather
  than `objc2`'s actively maintained runtime bindings. Adopting a
  self-declared-deprecated dependency for a new crate is not defensible
  when a maintained alternative covers the same surface.
- **A hand-rolled Objective-C/Metal FFI shim** was rejected: `objc2-metal`
  already provides a safe surface for every operation this ticket and
  its compute probe need (see "Decision — unsafe boundary" below), so a
  narrower hand-written binding would only reproduce work already done,
  reviewed, and maintained upstream, contrary to
  `docs/product/PRODUCT_CONSTITUTION.md`'s "C only at unavoidable FFI
  boundaries" policy applied by analogy.
- **A broad Swift/Objective-C sidecar process** was rejected per Jira's
  own instruction: nothing about this backend's scope (device discovery,
  static attribute reporting, a single compute-kernel probe) requires
  capabilities `objc2-metal` cannot express in Rust; a sidecar would add
  a second language, a second build toolchain, and a process/IPC boundary
  for no capability gain.

`objc2-metal` 0.3.x is pinned with `default-features = false` and an
explicit, narrow feature list (`MTLDevice`, `MTLLibrary`,
`MTLCommandQueue`, `MTLCommandBuffer`, `MTLComputePipeline`,
`MTLComputeCommandEncoder`, `MTLBuffer`, `MTLResource`, `MTLTypes`, `std`)
rather than its ~104-feature default set, which pulls in bindings for
subsystems (ray tracing, indirect command buffers, `MTL4*` types, capture
management, and more) this crate never calls. License:
`Zlib OR Apache-2.0 OR MIT` (verified against `deny.toml`'s allow-list,
which already permits `MIT`/`Apache-2.0`); `cargo deny check licenses`
was run against the real dependency graph this Cargo.toml produces
before this PR, not assumed.

## Decision — unsafe boundary

This workspace's default posture (`docs/product/PRODUCT_CONSTITUTION.md`)
is `#![forbid(unsafe_code)]` on every vendor-neutral crate, with `unsafe`
permitted only in platform/vendor crates. `crates/eltanin-apple` is such
a crate, but it does **not** blanket-allow `unsafe_code` at the crate
level — it uses a single, scoped `#[allow(unsafe_code)]` on exactly one
function, `crate::probe::run_compute_probe`, which is the only place this
crate's code cannot express what it needs through a safe `objc2-metal`
function alone: binding a `ProtocolObject<dyn MTLBuffer>` at a fixed
index/offset on a compute encoder
(`MTLComputeCommandEncoder::setBuffer_offset_atIndex`, an `unsafe fn` on
the pinned `objc2-metal` version because it hands the GPU a
caller-chosen memory region) and reconstructing a typed Rust slice over
`MTLBuffer::contents()`'s returned pointer for the correctness readback
(`std::slice::from_raw_parts`, whose safety depends on invariants — bound
by the buffer's allocated length and by `waitUntilCompleted` having
already returned — that the type system cannot verify). Every other
public function in this crate, including all of device discovery
(`crate::device::snapshot_all`) and the entire `ComputeBackend`
implementation (`crate::backend::AppleBackend`), uses zero `unsafe` code:
`MTLCopyAllDevices` and every `MTLDevice` accessor this crate calls
(`name`, `registryID`, `hasUnifiedMemory`) are safe functions on the
pinned `objc2-metal` version — verified against that version's real
docs.rs output, not assumed from the crate's general "Metal is as unsafe
as CPU code" framing.

This ADR amends [ADR 0004](0004-local-ipc-and-nvml-ffi-boundary.md)'s
Consequences section, which stated HORO-828/NVML was "the only ticket
expected to introduce `unsafe` code into the workspace's initial crate
set." That is no longer accurate as of this ADR; see the amendment note
added to ADR 0004 in the same PR as this ADR. ADR 0004 itself is not
edited or renumbered beyond that note — its NVML FFI-boundary decision
is unaffected.

## Decision — capability and memory mapping

`AppleBackend` reports itself via `ResourceCapabilities::from_states(..)`
(explicit per-capability `SupportState`), never `::new(..)` (which would
mark every listed capability `Supported` with no way to express
`Partial`/`NotEvaluated`):

| Capability | State | Why |
|---|---|---|
| `DiscoverResource` | `Supported` | `MTLCopyAllDevices` genuinely enumerates every Metal device present. |
| `ObserveResource` | `Partial` | Only static attributes are available (name, registry ID, unified-memory flag) — no utilization API, and this backend never shells out to `system_profiler` or scrapes IOKit as a substitute for a real API. |
| `ObserveWorkload` | `Unsupported` | No public cross-process GPU workload enumeration exists on this platform. |
| `AttributeWorkload` | `Unsupported` | Attribution of an observed workload to a requester is the platform adapter's job (HORO-1013), not this discovery backend's. |
| `Authorize` | `Unsupported` | This backend never makes an authorization decision — that is F-M1-004's job, evaluated before any backend is consulted. |
| `ControlledLaunch` | `NotEvaluated` | Launching a workload under a controlled/observed context is HORO-1013's scope; this ticket implements discovery only and must not claim a capability it has not built. |
| `DeviceEnforce` | `Unsupported` | Per this ticket's acceptance criteria and ADR 0006's E2 definition: Apple Silicon has no validated kernel-level mechanism this project uses to deny device-level GPU access. |
| `DeviceRevoke` | `Unsupported` | Same reasoning as `DeviceEnforce`. |
| `Attest` | `Unsupported` | No attestation path exists. |

Memory topology: `MTLDevice::hasUnifiedMemory() == true` maps to
`AcceleratorMemory::Unified` (no byte count, per ADR 0006);
`false` maps to `AcceleratorMemory::NotReportable`. This backend never
synthesizes `AcceleratorMemory::Dedicated { total_bytes }` from
`recommendedMaxWorkingSetSize()` or any other working-set-recommendation
API — that number is a scheduling hint, not a real dedicated-VRAM
figure, and reporting it as `Dedicated` would violate both this ticket's
"report unified memory truthfully" acceptance criterion and ADR 0006's
truthful-by-construction intent.

Identity: `ResourceVendor::new("apple")` is constructed inside
`crates/eltanin-apple` itself — no `ResourceVendor::apple()` helper is
added to `eltanin-core`, which would be exactly the vendor-name leak
into core `docs/product/PRODUCT_CONSTITUTION.md` forbids.
`ResourceIdentity::local_id` is the device's `registryID` (as a decimal
string), not its human-readable `name` — `name` is not guaranteed
stable or unique on a multi-GPU host, while `registryID` is a stable
per-device local identifier.

## Decision — non-macOS fallback

`AppleBackend::discover`/`observe` are `cfg`-gated: on `macos` they call
into `crate::device`; on every other `target_os` they return
`Err(BackendError::Unsupported)` directly, with zero Metal calls
attempted (no `objc2*` dependency exists in a non-macOS build's
dependency graph at all). `AppleBackend::enforce`/`revoke` are
deliberately **not** `cfg`-gated: they return
`Ok(EnforcementResult::Unsupported)` unconditionally on every target, so
no compilation path — macOS or otherwise — can ever produce
`EnforcementResult::Allowed` from this backend. `crate::device::DeviceSnapshot`
and the capability/memory mapping function that consumes it
(`crate::backend::snapshot_to_resource`) are themselves unconditional
(not `cfg`-gated), which is what lets this ADR's capability/memory
mapping decision above be tested as a pure function over synthetic
`DeviceSnapshot` values on this repository's hardware-free
`ubuntu-latest` CI, with no real Metal device or macOS runner required.

The real Metal compute probe (`crate::probe::run_compute_probe`) is a
standalone function, not a `ComputeBackend` method — the trait gains no
new method for it. `AppleBackend::discover` must stay cheap and
side-effect-free (no kernel dispatch); the probe is real-hardware-tagged
integration evidence for HORO-1015, not part of the vendor-neutral
contract every backend implements.

## Consequences

- A second `unsafe`-containing crate now exists in this workspace
  (`crates/eltanin-nvidia`, not yet implemented, remains the first
  planned one per ADR 0004; `crates/eltanin-apple` is the first one
  actually merged). ADR 0004 is amended, not rewritten, to reflect this.
- `crates/eltanin-core/tests/architecture_no_vendor_leak.rs` and
  `crates/eltanin-backend/tests/architecture_no_vendor_leak.rs` gain five
  new forbidden terms (`metal`, `mtl`, `objc`, `apple`, `darwin`),
  landing before any Apple-specific code in this PR's commit sequence.
- `docs/product/PRODUCT_CONSTITUTION.md`'s unsafe-crate exception list
  and vendor-adapter bullet, and `docs/architecture/domain-model.md`,
  are updated in this same PR to reflect this crate's existence.
- This PR does not add a `macos-latest` CI job: no CI runner in this
  repository's `.github/workflows/ci.yml` runs on macOS, and HORO-1012's
  Jira description does not ask for one — the real-hardware compute
  probe is real-hardware-tagged integration evidence for HORO-1015
  (physical M3 Max), run manually/out-of-band, exactly like this
  repository's existing Linux/NVIDIA hardware evidence gates
  (`docs/qa/test-plans/mvp-1.0.md`'s "Hardware requirement" section).
  `#[cfg(target_os = "macos")]` code in this PR compiles on this
  repository's Linux CI (the `cfg` condition is false there, so the
  block is skipped, not exercised) but is never executed by CI — only a
  real macOS session can execute it, and this PR's author states plainly
  in its own report which parts were and were not actually run.

## North Star unchanged

**"No protected compute without authorization"** is untouched by this
ADR. `AppleBackend` adds discovery and (separately, via
`crate::probe::run_compute_probe`) real-hardware functional proof of
Metal GPU compute — it adds zero authorization, enforcement, or revoke
capability. `EnforcementResult::Allowed` is unreachable from this
backend by construction (see "Decision — non-macOS fallback" above).

This ADR does not change ADR 0006's evidence-class framing: **E2
(Apple Silicon real-accelerator functional evidence) remains additive
functional proof, explicitly not a device-level protection claim.**
**E3 (Linux/NVIDIA physical device-level enforcement, F-M1-007) remains
the sole, mandatory basis for any device-level protection claim this
project makes.** An Apple-only PASS is insufficient for MVP 1.0 READY
and remains **BLOCKED ON E3** — this ADR implements one input to E2
evidence collection; it does not and cannot satisfy E3.

This ADR amends [ADR 0004](0004-local-ipc-and-nvml-ffi-boundary.md) (see
above) and builds on [ADR 0006](0006-cross-accelerator-capability-and-memory-model.md);
it does not supersede either, and neither is renumbered or edited beyond
ADR 0004's amendment note.
