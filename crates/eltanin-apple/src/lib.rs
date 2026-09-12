//! Apple Silicon accelerator adapter (F-M1-010, HORO-1012).
//!
//! Discovers the system Metal GPU device(s) through supported, public
//! Metal APIs (`objc2-metal`) and maps them into Eltanin's vendor-neutral
//! `ProtectedResource` contract (`eltanin_core::resource`). No
//! Objective-C/Metal-specific type crosses this crate's boundary — see
//! `crate::device::DeviceSnapshot`, an owned, plain-Rust value.
//!
//! # Capability honesty
//!
//! [`AppleBackend`] never claims device-level protection. Per
//! `docs/adr/0006-cross-accelerator-capability-and-memory-model.md` and
//! `docs/adr/0007-apple-silicon-metal-backend.md`:
//!
//! | Capability | State | Why |
//! |---|---|---|
//! | `DiscoverResource` | `Supported` | `MTLCopyAllDevices` genuinely enumerates devices. |
//! | `ObserveResource` | `Partial` | Only static attributes (name, registry ID, unified-memory flag) — no utilization API, no shelling out to `system_profiler`. |
//! | `ObserveWorkload` | `Unsupported` | No public cross-process GPU workload enumeration exists. |
//! | `AttributeWorkload` | `Unsupported` | Attribution is the platform adapter's job (HORO-1013), not this backend. |
//! | `Authorize` | `Unsupported` | This backend never decides authorization. |
//! | `ControlledLaunch` | `NotEvaluated` | Launch is HORO-1013's scope — not claimed here. |
//! | `DeviceEnforce` | `Unsupported` | Per this ticket's AC and ADR 0006's E2 definition. |
//! | `DeviceRevoke` | `Unsupported` | Same as `DeviceEnforce`. |
//! | `Attest` | `Unsupported` | No attestation path exists. |
//!
//! Successful discovery is not protection: `ComputeBackend::enforce` and
//! `ComputeBackend::revoke` report `EnforcementResult::Unsupported` on
//! every target, unconditionally — not just when a Metal device happens to
//! be absent.
//!
//! # Non-macOS builds
//!
//! On any `target_os` other than `macos`, `AppleBackend::discover` and
//! `AppleBackend::observe` return `Err(BackendError::Unsupported)`
//! rather than failing to compile: no `objc2`/`objc2-metal` dependency
//! enters a non-macOS build's dependency graph at all (see this crate's
//! `Cargo.toml`), and `crate::probe::run_compute_probe` returns the
//! same `Unsupported` shape. `enforce`/`revoke` are not `cfg`-gated at
//! all — they return `Unsupported` on every target, so no compilation
//! path can ever produce `EnforcementResult::Allowed`.

pub mod backend;
pub mod device;
pub mod probe;

pub use backend::AppleBackend;
