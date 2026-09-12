//! `metal-workload-fixture` — a small, standalone, spawnable Metal
//! compute workload (F-M1-010, HORO-1014).
//!
//! This is the repository-owned real-GPU-compute program Jira's
//! "Eltanin Integration" section asks for: something `eltanin run`
//! (or the equivalent controlled-launch flow) can spawn as `<program>`
//! after `--`, so the managed ALLOW/DENY journey has a genuine Metal
//! workload to authorize or block — not `echo`/`true`, which prove the
//! launch mechanics but not real accelerator execution.
//!
//! It is deliberately **not** a product runtime binary and is not part
//! of any `ComputeBackend`: it reuses `eltanin_apple::probe`'s already
//! Feature-Verification-adjacent kernel-dispatch code (F-M1-010,
//! HORO-1012), adding only host/workload metadata and a machine-readable
//! JSON evidence report on top — see `#![forbid(unsafe_code)]` below:
//! every `unsafe` line in this workload's actual Metal dispatch stays
//! isolated in `crate::probe`'s `imp` module, exactly where it already
//! was.
//!
//! # What this proves, and what it does not
//!
//! A `0` exit and a printed JSON report prove: a real Metal command
//! buffer was submitted to a real system GPU device and completed
//! (`waitUntilCompleted`), and its output was read back and
//! independently verified against a CPU-computed expected value for the
//! same deterministic input. It proves nothing about device-level
//! enforcement, revocation, or protection — see
//! `docs/product/APPLE_SILICON_FIXTURE.md` for the full claim boundary
//! (same E2/E3 distinction as ADR 0006/0007 and
//! `docs/product/SECURITY_MODEL.md`).
//!
//! # Exit codes
//!
//! | Exit | Meaning |
//! |---|---|
//! | 0 | Metal compute completed and the result was independently verified. |
//! | 1 | No Metal device/command execution is available on this host (e.g. non-macOS, or macOS with no Metal device) — an environment precondition, not a compute failure. |
//! | 2 | A Metal device was present but the kernel dispatch, readback, or result verification failed — always a hard failure, never silently downgraded to a skip. |
//!
//! No code path here falls back to a CPU-only computation and reports
//! success — see `crate::probe::run_compute_probe`'s doc comment and
//! `BackendError` cases: every non-`Ok` outcome is `Unsupported` (exit 1)
//! or `Transient` (exit 2), and only `Ok` produces exit 0.
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use eltanin_apple::probe::{self, ComputeProbeReport};
use eltanin_backend::contract::BackendError;

/// This fixture's own schema version for the JSON evidence it prints —
/// bump if the shape of [`Evidence`] changes in a way a consumer might
/// depend on.
const SCHEMA_VERSION: u32 = 1;

/// Machine-readable run evidence (Jira's "produce machine-readable run
/// metadata/evidence" requirement). Serialized as JSON to stdout always,
/// and additionally to `--evidence-out <path>` when given.
#[derive(Debug, serde::Serialize)]
struct Evidence {
    schema_version: u32,
    fixture: &'static str,
    host: Host,
    device: Device,
    workload: Workload,
    result: WorkloadResult,
}

#[derive(Debug, serde::Serialize)]
struct Host {
    /// `std::env::consts::ARCH`, e.g. `"aarch64"`.
    arch: &'static str,
    /// `std::env::consts::OS`, e.g. `"macos"`.
    os: &'static str,
}

#[derive(Debug, serde::Serialize)]
struct Device {
    name: String,
    /// Hex-encoded `MTLDevice::registryID` — see
    /// [`ComputeProbeReport::registry_id`].
    registry_id: String,
    has_unified_memory: bool,
}

#[derive(Debug, serde::Serialize)]
struct Workload {
    kernel: &'static str,
    element_count: usize,
    /// Hex-encoded FNV-1a 64-bit fingerprint of the kernel's input
    /// buffer — see `eltanin_apple::probe::fnv1a_64`.
    input_hash: String,
}

#[derive(Debug, serde::Serialize)]
struct WorkloadResult {
    verified_elements: usize,
    /// `true` iff every dispatched output element was independently
    /// checked against its CPU-computed expected value — always `true`
    /// when this struct exists at all, since `probe::run_compute_probe`
    /// returns `Err` rather than a partial `Ok` on any mismatch. Kept as
    /// an explicit field (not implied) so a consumer never has to infer
    /// "verified" from mere presence of this JSON document.
    all_elements_verified: bool,
    /// `true` iff the Metal command buffer's `waitUntilCompleted` call
    /// returned, i.e. the GPU genuinely finished executing the
    /// submitted command — the "proof the GPU command completed through
    /// Metal" Jira's QA section asks for.
    gpu_command_completed: bool,
}

impl From<ComputeProbeReport> for Evidence {
    fn from(report: ComputeProbeReport) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            fixture: "eltanin-apple-metal-workload-fixture",
            host: Host {
                arch: std::env::consts::ARCH,
                os: std::env::consts::OS,
            },
            device: Device {
                name: report.device_name,
                registry_id: format!("{:#x}", report.registry_id),
                has_unified_memory: report.has_unified_memory,
            },
            workload: Workload {
                kernel: "double_elements",
                element_count: report.element_count,
                input_hash: format!("{:#018x}", report.input_hash),
            },
            result: WorkloadResult {
                verified_elements: report.verified_elements,
                all_elements_verified: report.verified_elements == report.element_count,
                gpu_command_completed: true,
            },
        }
    }
}

/// `--evidence-out <path>`: an optional file to additionally write the
/// same JSON evidence to. Kept deliberately tiny (one optional flag, no
/// argument-parsing dependency) — this is a QA fixture, not a CLI
/// product surface.
fn parse_evidence_out(args: &[String]) -> Result<Option<PathBuf>, String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--evidence-out" {
            let path = iter
                .next()
                .ok_or_else(|| "--evidence-out requires a path argument".to_string())?;
            return Ok(Some(PathBuf::from(path)));
        }
    }
    Ok(None)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let evidence_out = match parse_evidence_out(&args) {
        Ok(path) => path,
        Err(message) => {
            eprintln!("metal-workload-fixture: {message}");
            return ExitCode::from(1);
        }
    };

    match probe::run_compute_probe() {
        Ok(report) => {
            let evidence = Evidence::from(report);
            let json = serde_json::to_string_pretty(&evidence)
                .expect("Evidence serializes to JSON infallibly");
            println!("{json}");
            if let Some(path) = evidence_out {
                if let Err(e) = write_evidence_file(&path, &json) {
                    eprintln!(
                        "metal-workload-fixture: computed and verified real Metal GPU output, \
                         but failed to write --evidence-out {}: {e}",
                        path.display()
                    );
                    return ExitCode::from(2);
                }
            }
            ExitCode::SUCCESS
        }
        Err(BackendError::Unsupported { .. }) => {
            eprintln!(
                "metal-workload-fixture: no Metal device/command execution is available on \
                 this host (non-macOS target, or macOS with no Metal device present) — this is \
                 an environment precondition failure, not a compute failure; refusing to report \
                 a fabricated CPU-only success"
            );
            ExitCode::from(1)
        }
        Err(other) => {
            eprintln!(
                "metal-workload-fixture: real Metal compute failed on a present device: {other}"
            );
            ExitCode::from(2)
        }
    }
}

fn write_evidence_file(path: &PathBuf, json: &str) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(json.as_bytes())?;
    file.write_all(b"\n")
}
