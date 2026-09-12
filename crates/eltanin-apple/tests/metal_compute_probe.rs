//! Real-hardware Metal compute probe evidence (F-M1-010, HORO-1012).
//!
//! This is the "real-hardware tagged integration test on physical M3
//! Max" Jira's QA section asks for. It is macOS-only by construction
//! (`#![cfg(target_os = "macos")]` on the whole file — mirroring
//! `eltanin-linux/tests/linux_integration.rs`'s Linux-only pattern) and
//! is never run by this repository's CI, which has no macOS runner
//! configured (see `.github/workflows/ci.yml`). It is *not* a Feature
//! Verification Record or formal F-M1-010 evidence — that is HORO-1015's
//! scope; this is local developer verification only, run by hand on a
//! real Apple Silicon host.
#![cfg(target_os = "macos")]

use eltanin_apple::probe::run_compute_probe;

#[test]
fn a_trivial_metal_kernel_computes_the_correct_result_on_real_hardware() {
    let report = run_compute_probe()
        .expect("the Metal compute probe must succeed on real Apple Silicon hardware");
    assert!(
        !report.device_name.is_empty(),
        "expected a non-empty Metal device name"
    );
    assert!(
        report.verified_elements > 0,
        "expected at least one verified output element"
    );
    // F-M1-010/HORO-1014's evidence fields, real-hardware-verified (see
    // that ticket's `metal_workload_fixture` bin, which reports these
    // same fields as machine-readable JSON evidence).
    assert_eq!(
        report.verified_elements, report.element_count,
        "every dispatched element must be verified — a partial match would mean the kernel's \
         output was silently accepted as only partially correct"
    );
    // `registryID` is never guaranteed non-zero by Apple's API contract
    // in the abstract, but a real Apple Silicon integrated GPU always
    // reports one — this is the same "verify the real path, don't just
    // assert the fallback" convention `non_macos_fallback.rs` documents.
    assert_ne!(
        report.registry_id, 0,
        "expected a real Metal device to report a non-zero registryID on this hardware"
    );
}

#[test]
fn the_input_hash_is_deterministic_across_independent_probe_runs_on_real_hardware() {
    // Two entirely separate Metal dispatches, each building its own
    // fresh `[0.0, 1.0, ..., 15.0]` input array — this is the actual
    // "Result is deterministic" Acceptance Criterion (HORO-1014),
    // machine-checked against real hardware rather than merely asserted
    // of the hash function in isolation (see `tests/probe_hash.rs` for
    // that hardware-free coverage).
    let first = run_compute_probe().expect("first probe run must succeed on real hardware");
    let second = run_compute_probe().expect("second probe run must succeed on real hardware");
    assert_eq!(
        first.input_hash, second.input_hash,
        "the probe's deterministic input must fingerprint identically across independent runs"
    );
    assert_eq!(
        first.device_name, second.device_name,
        "expected the same default Metal device to be reported on both runs"
    );
}
