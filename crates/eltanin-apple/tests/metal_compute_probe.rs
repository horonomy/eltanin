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
}
