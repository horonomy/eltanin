//! HORO-1618: `--help`/`-h` must never reach `eltanin run`'s actual launch
//! path. `root_help_version.rs` already covers root `--help`/`-V` by output
//! text; this file instruments the real side effect `launch::run` would
//! cause (spawning the given program) rather than only inspecting stdout,
//! so a regression that let a `--help`-shaped invocation fall through to
//! `launch::run` would fail this test even if it still printed something
//! help-shaped on its way there.
//!
//! The marker program is a real `touch <marker-file>` — if `launch::run`
//! ever executes it, the marker file appears; every case here asserts it
//! does not.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_eltanin"))
}

/// A fresh, unique scratch directory per call -- avoids a new dependency
/// (`tempfile`) for a single-use marker path; cleaned up on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "eltanin-help-purity-test-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_marker_not_created(args: &[&str]) {
    let scratch = ScratchDir::new();
    let marker = scratch.path().join("launched");

    let output = Command::new(bin())
        .args(args)
        .arg(marker.to_str().expect("utf8 scratch path"))
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn eltanin {args:?}: {e}"));

    assert!(
        !marker.exists(),
        "{args:?} launched the workload (marker file created) instead of \
         exiting through help/parser logic; stdout={:?} stderr={:?}",
        output.stdout,
        output.stderr
    );
}

#[test]
fn root_help_before_a_full_run_invocation_never_launches_anything() {
    // argv[0] is "--help", so everything after it is irrelevant to parsing --
    // but prove it's also irrelevant to *execution*, not just to the stdout
    // this test's sibling already checks.
    assert_marker_not_created(&["--help", "run", "--profile", "x", "--", "touch"]);
}

#[test]
fn run_help_is_an_unrecognized_argument_and_never_launches_anything() {
    // "run" is argv[0] here, so the root --help check (which only looks at
    // argv[0]) never fires; this exercises parse_run's own rejection of
    // "--help" as an unrecognized argument instead, which is the actual
    // invariant worth a regression test -- a future refactor could plausibly
    // special-case "--help" inside parse_run without reasoning about
    // launch::run at all.
    assert_marker_not_created(&["run", "--help", "--profile", "x", "--", "touch"]);
}

#[test]
fn trailing_help_after_profile_never_launches_anything() {
    assert_marker_not_created(&["run", "--profile", "x", "--help", "--", "touch"]);
}
