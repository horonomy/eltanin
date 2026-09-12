//! macOS integration coverage (F-M1-010, HORO-1013 — mirrors
//! `crates/eltanin-linux/tests/linux_integration.rs`). This test
//! exercises the real `libproc` collection path against this test
//! binary's own process — it only meaningfully validates real macOS
//! kernel behavior when run on macOS (this repo's `macos-latest` CI); on
//! any other `target_os` it validates the documented `Unsupported`
//! fallback instead, so the test still compiles and passes on a
//! Linux/Windows dev machine.

use eltanin_core::identity::Evidence;
use eltanin_macos::{collect_execution_context, collect_workload_identity};

#[test]
fn self_pid_round_trip_is_internally_consistent() {
    let pid = std::process::id();
    let identity = collect_workload_identity(pid);
    assert_eq!(identity.pid, pid);

    let ctx = collect_execution_context(pid);
    assert_eq!(ctx.workload.pid, pid);

    #[cfg(target_os = "macos")]
    {
        // Two independent collections of the same still-running process
        // must observe the same start token — this is exactly the
        // signal `IdentityComparison::compare_process` relies on to
        // distinguish a live process from PID reuse.
        let identity_again = collect_workload_identity(pid);
        assert_eq!(
            identity.process_start, identity_again.process_start,
            "same live process must report a stable start token across collections"
        );
        assert!(identity.uid.is_present());
        assert!(identity.executable_path.is_present());
    }

    #[cfg(not(target_os = "macos"))]
    {
        assert!(matches!(identity.process_start, Evidence::Unsupported));
        assert!(matches!(ctx.cgroup_path, Evidence::Unsupported));
    }
}

#[test]
fn two_collections_of_same_process_compare_as_same() {
    use eltanin_core::identity::IdentityComparison;

    let pid = std::process::id();
    let first = collect_workload_identity(pid);
    let second = collect_workload_identity(pid);

    #[cfg(target_os = "macos")]
    assert_eq!(first.compare_process(&second), IdentityComparison::Same);

    #[cfg(not(target_os = "macos"))]
    assert_eq!(
        first.compare_process(&second),
        IdentityComparison::Indeterminate
    );
}

/// Mirrors `eltanin-linux`'s own PID-reuse/exit-race regression test
/// (HORO-833 AC): spawns a real child process, waits for it to fully
/// exit and be reaped, then collects on its now-stale PID. Must never
/// panic and must never fabricate a live identity for a process that is
/// actually gone.
#[cfg(target_os = "macos")]
#[test]
fn exited_child_process_reports_missing_or_a_genuinely_different_process() {
    use std::process::Command;

    let mut child = Command::new("/usr/bin/true")
        .spawn()
        .expect("spawning a short-lived child process must succeed on macOS CI");
    let pid = child.id();
    child.wait().expect("reaping the child must succeed");

    // The child has fully exited and been reaped. Collecting on its old
    // PID must never panic. Either the PID is now unoccupied (Missing,
    // the expected outcome) or the kernel has already reused it for an
    // unrelated real process (Present) — both are safe, non-fabricated
    // answers; only a panic or a value that impersonates the exited
    // child would be unsafe.
    let identity = collect_workload_identity(pid);
    match &identity.process_start {
        Evidence::Missing { reason } => assert!(!reason.is_empty()),
        Evidence::Present { .. } => {
            // PID already reused by a different real process — the
            // collector is reporting that real occupant, not the
            // exited child, which is exactly the safe behavior.
        }
        Evidence::Unsupported => panic!("a macOS build must never report Unsupported"),
    }
}
