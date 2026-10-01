//! Root `--help`/`--version` contract for the real `eltanin` binary
//! (HORO-1615, ADR-0013 §1). Before this, neither flag existed: both fell
//! into the generic "unknown or missing subcommand"-shaped usage error.

use std::process::Command;

fn bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_eltanin"))
}

#[test]
fn help_flags_exit_zero_and_print_usage() {
    for flag in ["--help", "-h"] {
        let output = Command::new(bin())
            .arg(flag)
            .output()
            .expect("spawn eltanin");
        assert!(output.status.success(), "{flag} should exit 0");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("eltanin"), "{flag}: {stdout}");
        assert!(stdout.contains("Usage:"), "{flag}: {stdout}");
        assert!(stdout.contains("eltanin run"), "{flag}: {stdout}");
    }
}

#[test]
fn version_flags_exit_zero_and_print_cargo_pkg_version() {
    for flag in ["--version", "-V"] {
        let output = Command::new(bin())
            .arg(flag)
            .output()
            .expect("spawn eltanin");
        assert!(output.status.success(), "{flag} should exit 0");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            stdout.trim(),
            format!("eltanin {}", env!("CARGO_PKG_VERSION"))
        );
    }
}

/// Anti-vacuity: an unknown first argument must still fail closed (exit 64,
/// the pre-existing usage-error code), distinct from the two success paths
/// above, and must never panic.
#[test]
fn unknown_first_argument_still_fails_closed() {
    let output = Command::new(bin())
        .arg("not-a-real-subcommand")
        .output()
        .expect("spawn eltanin");
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "must not panic: {stderr}");
}

/// HORO-1615 (ADR-0013 §5): the usage-error message used to interpolate the
/// offending argument unwrapped via Rust's `{:?}` (Debug) formatting, so its
/// length scaled directly with the argument's length -- a genuinely
/// unbounded line, independent of terminal width. Confirm it's now bounded
/// and no longer leaks the `Some("...")` Debug wrapper.
#[test]
fn unknown_argument_error_message_is_bounded_and_does_not_leak_debug_formatting() {
    let long_arg = "x".repeat(500);
    let output = Command::new(bin())
        .arg(&long_arg)
        .output()
        .expect("spawn eltanin");

    assert_eq!(output.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.len() < 250,
        "error message must be bounded regardless of argument length: {} bytes",
        stderr.len()
    );
    assert!(
        !stderr.contains("Some("),
        "must not leak Option's Debug wrapper into user-facing text: {stderr}"
    );
}
