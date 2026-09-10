//! Architecture tests for `eltanin-backend`: no vendor/platform concept
//! leaks into the trait contract itself, and `eltanin-core` never depends
//! back on this crate (the dependency direction HORO-826's AC requires).
//!
//! The vendor-leak scan intentionally excludes `src/fake.rs` — the
//! deterministic Fake Compute Backend legitimately needs to say "fake,"
//! which is not a forbidden term (see `FORBIDDEN` below); this exclusion
//! exists only so a future real vendor module dropped next to `fake.rs`
//! doesn't accidentally inherit an overly broad exemption.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN: &[&str] = &[
    "nvidia",
    "cuda",
    "cgroup",
    "/dev/nvidia",
    "nvml",
    "bpf_prog_type",
];

fn strip_comment_lines(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn code_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            code_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn backend_contract_names_no_vendor_or_platform_concept() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    code_files(&src_dir, &mut files);
    assert!(
        !files.is_empty(),
        "expected to find eltanin-backend source files to scan"
    );

    let mut violations = Vec::new();
    for file in files {
        let contents = fs::read_to_string(&file).expect("read source file");
        let code_only = strip_comment_lines(&contents).to_lowercase();
        for term in FORBIDDEN {
            if code_only.contains(term) {
                violations.push(format!(
                    "{}: contains forbidden term {term:?}",
                    file.display()
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "eltanin-backend's trait contract must stay vendor/platform-neutral, but found:\n{}",
        violations.join("\n")
    );
}

#[test]
fn eltanin_core_does_not_depend_back_on_eltanin_backend() {
    // Dependency direction: vendor backend -> eltanin-backend -> eltanin-core.
    // eltanin-core must never depend on eltanin-backend (Cargo itself would
    // refuse a real cycle, but this also catches a stray reference in
    // eltanin-core's own source, e.g. a doc example that imports it).
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let core_manifest = fs::read_to_string(workspace_root.join("crates/eltanin-core/Cargo.toml"))
        .expect("read eltanin-core Cargo.toml");
    assert!(
        !core_manifest.contains("eltanin-backend"),
        "eltanin-core/Cargo.toml must not depend on eltanin-backend"
    );

    let mut core_src_files = Vec::new();
    code_files(
        &workspace_root.join("crates/eltanin-core/src"),
        &mut core_src_files,
    );
    for file in core_src_files {
        let contents = fs::read_to_string(&file).expect("read eltanin-core source file");
        assert!(
            !contents.to_lowercase().contains("eltanin_backend")
                && !contents.to_lowercase().contains("eltanin-backend"),
            "{} references eltanin-backend, violating dependency direction",
            file.display()
        );
    }
}
