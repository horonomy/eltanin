//! Architecture test: `eltanin-agent` is transport/runtime only
//! (F-M1-006, HORO-839) — it must never name `eltanin-core`'s
//! policy/lease *evaluation* API, and its source must contain no
//! `unsafe` code. Same blunt lexical-scan idiom as
//! `eltanin-core`'s `architecture_no_vendor_leak.rs` and
//! `eltanin-protocol`'s `protocol_no_self_asserted_identity.rs`:
//! comment lines are stripped, string literals are not specially
//! handled.
//!
//! HORO-840 implements policy evaluation and lease issue/release
//! *behind* [`eltanin_agent::handler::RequestHandler`] — in its own
//! code, not this crate's. This test makes that boundary mechanically
//! checkable rather than a review promise.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_PRODUCT_LOGIC: &[&str] = &[
    "PolicySet",
    "PolicyDecision",
    "PolicyDocument",
    "LeaseIssuer",
    "ComputeLease",
    ".evaluate(",
    ".issue(",
    ".revoke(",
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
fn agent_source_never_names_policy_or_lease_evaluation_logic() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    code_files(&src_dir, &mut files);
    assert!(
        !files.is_empty(),
        "expected to find eltanin-agent source files to scan"
    );

    let mut violations = Vec::new();
    for file in &files {
        let contents = fs::read_to_string(file).expect("read source file");
        let code_only = strip_comment_lines(&contents);
        for term in FORBIDDEN_PRODUCT_LOGIC {
            if code_only.contains(term) {
                violations.push(format!(
                    "{}: names forbidden product logic {term:?}",
                    file.display()
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "eltanin-agent must stay transport/runtime only — policy evaluation and lease \
         issue/revoke belong behind RequestHandler in HORO-840's own crate/module, but found:\n{}",
        violations.join("\n")
    );
}

#[test]
fn agent_source_contains_no_unsafe_code() {
    // Belt-and-suspenders alongside #![forbid(unsafe_code)] in lib.rs:
    // this also catches an `unsafe` block appearing anywhere the forbid
    // attribute wouldn't apply (e.g. a future submodule that
    // accidentally overrides it with `#[allow(unsafe_code)]`).
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    code_files(&src_dir, &mut files);

    let mut violations = Vec::new();
    for file in &files {
        let contents = fs::read_to_string(file).expect("read source file");
        for line in strip_comment_lines(&contents).lines() {
            let trimmed = line.trim_start();
            // Exclude `#![forbid(unsafe_code)]`/`#[allow(unsafe_code)]`
            // style attribute lines — they *name* the word as a lint
            // identifier, not as the `unsafe` keyword introducing a
            // block/fn/impl/trait.
            if trimmed.starts_with('#') {
                continue;
            }
            if line.contains("unsafe") {
                violations.push(format!("{}: {trimmed}", file.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "eltanin-agent must contain no unsafe code (SO_PEERCRED access is isolated in \
         eltanin-linux via the safe rustix wrapper), but found it in:\n{}",
        violations.join("\n")
    );
}
