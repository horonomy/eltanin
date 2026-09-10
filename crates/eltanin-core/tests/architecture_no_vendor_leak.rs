//! Architecture test: no vendor/platform concept may leak into
//! `eltanin-core`'s actual code (as opposed to its documentation, which
//! is allowed to *name* what's forbidden — see the module docs in
//! `resource.rs`). See `docs/product/PRODUCT_CONSTITUTION.md`'s
//! "vendor-neutral core, vendor-specific adapters" rule and HORO-825's
//! acceptance criterion: "Architecture test/review rule catches
//! vendor-specific concepts leaking into core."
//!
//! This is a blunt lexical check, not a full parser: it strips comment
//! lines (`//`, `///`, `//!`) and string literals are not specially
//! handled (a code string containing a forbidden word would also be
//! flagged) — that's a feature, not a gap, since a domain type should
//! never need such a string either.

use std::fs;
use std::path::Path;

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

fn code_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
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
fn core_source_names_no_vendor_or_platform_concept() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    code_files(&src_dir, &mut files);
    assert!(
        !files.is_empty(),
        "expected to find eltanin-core source files to scan"
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
        "eltanin-core must stay vendor/platform-neutral, but found:\n{}",
        violations.join("\n")
    );
}
