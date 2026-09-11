//! Architecture tests for `eltanin-audit`: no vendor/platform concept
//! leaks into the schema, and this crate never depends on
//! `eltanin-linux` or `eltanin-agent` — the dependency direction
//! `src/lib.rs`'s own docs require (`eltanin-agent`'s daemon binary
//! selects this crate's sink, so the reverse dependency would be a
//! cycle; the platform independence is also what keeps this crate
//! portable to a future non-Linux transport, per HORO-788's own
//! requirement).

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN: &[&str] = &["nvidia", "cuda", "/dev/nvidia", "nvml", "bpf_prog_type"];

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
fn audit_schema_names_no_vendor_or_platform_concept() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    code_files(&src_dir, &mut files);
    assert!(
        !files.is_empty(),
        "expected to find eltanin-audit source files to scan"
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
        "eltanin-audit's schema must stay vendor/platform-neutral, but found:\n{}",
        violations.join("\n")
    );
}

#[test]
fn eltanin_audit_never_depends_on_eltanin_linux_or_eltanin_agent() {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("read eltanin-audit Cargo.toml");
    let lower = manifest.to_lowercase();
    assert!(
        !lower.contains("eltanin-linux") && !lower.contains("eltanin_linux"),
        "eltanin-audit must not depend on eltanin-linux — the peer-credential mirrors in \
         src/record.rs are plain data precisely so this dependency is unnecessary"
    );
    assert!(
        !lower.contains("eltanin-agent") && !lower.contains("eltanin_agent"),
        "eltanin-audit must not depend on eltanin-agent — that would be a dependency cycle, \
         since eltanin-agent's daemon binary selects this crate's sink"
    );
}
