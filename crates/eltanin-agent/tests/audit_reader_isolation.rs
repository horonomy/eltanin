//! Architecture test: `eltanin-agent` writes the audit trail and never
//! reads it (F-M1-009, HORO-824). Same blunt lexical-scan idiom as
//! `agent_architecture_guard.rs`: comment lines are stripped, string
//! literals are not specially handled.
//!
//! No edited log line can reach an authorization decision if the code
//! that would decide never even calls the reader. This makes that a
//! mechanically checkable fact, not a review promise.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_READER_API: &[&str] = &["eltanin_audit::explain", "read_log", "Selector"];

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
fn agent_source_never_reads_the_audit_trail() {
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
        for term in FORBIDDEN_READER_API {
            if code_only.contains(term) {
                violations.push(format!(
                    "{}: names forbidden reader API {term:?}",
                    file.display()
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "eltanin-agent must only write the audit trail (eltanin_audit::sink), never read it \
         (eltanin_audit::explain) — an edited log line must never be able to reach an \
         authorization decision, but found:\n{}",
        violations.join("\n")
    );
}
