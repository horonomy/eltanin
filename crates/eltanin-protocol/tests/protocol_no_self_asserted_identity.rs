//! Architecture test: no wire *message* type may carry an identity or
//! evidence field, and this crate must never construct self-asserted
//! identity evidence (F-M1-006, HORO-838). Same blunt lexical-scan idiom
//! as `eltanin-core`'s `architecture_no_vendor_leak.rs` — deliberately
//! not a full parser; comment lines are stripped, string literals are
//! not specially handled.
//!
//! [`eltanin_protocol::request::provenance_for`] is the one sanctioned
//! exception: its whole purpose is to accept an agent-derived
//! `ExecutionContext` and produce a `ProvenanceRecord` from it (see its
//! own doc comment). This test excludes that one function body/signature
//! from the scan and checks everything else in the crate — in
//! particular every `struct`/`enum` field declaration, which is what
//! actually reaches the wire.

use std::fs;
use std::path::{Path, PathBuf};

// Types no wire *message* declaration may name as a field type. Checked
// against the crate's source with `provenance_for`'s own
// signature/body excluded (see module docs).
const FORBIDDEN_TYPES: &[&str] = &[
    "WorkloadIdentity",
    "ExecutionContext",
    "Evidence<",
    "ProvenanceRecord",
    "ComputeLease",
    "PolicyDecision",
    "LeaseValidity",
];

const FORBIDDEN_CONSTRUCTS: &[&str] = &["SelfAsserted"];

fn strip_comment_lines(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `use` statements legitimately import `ExecutionContext`/
/// `ProvenanceRecord` for `provenance_for`'s signature — not a wire-type
/// field declaration, so not what this test is checking for.
fn strip_use_lines(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Removes the `pub fn provenance_for` function (signature through its
/// matching closing brace) from `source`, by simple brace counting. Not
/// a general-purpose Rust parser — relies on `provenance_for` being the
/// only function whose signature spans the `fn` keyword to its opening
/// `{` without any nested `{`/`}` in between, which is true for its
/// current one-line signature.
fn strip_provenance_for(source: &str) -> String {
    let Some(start) = source.find("pub fn provenance_for") else {
        return source.to_string();
    };
    let Some(open_offset) = source[start..].find('{') else {
        return source.to_string();
    };
    let open = start + open_offset;
    let mut depth = 0usize;
    let mut end = open;
    for (i, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    format!("{}{}", &source[..start], &source[end..])
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
fn protocol_wire_types_never_name_derived_identity_or_authority_types() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    code_files(&src_dir, &mut files);
    assert!(
        !files.is_empty(),
        "expected to find eltanin-protocol source files to scan"
    );

    let mut violations = Vec::new();
    for file in files {
        let contents = fs::read_to_string(&file).expect("read source file");
        let code_only = strip_provenance_for(&strip_use_lines(&strip_comment_lines(&contents)));
        for term in FORBIDDEN_TYPES {
            if code_only.contains(term) {
                violations.push(format!("{}: names forbidden type {term:?}", file.display()));
            }
        }
        for term in FORBIDDEN_CONSTRUCTS {
            if code_only.contains(term) {
                violations.push(format!(
                    "{}: constructs forbidden evidence source {term:?}",
                    file.display()
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "eltanin-protocol's wire types must carry no identity/evidence field and \
         construct no self-asserted evidence outside provenance_for, but found:\n{}",
        violations.join("\n")
    );
}

#[test]
fn provenance_for_is_actually_present_and_is_the_only_exempted_function() {
    // Guards the guard: if provenance_for is ever renamed/removed, the
    // strip_provenance_for helper above would silently stop excluding
    // anything and the main test would start failing on its own
    // legitimate signature — which is the right failure mode, but this
    // makes the dependency explicit rather than discovered by a
    // confusing failure in the other test.
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let request_rs = fs::read_to_string(src_dir.join("request.rs")).unwrap();
    assert!(
        request_rs.contains("pub fn provenance_for"),
        "expected eltanin_protocol::request::provenance_for to exist"
    );
}
