//! Architecture test: the canonical protocol layer must stay platform-
//! neutral (F-M1-006, HORO-838) — no Unix-socket, Windows-named-pipe, or
//! raw-syscall concept may leak into `eltanin-protocol`'s code. Actual
//! transport implementation (opening a `UnixListener`, reading
//! `SO_PEERCRED`) belongs to HORO-839, in a different crate entirely.
//! Same blunt lexical-scan idiom as `eltanin-core`'s
//! `architecture_no_vendor_leak.rs`: comment lines are stripped
//! (allowing the module docs to *name* "Unix domain socket" / "Windows
//! named pipe" freely), string literals are not specially handled.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN: &[&str] = &[
    "unix",
    "socket",
    "peercred",
    "libc",
    "nix::",
    "windows",
    "named_pipe",
    "linux",
    "/proc",
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
fn protocol_source_names_no_transport_or_platform_mechanism() {
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
        let code_only = strip_comment_lines(&contents).to_lowercase();
        for term in FORBIDDEN {
            if code_only.contains(term) {
                violations.push(format!(
                    "{}: contains forbidden platform/transport term {term:?}",
                    file.display()
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "eltanin-protocol must stay platform-neutral at the canonical layer, but found:\n{}",
        violations.join("\n")
    );
}
