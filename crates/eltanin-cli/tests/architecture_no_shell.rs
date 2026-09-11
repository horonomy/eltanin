//! Architecture guard: `eltanin-cli` never invokes a shell to launch the
//! workload (F-M1-008, HORO-845). The security requirement is "exact
//! argv semantics avoid shell re-parsing/injection" — the mechanical
//! check is that no source file in this crate names a shell interpreter
//! or `libc::system`.

use std::fs;
use std::path::Path;

const FORBIDDEN_PATTERNS: &[&str] = &[
    "sh -c", "\"sh\"", "'sh'", "/bin/sh", "bash -c", "\"bash\"", "system(",
];

fn scan_dir(dir: &Path, violations: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_dir(&path, violations);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        for pattern in FORBIDDEN_PATTERNS {
            if contents.contains(pattern) {
                violations.push(format!("{}: contains {pattern:?}", path.display()));
            }
        }
    }
}

#[test]
fn eltanin_cli_source_never_names_a_shell_interpreter_or_system_call() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut violations = Vec::new();
    scan_dir(&src, &mut violations);
    assert!(
        violations.is_empty(),
        "eltanin-cli must launch the workload via an explicit argv array (Command::new), \
         never a shell — found: {violations:?}"
    );
}
