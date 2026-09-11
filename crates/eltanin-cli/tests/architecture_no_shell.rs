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

fn find_spawn_call_sites(dir: &Path, sites: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            find_spawn_call_sites(&path, sites);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        if contents.contains(".spawn(") {
            sites.push(path.display().to_string());
        }
    }
}

/// "Never start the workload before an observed `LeaseGranted`"
/// (HORO-823's security requirement) is provable exactly because
/// there is exactly one `Command::spawn` call site in this crate, and
/// it's textually and control-flow-wise inside `launch::run`'s
/// `LeaseGranted` match arm — not because of an injected `Spawner`
/// seam production code doesn't otherwise need.
#[test]
fn there_is_exactly_one_command_spawn_call_site() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sites = Vec::new();
    find_spawn_call_sites(&src, &mut sites);
    assert_eq!(
        sites,
        vec![src.join("launch.rs").display().to_string()],
        "expected exactly one Command::spawn call site, in launch.rs — found: {sites:?}"
    );
}
