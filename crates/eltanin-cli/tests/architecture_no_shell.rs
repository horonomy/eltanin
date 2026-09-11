//! Architecture guard: `eltanin-cli` never invokes a shell to launch the
//! workload (F-M1-008, HORO-845/846). The security requirement is
//! "exact argv semantics avoid shell re-parsing/injection" — these are
//! mechanical, literal-substring heuristic checks (no source file names
//! a known shell interpreter or `libc::system`), not a formal proof: a
//! sufficiently indirect construction (a dynamically built string, an
//! unlisted shell, `CommandExt::exec`, `Command::status`/`output`) could
//! defeat them. They catch the direct, common-case violation; they are
//! not a substitute for review of any new process-launching code.

use std::fs;
use std::path::Path;

const FORBIDDEN_PATTERNS: &[&str] = &[
    "sh -c", "\"sh\"", "'sh'", "/bin/sh", "bash -c", "\"bash\"", "zsh -c", "\"zsh\"", "ksh -c",
    "dash -c", "ash -c", "csh -c", "tcsh -c", "system(",
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

/// Mechanical, heuristic check supporting "never start the workload
/// before an observed `LeaseGranted`" (HORO-823's security
/// requirement): today, there is exactly one literal `.spawn(` call
/// site in this crate, and it's textually and control-flow-wise inside
/// `launch::run`'s `LeaseGranted` match arm. This is a substring match,
/// not a proof — a future process-launch path added via
/// `Command::status`/`output` or `CommandExt::exec` would not contain
/// `.spawn(` and would pass this test silently. Any new
/// process-launching code must be reviewed against the same invariant
/// by hand; this guard only catches the common-case regression of a
/// second `.spawn(` call site appearing outside `launch.rs`.
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
