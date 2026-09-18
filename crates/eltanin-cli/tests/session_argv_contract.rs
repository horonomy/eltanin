//! Argv grammar coverage for `eltanin session start|list|end` (F-M2-001,
//! HORO-791). `eltanin run`'s own grammar is covered unchanged by
//! `argv_contract.rs` — nothing here touches it.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use eltanin_cli::args::{parse, parse_session, Invocation, SessionInvocation, UsageError};

fn argv(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

#[test]
fn top_level_dispatch_routes_run_to_run_invocation() {
    let invocation = parse(argv(&["run", "--profile", "dev", "--", "true"])).unwrap();
    assert!(matches!(invocation, Invocation::Run(_)));
}

#[test]
fn top_level_dispatch_routes_session_to_session_invocation() {
    let invocation = parse(argv(&["session", "list"])).unwrap();
    assert!(matches!(
        invocation,
        Invocation::Session(SessionInvocation::List)
    ));
}

#[test]
fn an_unknown_top_level_subcommand_is_rejected() {
    let result = parse(argv(&["frobnicate"]));
    assert!(matches!(result, Err(UsageError::UnknownSubcommand { .. })));
}

#[test]
fn empty_argv_is_rejected_as_unknown_subcommand() {
    let result = parse(std::iter::empty());
    assert_eq!(result, Err(UsageError::UnknownSubcommand { found: None }));
}

#[test]
fn session_start_with_one_profile_and_ttl_parses() {
    let invocation = parse_session(argv(&[
        "session",
        "start",
        "--profile",
        "dev",
        "--ttl",
        "2h",
    ]))
    .unwrap();
    assert_eq!(
        invocation,
        SessionInvocation::Start {
            profiles: vec![
                eltanin_cli::profile::ProfileName::parse(&OsString::from("dev")).unwrap()
            ],
            ttl: Duration::from_hours(2),
        }
    );
}

#[test]
fn session_start_unions_repeated_profile_flags() {
    let invocation = parse_session(argv(&[
        "session",
        "start",
        "--profile",
        "a",
        "--profile",
        "b",
        "--ttl",
        "30m",
    ]))
    .unwrap();
    let SessionInvocation::Start { profiles, ttl } = invocation else {
        panic!("expected Start");
    };
    assert_eq!(profiles.len(), 2);
    assert_eq!(ttl, Duration::from_mins(30));
}

#[test]
fn session_start_accepts_bare_seconds() {
    let invocation = parse_session(argv(&[
        "session",
        "start",
        "--profile",
        "dev",
        "--ttl",
        "3600",
    ]))
    .unwrap();
    let SessionInvocation::Start { ttl, .. } = invocation else {
        panic!("expected Start");
    };
    assert_eq!(ttl, Duration::from_secs(3600));
}

#[test]
fn session_start_accepts_bare_seconds_with_s_suffix() {
    let invocation = parse_session(argv(&[
        "session",
        "start",
        "--profile",
        "dev",
        "--ttl",
        "45s",
    ]))
    .unwrap();
    let SessionInvocation::Start { ttl, .. } = invocation else {
        panic!("expected Start");
    };
    assert_eq!(ttl, Duration::from_secs(45));
}

#[test]
fn session_start_requires_at_least_one_profile() {
    let result = parse_session(argv(&["session", "start", "--ttl", "1h"]));
    assert_eq!(result, Err(UsageError::ProfileMissing));
}

#[test]
fn session_start_requires_a_ttl() {
    let result = parse_session(argv(&["session", "start", "--profile", "dev"]));
    assert_eq!(result, Err(UsageError::TtlMissing));
}

#[test]
fn session_start_rejects_an_invalid_ttl() {
    let result = parse_session(argv(&[
        "session",
        "start",
        "--profile",
        "dev",
        "--ttl",
        "banana",
    ]));
    assert_eq!(
        result,
        Err(UsageError::InvalidTtl {
            found: OsString::from("banana")
        })
    );
}

#[test]
fn session_start_rejects_ttl_given_twice() {
    let result = parse_session(argv(&[
        "session",
        "start",
        "--profile",
        "dev",
        "--ttl",
        "1h",
        "--ttl",
        "2h",
    ]));
    assert_eq!(result, Err(UsageError::TtlGivenTwice));
}

#[test]
fn session_list_parses_with_no_arguments() {
    assert_eq!(
        parse_session(argv(&["session", "list"])),
        Ok(SessionInvocation::List)
    );
}

#[test]
fn session_end_parses_with_no_arguments() {
    assert_eq!(
        parse_session(argv(&["session", "end"])),
        Ok(SessionInvocation::End)
    );
}

#[test]
fn session_list_rejects_extra_arguments() {
    let result = parse_session(argv(&["session", "list", "extra"]));
    assert!(matches!(
        result,
        Err(UsageError::UnexpectedSessionArgument { action: "list", .. })
    ));
}

#[test]
fn session_takes_no_arbitrary_id_argument_anywhere() {
    // AC2/enumeration-resistance guard at the argv layer: there is no
    // grammar path that accepts a session id at all for `end` or
    // `list` — any extra token is rejected outright, never silently
    // accepted as an id.
    let result = parse_session(argv(&["session", "end", "some-session-id"]));
    assert!(matches!(
        result,
        Err(UsageError::UnexpectedSessionArgument { action: "end", .. })
    ));
}

#[test]
fn an_unknown_session_action_is_rejected() {
    let result = parse_session(argv(&["session", "pause"]));
    assert!(matches!(
        result,
        Err(UsageError::UnknownSessionAction { .. })
    ));
}

#[test]
fn missing_session_subcommand_is_rejected() {
    let result = parse_session(argv(&["run"]));
    assert!(matches!(
        result,
        Err(UsageError::NotSessionSubcommand { .. })
    ));
}

/// Recursively list every path under `dir`, sorted, for a before/after
/// filesystem-side-effect comparison — used by
/// `session_start_persists_no_client_side_credential` below.
fn snapshot_dir(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut entries = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(read_dir) = fs::read_dir(&current) else {
            continue;
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path.clone());
            }
            entries.push(path);
        }
    }
    entries.sort();
    entries
}

/// Machine-asserts HORO-1278's core design decision: `eltanin session
/// start` is byte-for-byte unchanged at the CLI layer — no new flag, no
/// persisted file/token/env var. `HOME`/every `XDG_*` directory/`TMPDIR`
/// are all pointed at one empty, private scratch directory, so *any*
/// client-side write this command might make (a credential file, a
/// cache, a lockfile) would land somewhere under it — this asserts the
/// directory tree is byte-identical before and after the command runs,
/// and that stdout carries no token/credential-shaped value. Does not
/// require a running `eltanin-agentd` — the command is expected to fail
/// with `AgentUnavailable`/`ProfileUnresolved` in this hermetic
/// environment; the assertion is about filesystem side effects and
/// stdout shape, not about the command's exit status.
#[test]
fn session_start_persists_no_client_side_credential() {
    use std::os::unix::fs::PermissionsExt;

    let real_tmp = fs::canonicalize("/tmp").unwrap_or_else(|_| PathBuf::from("/tmp"));
    let scratch = real_tmp.join(format!(
        "eltanin-cli-session-start-no-credential-{}",
        std::process::id()
    ));
    fs::create_dir_all(&scratch).expect("create scratch dir");
    fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700))
        .expect("chmod scratch dir private");

    let before = snapshot_dir(&scratch);
    assert!(
        before.is_empty(),
        "expected a freshly created scratch dir to start empty, got {before:?}"
    );

    let eltanin = PathBuf::from(env!("CARGO_BIN_EXE_eltanin"));
    let output = Command::new(&eltanin)
        .env("HOME", &scratch)
        .env("XDG_CONFIG_HOME", &scratch)
        .env("XDG_DATA_HOME", &scratch)
        .env("XDG_STATE_HOME", &scratch)
        .env("XDG_CACHE_HOME", &scratch)
        .env("TMPDIR", &scratch)
        .env_remove("ELTANIN_PROFILE_DIR")
        .env_remove("ELTANIN_AGENT_SOCKET")
        .args([
            "session",
            "start",
            "--profile",
            "no-such-profile",
            "--ttl",
            "1h",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run `eltanin session start`");

    let after = snapshot_dir(&scratch);
    assert_eq!(
        before, after,
        "[HORO-1278] `eltanin session start` must persist no client-side file of any kind — \
         the entire fix is agent-side; no client-held session credential exists by design. \
         Directory contents changed: before={before:?} after={after:?}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lower = stdout.to_lowercase();
    assert!(
        !lower.contains("token") && !lower.contains("credential") && !lower.contains("secret"),
        "[HORO-1278] `eltanin session start`'s stdout must never carry a token/credential-shaped \
         value — got: {stdout:?}"
    );
}
