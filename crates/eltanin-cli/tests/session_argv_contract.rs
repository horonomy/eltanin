//! Argv grammar coverage for `eltanin session start|list|end` (F-M2-001,
//! HORO-791). `eltanin run`'s own grammar is covered unchanged by
//! `argv_contract.rs` — nothing here touches it.

use std::ffi::OsString;
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
