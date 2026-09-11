//! Argv grammar coverage for `eltanin run` (F-M1-008, HORO-845).

use std::ffi::OsString;

use eltanin_cli::args::{parse_run, UsageError};

fn argv(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

#[test]
fn a_well_formed_invocation_parses() {
    let invocation = parse_run(argv(&["run", "--profile", "dev", "--", "echo", "hi"])).unwrap();
    assert_eq!(invocation.profile.as_str(), "dev");
    assert_eq!(invocation.program, OsString::from("echo"));
    assert_eq!(invocation.args, vec![OsString::from("hi")]);
}

#[test]
fn a_command_with_no_extra_arguments_parses() {
    let invocation = parse_run(argv(&["run", "--profile", "dev", "--", "true"])).unwrap();
    assert_eq!(invocation.program, OsString::from("true"));
    assert!(invocation.args.is_empty());
}

#[test]
fn missing_run_subcommand_is_rejected() {
    let result = parse_run(argv(&["--profile", "dev", "--", "true"]));
    assert!(matches!(result, Err(UsageError::NotRunSubcommand { .. })));
}

#[test]
fn empty_argv_is_rejected_as_not_run() {
    let result = parse_run(std::iter::empty());
    assert!(matches!(
        result,
        Err(UsageError::NotRunSubcommand { found: None })
    ));
}

#[test]
fn a_bare_word_before_the_separator_is_rejected_as_unrecognized() {
    let result = parse_run(argv(&["run", "--profile", "dev", "true"]));
    assert_eq!(
        result,
        Err(UsageError::UnrecognizedArgument {
            found: OsString::from("true"),
        })
    );
}

#[test]
fn missing_separator_with_nothing_after_profile_is_rejected() {
    let result = parse_run(argv(&["run", "--profile", "dev"]));
    assert_eq!(result, Err(UsageError::MissingSeparator));
}

#[test]
fn empty_command_after_separator_is_rejected() {
    let result = parse_run(argv(&["run", "--profile", "dev", "--"]));
    assert_eq!(result, Err(UsageError::EmptyCommand));
}

#[test]
fn missing_profile_is_rejected() {
    let result = parse_run(argv(&["run", "--", "true"]));
    assert_eq!(result, Err(UsageError::ProfileMissing));
}

#[test]
fn profile_given_twice_is_rejected() {
    let result = parse_run(argv(&[
        "run",
        "--profile",
        "a",
        "--profile",
        "b",
        "--",
        "true",
    ]));
    assert_eq!(result, Err(UsageError::ProfileGivenTwice));
}

#[test]
fn profile_missing_its_value_is_rejected() {
    let result = parse_run(argv(&["run", "--profile"]));
    assert_eq!(result, Err(UsageError::ProfileMissingValue));
}

#[test]
fn a_flag_shaped_argument_after_the_separator_is_passed_through_verbatim() {
    let invocation = parse_run(argv(&[
        "run",
        "--profile",
        "dev",
        "--",
        "grep",
        "--color",
        "-n",
    ]))
    .unwrap();
    assert_eq!(invocation.program, OsString::from("grep"));
    assert_eq!(
        invocation.args,
        vec![OsString::from("--color"), OsString::from("-n")]
    );
}

#[test]
fn a_second_separator_after_the_first_is_a_literal_workload_argument() {
    let invocation = parse_run(argv(&[
        "run",
        "--profile",
        "dev",
        "--",
        "echo",
        "--",
        "literal",
    ]))
    .unwrap();
    assert_eq!(invocation.program, OsString::from("echo"));
    assert_eq!(
        invocation.args,
        vec![OsString::from("--"), OsString::from("literal")]
    );
}

#[test]
fn shell_metacharacters_in_workload_arguments_are_preserved_verbatim_not_reparsed() {
    // No shell is ever invoked (Command::new + argv array, not sh -c),
    // so a string shaped like a shell injection is just a literal
    // argument to the child — never re-parsed. See
    // architecture_no_shell.rs for the mechanical guard on the launch
    // path itself; this test pins that parse_run never does any
    // interpretation of its own.
    let invocation = parse_run(argv(&[
        "run",
        "--profile",
        "dev",
        "--",
        "sh",
        "-c",
        "rm -rf / ; echo pwned",
    ]))
    .unwrap();
    assert_eq!(invocation.program, OsString::from("sh"));
    assert_eq!(
        invocation.args,
        vec![
            OsString::from("-c"),
            OsString::from("rm -rf / ; echo pwned"),
        ]
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_workload_arguments_round_trip_unchanged() {
    use std::os::unix::ffi::OsStringExt;

    let non_utf8 = OsString::from_vec(vec![0x66, 0x6f, 0xff, 0x6f]); // "fo\xFFo"
    let mut items = argv(&["run", "--profile", "dev", "--", "echo"]);
    items.push(non_utf8.clone());

    let invocation = parse_run(items).unwrap();
    assert_eq!(invocation.args, vec![non_utf8]);
}

#[test]
fn an_unrecognized_flag_before_the_separator_is_rejected() {
    let result = parse_run(argv(&["run", "--bogus", "--", "true"]));
    assert_eq!(
        result,
        Err(UsageError::UnrecognizedArgument {
            found: OsString::from("--bogus"),
        })
    );
}
