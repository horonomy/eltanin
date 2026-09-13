//! Argv grammar coverage for `eltanin approve` (F-M2-002, HORO-792).
//! `eltanin run`/`eltanin session ...`'s own grammars are covered
//! unchanged by `argv_contract.rs`/`session_argv_contract.rs` — nothing
//! here touches either.

use std::ffi::OsString;

use eltanin_cli::args::{parse, parse_approve, ApproveInvocation, Invocation, UsageError};
use eltanin_core::approval::ApprovalDisposition;

fn argv(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

#[test]
fn top_level_dispatch_routes_approve_to_approve_invocation() {
    let invocation = parse(argv(&["approve", "list"])).unwrap();
    assert!(matches!(
        invocation,
        Invocation::Approve(ApproveInvocation::List)
    ));
}

#[test]
fn approve_with_profile_and_remember_parses() {
    let invocation = parse_approve(argv(&["approve", "--profile", "dev", "--remember"])).unwrap();
    assert_eq!(
        invocation,
        ApproveInvocation::Record {
            profile: eltanin_cli::profile::ProfileName::parse(&OsString::from("dev")).unwrap(),
            disposition: ApprovalDisposition::Remember,
        }
    );
}

#[test]
fn approve_with_profile_and_once_parses() {
    let invocation = parse_approve(argv(&["approve", "--profile", "dev", "--once"])).unwrap();
    assert_eq!(
        invocation,
        ApproveInvocation::Record {
            profile: eltanin_cli::profile::ProfileName::parse(&OsString::from("dev")).unwrap(),
            disposition: ApprovalDisposition::Once,
        }
    );
}

#[test]
fn approve_with_profile_and_deny_parses() {
    let invocation = parse_approve(argv(&["approve", "--profile", "dev", "--deny"])).unwrap();
    assert_eq!(
        invocation,
        ApproveInvocation::Record {
            profile: eltanin_cli::profile::ProfileName::parse(&OsString::from("dev")).unwrap(),
            disposition: ApprovalDisposition::Deny,
        }
    );
}

#[test]
fn approve_list_parses() {
    let invocation = parse_approve(argv(&["approve", "list"])).unwrap();
    assert_eq!(invocation, ApproveInvocation::List);
}

#[test]
fn approve_forget_with_id_parses() {
    let invocation = parse_approve(argv(&["approve", "forget", "abc123"])).unwrap();
    assert_eq!(
        invocation,
        ApproveInvocation::Forget {
            id: eltanin_core::approval::ApprovalId::from_raw("abc123")
        }
    );
}

#[test]
fn approve_forget_with_no_id_is_rejected() {
    let result = parse_approve(argv(&["approve", "forget"]));
    assert_eq!(result, Err(UsageError::ForgetIdMissing));
}

#[test]
fn approve_forget_with_extra_argument_is_rejected() {
    let result = parse_approve(argv(&["approve", "forget", "abc123", "extra"]));
    assert!(matches!(
        result,
        Err(UsageError::UnexpectedApproveArgument { .. })
    ));
}

#[test]
fn approve_with_no_disposition_is_rejected() {
    let result = parse_approve(argv(&["approve", "--profile", "dev"]));
    assert_eq!(result, Err(UsageError::DispositionMissing));
}

#[test]
fn approve_with_two_dispositions_is_rejected() {
    let result = parse_approve(argv(&[
        "approve",
        "--profile",
        "dev",
        "--once",
        "--remember",
    ]));
    assert_eq!(result, Err(UsageError::DispositionGivenTwice));
}

#[test]
fn approve_with_no_profile_is_rejected() {
    let result = parse_approve(argv(&["approve", "--remember"]));
    assert_eq!(result, Err(UsageError::ProfileMissing));
}

#[test]
fn approve_with_profile_given_twice_is_rejected() {
    let result = parse_approve(argv(&[
        "approve",
        "--profile",
        "dev",
        "--profile",
        "dev2",
        "--remember",
    ]));
    assert_eq!(result, Err(UsageError::ProfileGivenTwice));
}

#[test]
fn an_unrecognized_approve_flag_is_rejected() {
    let result = parse_approve(argv(&["approve", "--bogus"]));
    assert!(matches!(
        result,
        Err(UsageError::UnrecognizedArgument { .. })
    ));
}
