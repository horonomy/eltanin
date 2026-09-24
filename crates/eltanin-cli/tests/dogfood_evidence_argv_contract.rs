//! Argv grammar coverage for `eltanin dogfood-evidence` (HORO-1376) —
//! mirrors `explain_audit_status_argv_contract.rs`'s own convention for
//! `eltanin audit`'s `--log` grammar exactly, since this command shares
//! the same shape.

use std::ffi::OsString;
use std::path::PathBuf;

use eltanin_cli::args::{parse, parse_dogfood_evidence, Invocation, UsageError};

fn argv(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

#[test]
fn top_level_dispatch_routes_dogfood_evidence() {
    assert!(matches!(
        parse(argv(&["dogfood-evidence"])).unwrap(),
        Invocation::DogfoodEvidence(_)
    ));
}

#[test]
fn dogfood_evidence_with_no_arguments_uses_no_explicit_log_path() {
    let invocation = parse_dogfood_evidence(argv(&["dogfood-evidence"])).unwrap();
    assert_eq!(invocation.log_path, None);
}

#[test]
fn dogfood_evidence_with_log_parses() {
    let invocation =
        parse_dogfood_evidence(argv(&["dogfood-evidence", "--log", "/tmp/audit.log"])).unwrap();
    assert_eq!(invocation.log_path, Some(PathBuf::from("/tmp/audit.log")));
}

#[test]
fn dogfood_evidence_with_missing_log_value_is_rejected() {
    let result = parse_dogfood_evidence(argv(&["dogfood-evidence", "--log"]));
    assert_eq!(result, Err(UsageError::LogMissingValue));
}

#[test]
fn dogfood_evidence_with_unrecognized_argument_is_rejected() {
    let result = parse_dogfood_evidence(argv(&["dogfood-evidence", "--bogus"]));
    assert!(matches!(
        result,
        Err(UsageError::UnrecognizedArgument { .. })
    ));
}

#[test]
fn dogfood_evidence_with_wrong_first_token_is_rejected() {
    let result = parse_dogfood_evidence(argv(&["audit"]));
    assert!(matches!(
        result,
        Err(UsageError::NotDogfoodEvidenceSubcommand { .. })
    ));
}
