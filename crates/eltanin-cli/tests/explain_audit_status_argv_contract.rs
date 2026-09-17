//! Argv grammar coverage for `eltanin explain`/`eltanin audit`/`eltanin
//! status` (F-M2-006, HORO-796 subtask 4). `eltanin run`/`session`/
//! `approve`'s own grammars are covered unchanged by their own
//! `*_argv_contract.rs` files — nothing here touches any of them.

use std::ffi::OsString;
use std::path::PathBuf;

use eltanin_audit::explain::Selector;
use eltanin_audit::record::AuditEventId;
use eltanin_cli::args::{
    parse, parse_audit, parse_explain, parse_status, Invocation, UsageError,
    DEFAULT_AUDIT_LIMIT,
};
use eltanin_core::lease::{IssuerInstanceId, LeaseId};

fn argv(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

fn event_id(instance: &str, sequence: u64) -> AuditEventId {
    AuditEventId {
        instance: IssuerInstanceId::new(instance),
        sequence,
    }
}

#[test]
fn top_level_dispatch_routes_explain_audit_status() {
    assert!(matches!(
        parse(argv(&["explain", "--pid", "1"])).unwrap(),
        Invocation::Explain(_)
    ));
    assert!(matches!(
        parse(argv(&["audit"])).unwrap(),
        Invocation::Audit(_)
    ));
    assert!(matches!(
        parse(argv(&["status"])).unwrap(),
        Invocation::Status(_)
    ));
}

#[test]
fn explain_with_event_selector_parses() {
    let invocation = parse_explain(argv(&["explain", "--event", "agent-1#7"])).unwrap();
    assert_eq!(invocation.selector, Selector::Event(event_id("agent-1", 7)));
    assert!(!invocation.chain);
    assert_eq!(invocation.log_path, None);
}

#[test]
fn explain_with_lease_selector_parses() {
    let invocation = parse_explain(argv(&["explain", "--lease", "agent-1#7"])).unwrap();
    assert_eq!(
        invocation.selector,
        Selector::Lease(LeaseId {
            issuer: IssuerInstanceId::new("agent-1"),
            sequence: 7,
        })
    );
}

#[test]
fn explain_with_pid_selector_parses() {
    let invocation = parse_explain(argv(&["explain", "--pid", "4242"])).unwrap();
    assert_eq!(invocation.selector, Selector::Pid(4242));
}

#[test]
fn explain_with_chain_and_log_parses() {
    let invocation = parse_explain(argv(&[
        "explain",
        "--pid",
        "1",
        "--chain",
        "--log",
        "/tmp/audit.log",
    ]))
    .unwrap();
    assert!(invocation.chain);
    assert_eq!(invocation.log_path, Some(PathBuf::from("/tmp/audit.log")));
}

#[test]
fn explain_with_no_selector_is_rejected() {
    let result = parse_explain(argv(&["explain", "--chain"]));
    assert_eq!(result, Err(UsageError::SelectorMissing));
}

#[test]
fn explain_with_two_selectors_is_rejected() {
    let result = parse_explain(argv(&["explain", "--pid", "1", "--event", "a#1"]));
    assert_eq!(result, Err(UsageError::SelectorGivenTwice));
}

#[test]
fn explain_with_malformed_event_is_rejected() {
    let result = parse_explain(argv(&["explain", "--event", "not-an-event-id"]));
    assert!(matches!(result, Err(UsageError::InvalidEvent { .. })));
}

#[test]
fn explain_with_non_numeric_pid_is_rejected() {
    let result = parse_explain(argv(&["explain", "--pid", "not-a-number"]));
    assert!(matches!(result, Err(UsageError::InvalidPid { .. })));
}

#[test]
fn audit_with_no_arguments_uses_the_default_limit() {
    let invocation = parse_audit(argv(&["audit"])).unwrap();
    assert_eq!(invocation.limit, DEFAULT_AUDIT_LIMIT);
    assert_eq!(invocation.log_path, None);
}

#[test]
fn audit_with_limit_and_log_parses() {
    let invocation =
        parse_audit(argv(&["audit", "--limit", "5", "--log", "/tmp/audit.log"])).unwrap();
    assert_eq!(invocation.limit, 5);
    assert_eq!(invocation.log_path, Some(PathBuf::from("/tmp/audit.log")));
}

#[test]
fn audit_with_invalid_limit_is_rejected() {
    let result = parse_audit(argv(&["audit", "--limit", "not-a-number"]));
    assert!(matches!(result, Err(UsageError::InvalidLimit { .. })));
}

#[test]
fn status_with_no_arguments_parses() {
    assert!(parse_status(argv(&["status"])).is_ok());
}

#[test]
fn status_with_an_extra_argument_is_rejected() {
    let result = parse_status(argv(&["status", "extra"]));
    assert!(matches!(
        result,
        Err(UsageError::UnexpectedStatusArgument { .. })
    ));
}
