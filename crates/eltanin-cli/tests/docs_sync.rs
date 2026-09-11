//! Doc/code sync guards (F-M1-008, HORO-845): the published exit-code
//! table and the published `eltanin run` example policy must not silently
//! drift from what the code actually does.

use eltanin_cli::exit::ExitCode;

#[test]
fn cli_contract_exit_code_table_matches_the_exit_code_enum() {
    let doc = include_str!("../../../docs/product/CLI_CONTRACT.md");
    let codes = [
        (ExitCode::Usage, "usage error"),
        (ExitCode::AgentUnavailable, "agent is unavailable"),
        (ExitCode::AgentError, "protocol or internal error"),
        (
            ExitCode::GovernedContextFailed,
            "governed execution context could not be established",
        ),
        (
            ExitCode::AuthorizationLapsed,
            "authorization lapsed mid-run",
        ),
        (ExitCode::Denied, "denied by policy"),
        (ExitCode::ProfileUnresolved, "could not be resolved"),
    ];
    for (code, doc_fragment) in codes {
        let row = format!("| {} |", code.code());
        assert!(
            doc.contains(&row),
            "CLI_CONTRACT.md must have a row for exit code {}",
            code.code()
        );
        assert!(
            doc.contains(doc_fragment),
            "CLI_CONTRACT.md must describe exit code {} using language matching {doc_fragment:?}",
            code.code()
        );
    }
}

/// `docs/product/POLICY_EXAMPLES.md`'s "Worked example: `eltanin run`"
/// section's fenced JSON block must stay byte-identical to the committed
/// fixture — mirroring
/// `crates/eltanin-core/tests/policy_replay.rs::docs_policy_example_is_byte_identical_to_the_committed_fixture`
/// for the SDK-integration example, but for the second (eltanin-run)
/// fenced block in the same doc.
#[test]
fn eltanin_run_policy_example_is_byte_identical_to_the_committed_fixture() {
    let doc = include_str!("../../../docs/product/POLICY_EXAMPLES.md");
    let fixture = include_str!("fixtures/eltanin_run_example_policy.json");

    // nth(1) is the first ```json block's content (the SDK-integration
    // example); nth(2) is the second — the eltanin-run example this test
    // covers.
    let fenced_json = doc
        .split("```json\n")
        .nth(2)
        .and_then(|rest| rest.split("\n```").next())
        .expect(
            "docs/product/POLICY_EXAMPLES.md must contain a second ```json fenced block for \
             the eltanin run example",
        );

    assert_eq!(
        fenced_json.trim_end(),
        fixture.trim_end(),
        "docs/product/POLICY_EXAMPLES.md's eltanin-run example has drifted from \
         crates/eltanin-cli/tests/fixtures/eltanin_run_example_policy.json — keep them in sync"
    );
}
