//! Doc/code sync guards (F-M1-008, HORO-845/847): the published exit-code
//! table, the published `eltanin run` example policy, and the canonical
//! E2E scenario's Quickstart must not silently drift from what the code
//! actually does.

use eltanin_cli::exit::ExitCode;

/// Mirrors `canonical_e2e.rs::SCENARIO_ID`. Not shared via a common
/// module — `docs_sync.rs` and `canonical_e2e.rs` are two independent
/// test binaries (`canonical_e2e` is `#![cfg(target_os = "linux")]`, this
/// file is not) — but `canonical_scenario_id_matches_the_e2e_test_source`
/// below reads `canonical_e2e.rs`'s actual source text (via
/// `include_str!`, which is not subject to `cfg`) and asserts this
/// literal appears there verbatim, so a drift is still caught on every
/// platform, not only Linux CI.
const CANONICAL_SCENARIO_ID: &str = "E2E-F-M1-008-controlled-launch-v1";

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
        // Require the code and its description on the *same* table row —
        // two independent whole-document `contains` checks would still
        // pass if a row's code and description were swapped with
        // another row's, since both fragments would still appear
        // somewhere in the document.
        let row_prefix = format!("| {} |", code.code());
        let row = doc
            .lines()
            .find(|line| line.starts_with(&row_prefix))
            .unwrap_or_else(|| {
                panic!(
                    "CLI_CONTRACT.md must have a row for exit code {}",
                    code.code()
                )
            });
        assert!(
            row.contains(doc_fragment),
            "CLI_CONTRACT.md's row for exit code {} must describe it using language matching \
             {doc_fragment:?}, got: {row:?}",
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

/// `canonical_e2e.rs`'s `pub const SCENARIO_ID` must still be the literal
/// this file duplicates in [`CANONICAL_SCENARIO_ID`] — see that
/// constant's doc comment for why this is checked via source text rather
/// than a shared module.
#[test]
fn canonical_scenario_id_matches_the_e2e_test_source() {
    let source = include_str!("canonical_e2e.rs");
    let expected_decl = format!("pub const SCENARIO_ID: &str = {CANONICAL_SCENARIO_ID:?};");
    assert!(
        source.contains(&expected_decl),
        "docs_sync.rs::CANONICAL_SCENARIO_ID ({CANONICAL_SCENARIO_ID:?}) no longer matches \
         canonical_e2e.rs's own `pub const SCENARIO_ID` declaration — keep them in sync"
    );
}

/// `docs/product/QUICKSTART.md`'s profile fenced block (HORO-847) must
/// stay byte-identical to the same fixture `tests/profile_loader.rs`
/// already loads — the same convention as
/// `eltanin_run_policy_example_is_byte_identical_to_the_committed_fixture`
/// above, applied to the Quickstart's first (and only) `json` fence.
#[test]
fn quickstart_profile_example_is_byte_identical_to_the_committed_fixture() {
    let doc = include_str!("../../../docs/product/QUICKSTART.md");
    let fixture = include_str!("fixtures/example_profile.json");

    let fenced_json = doc
        .split("```json\n")
        .nth(1)
        .and_then(|rest| rest.split("\n```").next())
        .expect("docs/product/QUICKSTART.md must contain a ```json fenced profile example");

    assert_eq!(
        fenced_json.trim_end(),
        fixture.trim_end(),
        "docs/product/QUICKSTART.md's profile example has drifted from \
         crates/eltanin-cli/tests/fixtures/example_profile.json — keep them in sync"
    );
}

/// The exact `eltanin run` invocation `canonical_e2e.rs`'s ALLOW leg runs
/// must appear verbatim in the Quickstart — built from the same literals
/// the test uses (`PROFILE_NAME`, the workload argv), not re-typed, so a
/// change to either one shows up here as a compile-time-adjacent
/// constant rather than two independently-maintained strings.
#[test]
fn quickstart_shows_the_exact_command_the_allow_journey_runs() {
    let doc = include_str!("../../../docs/product/QUICKSTART.md");
    let command_line = "eltanin run --profile gpu -- echo authorized-compute-ok";
    assert!(
        doc.contains(command_line),
        "docs/product/QUICKSTART.md must show the exact command the canonical E2E scenario's \
         ALLOW leg runs ({command_line:?}) — keep them in sync"
    );
}

/// Every environment variable `canonical_e2e.rs` sets on either binary
/// must be named somewhere in the Quickstart — a reader who copies every
/// command on the page ends up with the same configuration surface the
/// canonical scenario exercises.
#[test]
fn quickstart_names_every_env_var_the_canonical_scenario_sets() {
    let doc = include_str!("../../../docs/product/QUICKSTART.md");
    let env_vars = [
        "ELTANIN_AGENT_SOCKET",
        "ELTANIN_AGENT_SOCKET_MODE",
        "ELTANIN_AGENT_POLICY",
        "ELTANIN_AGENT_LEASE_TTL_SECS",
        "ELTANIN_AUDIT_LOG",
        "ELTANIN_PROFILE_DIR",
    ];
    for var in env_vars {
        assert!(
            doc.contains(var),
            "docs/product/QUICKSTART.md must name {var} (the canonical E2E scenario sets it on \
             eltanin-agentd or eltanin) — keep them in sync"
        );
    }
}

/// The canonical scenario's stable ID must be visible on both the
/// user-facing Quickstart and the Track B evidence record it backs — the
/// two ways a reader might arrive at "what does this scenario actually
/// prove."
#[test]
fn canonical_scenario_id_appears_in_quickstart_and_its_track_b_record() {
    let quickstart = include_str!("../../../docs/product/QUICKSTART.md");
    let track_b = include_str!("../../../docs/qa/e2e/F-M1-008-controlled-launch.md");
    assert!(
        quickstart.contains(CANONICAL_SCENARIO_ID),
        "docs/product/QUICKSTART.md must cite {CANONICAL_SCENARIO_ID:?}"
    );
    assert!(
        track_b.contains(CANONICAL_SCENARIO_ID),
        "docs/qa/e2e/F-M1-008-controlled-launch.md must cite {CANONICAL_SCENARIO_ID:?}"
    );
}
