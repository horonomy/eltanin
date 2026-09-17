//! Mechanical QA-governance drift guards: `docs/qa/README.md`'s
//! Feature Verification Record inventory and each `docs/qa/test-plans/
//! mvp-*.md` test plan's test-file citations must not silently drift
//! from what actually exists on disk (HORO-810), and `docs/qa/e2e/
//! README.md`'s Track B scenario manifest must not silently drift from
//! `canonical_e2e.rs`'s own `COVERS` claim (HORO-811). `docs/qa/README.md`
//! already lives one path segment away from `eltanin-cli` for a reason —
//! `docs_sync.rs` in this same crate already `include_str!`s into
//! `docs/qa/e2e/` — so this file is a natural extension of an existing
//! pattern, not a new one.
//!
//! What this does **not** check: whether every Feature *has* a record
//! (F-M1-001/002/007 legitimately don't yet — see the inventory's own
//! `*(none)*`/`*(none yet)*` cells, which are correct, not a gap this
//! file should flag), whether a cited test file's *content* still
//! matches its claimed purpose, or whether a Track B scenario's claimed
//! coverage is actually correct. It checks only that every path/ID these
//! governance documents name is real and mutually consistent —
//! inventory-consistency, not coverage-completeness.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

const README: &str = include_str!("../../../docs/qa/README.md");
const TEST_PLAN_MVP_1_0: &str = include_str!("../../../docs/qa/test-plans/mvp-1.0.md");
const TEST_PLAN_MVP_2_0: &str = include_str!("../../../docs/qa/test-plans/mvp-2.0.md");
/// Every versioned Track A test plan this crate mechanically checks —
/// add a new `include_str!` above and a new entry here for each future
/// milestone's test plan, rather than replacing `TEST_PLAN_MVP_1_0`.
const TEST_PLANS: &[(&str, &str)] = &[
    ("docs/qa/test-plans/mvp-1.0.md", TEST_PLAN_MVP_1_0),
    ("docs/qa/test-plans/mvp-2.0.md", TEST_PLAN_MVP_2_0),
];
const E2E_INDEX: &str = include_str!("../../../docs/qa/e2e/README.md");
const F_M1_008_RECORD: &str = include_str!("../../../docs/qa/e2e/F-M1-008-controlled-launch.md");
const CANONICAL_E2E: &str = include_str!("canonical_e2e.rs");
const B_M2_DEVFLOW_RECORD: &str = include_str!("../../../docs/qa/e2e/B-M2-DEVFLOW.md");
const MVP2_DEV_FLOW_E2E: &str = include_str!("mvp2_dev_flow_e2e.rs");

const FEATURE_IDS: &[&str] = &[
    "F-M1-001", "F-M1-002", "F-M1-003", "F-M1-004", "F-M1-005", "F-M1-006", "F-M1-007", "F-M1-008",
    "F-M1-009", "F-M1-010", "F-M2-001", "F-M2-002", "F-M2-003", "F-M2-004", "F-M2-005", "F-M2-006",
];

/// The `F-M*-` prefixes this file recognizes when extracting Feature IDs
/// from a governance document — `F-M1-` (MVP 1.0) and `F-M2-` (MVP 2.0).
/// Extend this list, not `extract_feature_ids`'s body, when a future
/// milestone introduces a new `F-M<N>-` prefix.
const FEATURE_ID_PREFIXES: &[&str] = &["F-M1-", "F-M2-"];

/// Parse a `pub const COVERS: &[&str] = &[...]` literal out of `source`
/// back into a `Vec<&str>` — the one place a scenario's Feature-coverage
/// claim is declared in code, everything else in this file checks
/// documentation against *that*. Generic over `source` (rather than
/// hardcoded to `canonical_e2e.rs`) so the same parser serves every
/// scenario test file this crate has — see [`parse_covers`] and
/// [`parse_mvp2_dev_flow_covers`] below.
fn parse_covers_from<'a>(source: &'a str, source_name: &str) -> Vec<&'a str> {
    let marker = "pub const COVERS: &[&str] = &[";
    let start = source.find(marker).unwrap_or_else(|| {
        panic!("{source_name} must declare `pub const COVERS: &[&str] = &[...]`")
    }) + marker.len();
    let rest = &source[start..];
    let end = rest
        .find(']')
        .unwrap_or_else(|| panic!("unterminated COVERS array literal in {source_name}"));
    rest[..end]
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_matches('"'))
        .collect()
}

fn parse_covers() -> Vec<&'static str> {
    parse_covers_from(CANONICAL_E2E, "canonical_e2e.rs")
}

fn parse_mvp2_dev_flow_covers() -> Vec<&'static str> {
    parse_covers_from(MVP2_DEV_FLOW_E2E, "mvp2_dev_flow_e2e.rs")
}

/// Extract every `F-M1-NNN`/`F-M2-NNN`-shaped substring from `s` — used
/// to read back "which Feature IDs does this slice of a doc claim"
/// without needing a regex dependency. Any prefix in [`FEATURE_ID_PREFIXES`]
/// plus exactly 3 ASCII digits, so it can't partially match a longer
/// token, and a future milestone's prefix is a one-line addition to that
/// list rather than a change here.
fn extract_feature_ids(s: &str) -> BTreeSet<&str> {
    let mut ids = BTreeSet::new();
    for prefix in FEATURE_ID_PREFIXES {
        let mut i = 0;
        while let Some(offset) = s[i..].find(prefix) {
            let start = i + offset;
            let digits_start = start + prefix.len();
            let digits_end = digits_start + 3;
            if digits_end <= s.len()
                && s[digits_start..digits_end]
                    .bytes()
                    .all(|b| b.is_ascii_digit())
            {
                ids.insert(&s[start..digits_end]);
                i = digits_end;
            } else {
                i = start + prefix.len();
            }
        }
    }
    ids
}

/// Slice `record` down to just its "## Coverage" section (up to the next
/// `##` heading) — a record's "Named limitations" prose can legitimately
/// mention Feature IDs it does *not* cover (e.g. `F-M1-008-controlled-launch.md`
/// mentions F-M1-002/F-M1-007), so a whole-document ID scan would
/// produce false positives. Generic over `record`/`record_name` so the
/// same slicer serves every scenario record this crate checks.
fn coverage_table_slice_of<'a>(record: &'a str, record_name: &str) -> &'a str {
    let marker = "## Coverage";
    let start = record
        .find(marker)
        .unwrap_or_else(|| panic!("{record_name} must have a \"## Coverage\" section"));
    let rest = &record[start + marker.len()..];
    let end = rest.find("\n## ").unwrap_or(rest.len());
    &rest[..end]
}

fn coverage_table_slice() -> &'static str {
    coverage_table_slice_of(F_M1_008_RECORD, "F-M1-008-controlled-launch.md")
}

fn b_m2_devflow_coverage_table_slice() -> &'static str {
    coverage_table_slice_of(B_M2_DEVFLOW_RECORD, "B-M2-DEVFLOW.md")
}

/// The Track B manifest's "Features covered" column, scoped to just the
/// one row whose scenario-ID cell starts with `row_prefix` — scoping to
/// one row (rather than the whole `E2E_INDEX` doc) avoids false
/// positives from the per-Feature coverage table below it, which
/// mentions every Feature ID including the N/A/BLOCKED ones a given
/// scenario does not cover.
fn manifest_row_covered_ids_for(row_prefix: &str) -> BTreeSet<&'static str> {
    let row = E2E_INDEX
        .lines()
        .find(|line| line.starts_with(row_prefix))
        .unwrap_or_else(|| {
            panic!("docs/qa/e2e/README.md must have a manifest row starting with {row_prefix:?}")
        });
    let last_cell = row
        .trim_matches('|')
        .rsplit('|')
        .next()
        .expect("a table row has at least one cell");
    extract_feature_ids(last_cell)
}

fn manifest_row_covered_ids() -> BTreeSet<&'static str> {
    manifest_row_covered_ids_for("| `E2E-")
}

fn b_m2_devflow_manifest_row_covered_ids() -> BTreeSet<&'static str> {
    manifest_row_covered_ids_for("| `B-M2-")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve repo root from CARGO_MANIFEST_DIR")
}

/// Every `docs/qa/feature-verification/F-*.md` file (excluding
/// `TEMPLATE.md`) must be linked from `docs/qa/README.md`'s inventory
/// table — an orphaned record nobody's inventory points at.
#[test]
fn every_feature_verification_record_is_cited_by_the_readme_inventory() {
    let dir = repo_root().join("docs/qa/feature-verification");
    let entries = fs::read_dir(&dir).expect("read docs/qa/feature-verification");
    let mut checked = 0;
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 file name")
            .to_string();
        if name == "TEMPLATE.md" {
            continue;
        }
        let link = format!("(feature-verification/{name})");
        assert!(
            README.contains(&link),
            "docs/qa/feature-verification/{name} exists but docs/qa/README.md's inventory \
             table does not link {link:?} — either link it there or remove the orphaned record"
        );
        checked += 1;
    }
    assert!(
        checked >= 6,
        "expected at least 6 real Feature Verification Records under \
         docs/qa/feature-verification/, found {checked} — did the directory move?"
    );
}

/// Every `feature-verification/...` link the README's inventory table
/// makes must resolve to a real file — never a dangling link.
#[test]
fn every_readme_inventory_record_link_resolves_to_a_real_file() {
    let root = repo_root();
    let marker = "(feature-verification/";
    let mut idx = 0;
    let mut checked = 0;
    while let Some(offset) = README[idx..].find(marker) {
        let link_start = idx + offset + 1; // skip the '('
        let rest = &README[link_start..];
        let end = rest
            .find(')')
            .expect("unterminated markdown link in docs/qa/README.md");
        let rel = &rest[..end];
        idx = link_start + end;
        if rel.ends_with('/') {
            // A bare `(feature-verification/)` link to the directory
            // itself (e.g. the "Feature Verification Record" section's
            // prose link) — not a specific-record citation the inventory
            // table makes, so it's exempt from the per-record checks
            // below. Still confirm the directory itself is real.
            assert!(
                root.join("docs/qa").join(rel).is_dir(),
                "docs/qa/README.md links to {rel:?} (resolved under docs/qa/), which is not a directory"
            );
            continue;
        }
        let path = root.join("docs/qa").join(rel);
        assert!(
            path.exists(),
            "docs/qa/README.md links to {rel:?} (resolved under docs/qa/), which does not exist"
        );
        let canonical = path
            .canonicalize()
            .unwrap_or_else(|e| panic!("canonicalize {path:?}: {e}"));
        let expected_parent = root
            .join("docs/qa/feature-verification")
            .canonicalize()
            .expect("resolve docs/qa/feature-verification — the inventory's link target directory");
        assert_eq!(
            canonical.parent(),
            Some(expected_parent.as_path()),
            "docs/qa/README.md links to {rel:?}, which resolves outside \
             docs/qa/feature-verification/ (possible ../ escape)"
        );
        checked += 1;
    }
    assert!(
        checked >= 6,
        "expected at least 6 feature-verification links in docs/qa/README.md, found {checked}"
    );
}

/// Every `F-M1-00N` Feature must appear in the inventory table exactly
/// once, with a non-empty QA-status cell — catching a dropped row or a
/// row someone forgot to fill in. Does not judge whether the status
/// itself is correct.
#[test]
fn every_feature_id_appears_once_in_the_inventory_with_a_non_empty_status() {
    for id in FEATURE_IDS {
        let row_prefix = format!("| {id} —");
        let matches: Vec<&str> = README
            .lines()
            .filter(|line| line.starts_with(&row_prefix))
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one docs/qa/README.md inventory row starting with {row_prefix:?}, \
             found {}",
            matches.len()
        );
        let cells: Vec<&str> = matches[0]
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        let status = cells.last().expect("a table row has at least one cell");
        assert!(
            !status.is_empty(),
            "docs/qa/README.md's inventory row for {id} has an empty QA-status cell"
        );
    }
}

/// Every `crates/.../tests/*.rs` path any versioned Track A test plan in
/// [`TEST_PLANS`] cites as evidence must exist on disk — a test-plan
/// citation rots exactly as easily as a stale code comment, and nothing
/// else checks it. Runs once per test plan, not just `mvp-1.0.md`, so a
/// future milestone's test plan gets this guard automatically once added
/// to `TEST_PLANS`.
#[test]
fn every_test_path_cited_by_a_test_plan_exists() {
    let root = repo_root();
    for (plan_path, plan_text) in TEST_PLANS {
        let mut checked = 0;
        for token in plan_text.split(|c: char| !is_path_char(c)) {
            let Some(crates_at) = token.find("crates/") else {
                continue;
            };
            let candidate = &token[crates_at..];
            if std::path::Path::new(candidate).extension() == Some("rs".as_ref()) {
                let path = root.join(candidate);
                assert!(
                    path.exists(),
                    "{plan_path} cites {token:?}, which does not exist"
                );
                checked += 1;
            }
        }
        assert!(
            checked >= 10,
            "expected at least 10 crates/**/tests/*.rs citations in {plan_path}, found {checked}"
        );
    }
}

fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-')
}

/// `canonical_e2e.rs`'s `COVERS` const must name *exactly* the same
/// Feature IDs as `F-M1-008-controlled-launch.md`'s own "Coverage" table —
/// checked both ways, not just "every `COVERS` entry is mentioned
/// somewhere": a one-directional `contains` check would miss the code
/// silently dropping a `COVERS` entry while the doc keeps overclaiming it.
#[test]
fn covers_feature_ids_exactly_match_the_f_m1_008_record_coverage_table() {
    let covers = parse_covers();
    assert!(
        !covers.is_empty(),
        "canonical_e2e.rs's COVERS parsed as empty — parser or const likely broken"
    );
    let covers_set: BTreeSet<&str> = covers.iter().copied().collect();
    let record_set = extract_feature_ids(coverage_table_slice());
    assert_eq!(
        covers_set, record_set,
        "canonical_e2e.rs's COVERS and docs/qa/e2e/F-M1-008-controlled-launch.md's Coverage \
         table section name different Feature-ID sets — one overclaims or underclaims \
         relative to the other"
    );
}

/// The same `COVERS` set must exactly match the Track B scenario
/// manifest's "Features covered" column in `docs/qa/e2e/README.md` — the
/// index HORO-811 introduces to summarize every scenario at a glance.
#[test]
fn covers_feature_ids_exactly_match_the_e2e_index_manifest_row() {
    let covers_set: BTreeSet<&str> = parse_covers().into_iter().collect();
    let manifest_set = manifest_row_covered_ids();
    assert_eq!(
        covers_set, manifest_set,
        "canonical_e2e.rs's COVERS and docs/qa/e2e/README.md's manifest \"Features covered\" \
         column name different Feature-ID sets — one overclaims or underclaims relative to \
         the other"
    );
}

/// `mvp2_dev_flow_e2e.rs`'s `COVERS` must exactly match
/// `B-M2-DEVFLOW.md`'s own "Coverage" table section — same two-way
/// equality discipline as `covers_feature_ids_exactly_match_the_f_m1_008_record_coverage_table`,
/// applied to the MVP 2.0 scenario HORO-797 introduces.
#[test]
fn covers_feature_ids_exactly_match_the_b_m2_devflow_record_coverage_table() {
    let covers = parse_mvp2_dev_flow_covers();
    assert!(
        !covers.is_empty(),
        "mvp2_dev_flow_e2e.rs's COVERS parsed as empty — parser or const likely broken"
    );
    let covers_set: BTreeSet<&str> = covers.iter().copied().collect();
    let record_set = extract_feature_ids(b_m2_devflow_coverage_table_slice());
    assert_eq!(
        covers_set, record_set,
        "mvp2_dev_flow_e2e.rs's COVERS and docs/qa/e2e/B-M2-DEVFLOW.md's Coverage table section \
         name different Feature-ID sets — one overclaims or underclaims relative to the other"
    );
}

/// The same `COVERS` set must exactly match `B-M2-DEVFLOW-v1`'s own row
/// in `docs/qa/e2e/README.md`'s manifest — same two-way equality
/// discipline as `covers_feature_ids_exactly_match_the_e2e_index_manifest_row`,
/// applied to the MVP 2.0 scenario HORO-797 introduces.
#[test]
fn covers_feature_ids_exactly_match_the_e2e_index_manifest_row_for_b_m2_devflow() {
    let covers_set: BTreeSet<&str> = parse_mvp2_dev_flow_covers().into_iter().collect();
    let manifest_set = b_m2_devflow_manifest_row_covered_ids();
    assert_eq!(
        covers_set, manifest_set,
        "mvp2_dev_flow_e2e.rs's COVERS and docs/qa/e2e/README.md's manifest \"Features covered\" \
         column (B-M2-DEVFLOW-v1's row) name different Feature-ID sets — one overclaims or \
         underclaims relative to the other"
    );
}

/// Every `F-M1-00N` Feature named by `docs/qa/README.md`'s inventory must
/// appear in `docs/qa/e2e/README.md`'s per-Feature coverage table with a
/// scenario ID, `N/A`, or `BLOCKED` marker — never a silently missing row.
#[test]
fn every_feature_id_appears_in_the_e2e_index_with_a_scenario_or_na_or_blocked_marker() {
    for id in FEATURE_IDS {
        let row_prefix = format!("| {id} —");
        let matches: Vec<&str> = E2E_INDEX
            .lines()
            .filter(|line| line.starts_with(&row_prefix))
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one docs/qa/e2e/README.md per-Feature coverage row starting with \
             {row_prefix:?}, found {}",
            matches.len()
        );
        let row = matches[0];
        // "E2E-" is this repository's original scenario-ID prefix
        // (`E2E-F-M1-008-controlled-launch-v1`); "B-M1-" is the second
        // naming lineage HORO-1015 introduces for the Apple Silicon Track
        // B scenario (`B-M1-APPLE-v1`, per that ticket's own Jira text
        // and `docs/development/campaign-state.md`); "B-M2-" is the
        // MVP 2.0 lineage HORO-797 introduces (`B-M2-DEVFLOW-v1`) — all
        // three are valid scenario-ID prefixes this repo now uses, not a
        // drift.
        assert!(
            row.contains("E2E-")
                || row.contains("B-M1-")
                || row.contains("B-M2-")
                || row.contains("N/A")
                || row.contains("BLOCKED"),
            "docs/qa/e2e/README.md's coverage row for {id} names neither a scenario ID, N/A, \
             nor BLOCKED — every Feature must state its Track B status explicitly: {row:?}"
        );
    }
}

/// Every link `docs/qa/e2e/README.md`'s manifest table makes — both the
/// `.rs` test-file link and the `.md` record link — must resolve to a real
/// file. The `.md` link is additionally checked to resolve *inside*
/// `docs/qa/e2e/` (mirroring `every_readme_inventory_record_link_resolves_
/// to_a_real_file`'s `../`-escape guard) since it's documented as a
/// same-directory record reference; the `.rs` link legitimately reaches
/// out to `crates/`, so it gets an existence check only.
#[test]
fn every_e2e_index_manifest_link_resolves_to_a_real_file() {
    let root = repo_root();
    let mut checked_md = 0;
    let mut checked_rs = 0;
    for line in E2E_INDEX.lines() {
        if !(line.starts_with("| `E2E-")
            || line.starts_with("| `B-M1-")
            || line.starts_with("| `B-M2-"))
        {
            continue;
        }
        let mut idx = 0;
        while let Some(offset) = line[idx..].find("](") {
            let link_start = idx + offset + 2;
            let rest = &line[link_start..];
            let end = rest
                .find(')')
                .expect("unterminated markdown link in docs/qa/e2e/README.md's manifest table");
            let rel = &rest[..end];
            idx = link_start + end;
            let path = root.join("docs/qa/e2e").join(rel);
            assert!(
                path.exists(),
                "docs/qa/e2e/README.md's manifest links to {rel:?} (resolved under \
                 docs/qa/e2e/), which does not exist"
            );
            match std::path::Path::new(rel).extension() {
                Some(ext) if ext == "md" => {
                    let canonical = path
                        .canonicalize()
                        .unwrap_or_else(|e| panic!("canonicalize {path:?}: {e}"));
                    let expected_parent = root
                        .join("docs/qa/e2e")
                        .canonicalize()
                        .expect("resolve docs/qa/e2e — the manifest's record-link directory");
                    assert_eq!(
                        canonical.parent(),
                        Some(expected_parent.as_path()),
                        "docs/qa/e2e/README.md's manifest links to {rel:?}, which resolves \
                         outside docs/qa/e2e/ (possible ../ escape)"
                    );
                    checked_md += 1;
                }
                Some(ext) if ext == "rs" => checked_rs += 1,
                _ => {}
            }
        }
    }
    assert!(
        checked_md >= 1,
        "expected at least 1 scenario-record (.md) link in docs/qa/e2e/README.md's manifest, \
         found 0"
    );
    assert!(
        checked_rs >= 1,
        "expected at least 1 test-file (.rs) link in docs/qa/e2e/README.md's manifest, found 0"
    );
}
