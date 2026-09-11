//! Mechanical QA-governance drift guards (HORO-810): `docs/qa/README.md`'s
//! Feature Verification Record inventory and `docs/qa/test-plans/mvp-1.0.md`'s
//! test-file citations must not silently drift from what actually exists
//! on disk. `docs/qa/README.md` already lives one path segment away from
//! `eltanin-cli` for a reason — `docs_sync.rs` in this same crate already
//! `include_str!`s into `docs/qa/e2e/` — so this file is a natural
//! extension of an existing pattern, not a new one.
//!
//! What this does **not** check: whether every Feature *has* a record
//! (F-M1-001/002/007 legitimately don't yet — see the inventory's own
//! `*(none)*`/`*(none yet)*` cells, which are correct, not a gap this
//! file should flag) or whether a cited test file's *content* still
//! matches its claimed purpose. It checks only that every path these two
//! governance documents name is real — inventory-consistency, not
//! coverage-completeness.

use std::fs;
use std::path::PathBuf;

const README: &str = include_str!("../../../docs/qa/README.md");
const TEST_PLAN: &str = include_str!("../../../docs/qa/test-plans/mvp-1.0.md");

const FEATURE_IDS: &[&str] = &[
    "F-M1-001", "F-M1-002", "F-M1-003", "F-M1-004", "F-M1-005", "F-M1-006", "F-M1-007", "F-M1-008",
    "F-M1-009",
];

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

/// Every `crates/.../tests/*.rs` path `docs/qa/test-plans/mvp-1.0.md`
/// cites as evidence must exist on disk — a test-plan citation rots
/// exactly as easily as a stale code comment, and nothing else checks it.
#[test]
fn every_test_path_cited_by_the_mvp_1_0_test_plan_exists() {
    let root = repo_root();
    let mut checked = 0;
    for token in TEST_PLAN.split(|c: char| !is_path_char(c)) {
        let Some(crates_at) = token.find("crates/") else {
            continue;
        };
        let candidate = &token[crates_at..];
        if std::path::Path::new(candidate).extension() == Some("rs".as_ref()) {
            let path = root.join(candidate);
            assert!(
                path.exists(),
                "docs/qa/test-plans/mvp-1.0.md cites {token:?}, which does not exist"
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 10,
        "expected at least 10 crates/**/tests/*.rs citations in docs/qa/test-plans/mvp-1.0.md, \
         found {checked}"
    );
}

fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-')
}
