//! `eltanin dogfood-evidence [--log <path>]` — HORO-1376: print the
//! ADR-0012 v1 `DogFood` evidence projection of the native audit log.
//!
//! Thin over [`eltanin_dogfood::adapter`], exactly the same shape as
//! [`crate::audit`]/[`crate::explain`] over [`eltanin_audit::explain`]:
//! this module resolves the log path, reads it, projects it, and prints
//! NDJSON (one evidence event per line) — it contains no adapter logic
//! of its own and never writes to the audit log.
//!
//! # Branch qualification (mandatory, ADR-0012 §11.4)
//!
//! Every invocation's output leads with
//! [`eltanin_dogfood::BRANCH_QUALIFICATION_NOTICE`] — observe-mode
//! authorization semantics are real only on `next/mvp-2.0`, never a
//! shipped `main` build — so this fact is never silently absent from
//! operator-facing output. See `tests/dogfood_evidence_argv_contract.rs`
//! for the argv grammar and `crates/eltanin-dogfood/tests/
//! branch_qualification.rs` for the string content itself.

use eltanin_dogfood::adapter::{
    project, resolve_profile, summary_unsupported_notes, PROFILE_ENV_VAR,
};

use crate::args::DogfoodEvidenceInvocation;
use crate::explain::{read_scan, resolve_log_path};
use crate::failure::LaunchFailure;

pub enum DogfoodEvidenceCliOutcome {
    Ok(String),
    Failure(LaunchFailure),
}

/// Run a parsed [`DogfoodEvidenceInvocation`].
#[must_use]
pub fn run(invocation: &DogfoodEvidenceInvocation) -> DogfoodEvidenceCliOutcome {
    let log_path = match resolve_log_path(invocation.log_path.clone()) {
        Ok(path) => path,
        Err(failure) => return DogfoodEvidenceCliOutcome::Failure(failure),
    };
    let scan = match read_scan(&log_path) {
        Ok(Some(scan)) => scan,
        Ok(None) => {
            return DogfoodEvidenceCliOutcome::Ok(format!(
                "{}\n\nno audit log found at {} (yet) — nothing to project",
                eltanin_dogfood::BRANCH_QUALIFICATION_NOTICE,
                log_path.display()
            ))
        }
        Err(failure) => return DogfoodEvidenceCliOutcome::Failure(failure),
    };

    let profile_raw = std::env::var(PROFILE_ENV_VAR).ok();
    let profile = resolve_profile(profile_raw.as_deref());
    let product_version = env!("CARGO_PKG_VERSION");
    let now = eltanin_audit::record::SystemWallClock;
    let now_reading = {
        use eltanin_audit::record::AuditClock;
        now.now()
    };

    let projection = project(&scan, profile, product_version, now_reading);

    let mut out = String::new();
    out.push_str(eltanin_dogfood::BRANCH_QUALIFICATION_NOTICE);
    out.push('\n');
    out.push('\n');

    for event in &projection.events {
        out.push_str(&serde_json::to_string(event).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&serde_json::to_string(&projection.summary).unwrap_or_default());
    out.push('\n');

    if !projection.malformed.is_empty() {
        use std::fmt::Write as _;
        out.push('\n');
        let _ = writeln!(
            out,
            "{} record(s) refused rather than fabricated a value:",
            projection.malformed.len()
        );
        for m in &projection.malformed {
            let _ = writeln!(out, "  {}: {}", m.event_id, m.reason);
        }
    }

    let notes = summary_unsupported_notes(&scan);
    if !notes.is_empty() {
        out.push('\n');
        out.push_str("unsupported: ");
        out.push_str(&notes.join(", "));
        out.push('\n');
    }

    DogfoodEvidenceCliOutcome::Ok(out)
}
