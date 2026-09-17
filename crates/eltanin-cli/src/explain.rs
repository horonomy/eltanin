//! `eltanin explain (--event|--lease|--pid) <v> [--chain]` — human-
//! readable audit-log explanation CLI (F-M2-006, HORO-796 subtask 4).
//!
//! Thin over [`eltanin_audit::explain`]: this module resolves the log
//! path, calls [`eltanin_audit::explain::read_log`]/[`select`], and
//! formats the result — it contains no decision logic of its own and
//! never feeds anything read here back into an authorization path (see
//! `eltanin_audit::explain`'s own module docs on that invariant).
//!
//! # `--chain`
//!
//! Without `--chain`, the output is exactly what
//! [`eltanin_audit::explain::select`] returned for the given selector.
//! With `--chain`, the selection is expanded breadth-first, deduplicated
//! by [`AuditEventId`] (never by [`eltanin_core::lease::LeaseId`] or
//! [`eltanin_core::session::SessionId`] — those are many-to-one with
//! records, so keying on them would under-visit), by repeatedly
//! following:
//!
//! - a record's own [`AuditRecord::lease_id`] to every other record
//!   naming the same lease (its grant and its release, whichever the
//!   seed didn't already cover) — for a `--lease` selector this adds
//!   nothing new, since
//!   [`Selector::Lease`](eltanin_audit::explain::Selector::Lease)
//!   already returns every matching record;
//! - a record's `session` to every other record sharing that
//!   [`eltanin_core::session::SessionId`];
//! - a [`RecordedOutcome::GrantedByDelegation`] record's
//!   `delegation.parent_lease` to that lease's own records.
//!
//! The expansion is exhaustive (it has nowhere left to grow once every
//! reachable record has been visited), so it always terminates on a
//! finite log.

use std::collections::{HashSet, VecDeque};
use std::env;
use std::path::{Path, PathBuf};

use eltanin_audit::explain::{read_log, render, select, SelectionResult};
use eltanin_audit::record::{AuditEventId, AuditRecord, RecordedOutcome};

use crate::args::ExplainInvocation;
use crate::failure::LaunchFailure;

/// The result of one `eltanin explain` invocation: either a
/// human-readable report (printed to stdout, exit 0 — this includes the
/// "no matching record" cases, mirroring `eltanin session list`'s own
/// "no active session" precedent: the command ran successfully and
/// truthfully reports there was nothing to explain) or a
/// [`LaunchFailure`] when the log itself could not be resolved or read.
pub enum ExplainCliOutcome {
    Ok(String),
    Failure(LaunchFailure),
}

/// Run a parsed [`ExplainInvocation`].
#[must_use]
pub fn run(invocation: &ExplainInvocation) -> ExplainCliOutcome {
    let log_path = match resolve_log_path(invocation.log_path.clone()) {
        Ok(path) => path,
        Err(failure) => return ExplainCliOutcome::Failure(failure),
    };
    let scan = match read_scan(&log_path) {
        Ok(Some(scan)) => scan,
        Ok(None) => {
            return ExplainCliOutcome::Ok(format!(
                "no audit log found at {} (yet) — nothing to explain",
                log_path.display()
            ))
        }
        Err(failure) => return ExplainCliOutcome::Failure(failure),
    };

    match select(&scan, &invocation.selector) {
        SelectionResult::Found(records) => {
            let expanded = if invocation.chain {
                expand_chain(&scan, &records)
            } else {
                records
            };
            let mut out = String::new();
            for (index, record) in expanded.iter().enumerate() {
                if index > 0 {
                    out.push('\n');
                }
                out.push_str(&render(record));
            }
            ExplainCliOutcome::Ok(out)
        }
        SelectionResult::PossiblyLost => ExplainCliOutcome::Ok(
            "no record found for that event id, but it falls inside an observed sequence gap \
             for its agent instance — it may exist and have failed to persist (audit \
             persistence is best-effort; see docs/product/SECURITY_MODEL.md)."
                .to_string(),
        ),
        SelectionResult::RetentionDiscarded => ExplainCliOutcome::Ok(
            "no record found for that event id — it was legitimately recorded, but its \
             generation has since been rotated away by the audit log's bounded-retention \
             policy (see docs/product/SECURITY_MODEL.md)."
                .to_string(),
        ),
        SelectionResult::NotFound => {
            ExplainCliOutcome::Ok("no matching record found.".to_string())
        }
    }
}

/// Resolve `explicit` (`--log`), falling back to `ELTANIN_AUDIT_LOG`
/// (matching `eltanin-agentd`'s own env var and
/// `crates/eltanin-audit/src/bin/eltanin-explain.rs`'s precedent).
///
/// # Errors
///
/// Returns [`LaunchFailure::AuditLogUnavailable`] if neither is given, or
/// if `ELTANIN_AUDIT_LOG` is set but not valid UTF-8 — a set-but-invalid
/// value is a distinct case from "unset" and must not silently fall
/// through, mirroring `AgentClient::from_env`'s identical discipline for
/// `ELTANIN_AGENT_SOCKET`.
pub(crate) fn resolve_log_path(explicit: Option<PathBuf>) -> Result<PathBuf, LaunchFailure> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    match env::var_os("ELTANIN_AUDIT_LOG") {
        Some(path) => Ok(PathBuf::from(path)),
        None => Err(LaunchFailure::AuditLogUnavailable(
            "no audit log path given (--log or ELTANIN_AUDIT_LOG)".to_string(),
        )),
    }
}

/// Read the log at `path`, or `Ok(None)` when nothing has been recorded
/// there yet — an absent log is the common first-run case for both
/// `eltanin explain` and `eltanin audit`, not a malformed invocation, so
/// it is reported as a clean informational message rather than the same
/// [`LaunchFailure`] a genuinely unreadable (e.g. permission-denied) path
/// produces.
pub(crate) fn read_scan(
    path: &Path,
) -> Result<Option<eltanin_audit::explain::LogScan>, LaunchFailure> {
    if !path.exists() {
        return Ok(None);
    }
    read_log(path)
        .map(Some)
        .map_err(|e| LaunchFailure::AuditLogUnavailable(e.to_string()))
}

/// Breadth-first-expand `seed` per this module's `--chain` doc section
/// above.
fn expand_chain<'a>(
    scan: &'a eltanin_audit::explain::LogScan,
    seed: &[&'a AuditRecord],
) -> Vec<&'a AuditRecord> {
    let mut visited: HashSet<AuditEventId> = HashSet::new();
    let mut result: Vec<&AuditRecord> = Vec::new();
    let mut queue: VecDeque<&AuditRecord> = VecDeque::new();

    for record in seed {
        if visited.insert(record.event_id.clone()) {
            result.push(record);
            queue.push_back(record);
        }
    }

    while let Some(record) = queue.pop_front() {
        if let Some(lease_id) = record.lease_id() {
            if let SelectionResult::Found(matches) =
                select(scan, &eltanin_audit::explain::Selector::Lease(lease_id.clone()))
            {
                for candidate in matches {
                    if visited.insert(candidate.event_id.clone()) {
                        result.push(candidate);
                        queue.push_back(candidate);
                    }
                }
            }
        }
        if let Some(session_id) = &record.session {
            for candidate in &scan.records {
                if candidate.session.as_ref() == Some(session_id)
                    && visited.insert(candidate.event_id.clone())
                {
                    result.push(candidate);
                    queue.push_back(candidate);
                }
            }
        }
        if let RecordedOutcome::GrantedByDelegation { delegation, .. } = &record.outcome {
            if let SelectionResult::Found(matches) = select(
                scan,
                &eltanin_audit::explain::Selector::Lease(delegation.parent_lease.clone()),
            ) {
                for candidate in matches {
                    if visited.insert(candidate.event_id.clone()) {
                        result.push(candidate);
                        queue.push_back(candidate);
                    }
                }
            }
        }
    }

    result
}
