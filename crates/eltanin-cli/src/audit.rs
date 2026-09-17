//! `eltanin audit [--limit N]` — recent audit-log activity browse
//! (F-M2-006, HORO-796 subtask 4).
//!
//! Unlike [`crate::explain`] (a targeted lookup by event/lease/pid), this
//! command is a browse: every readable
//! [`LogEntry::Decision`](eltanin_audit::record::LogEntry::Decision) and
//! [`LogEntry::Agent`](eltanin_audit::record::LogEntry::Agent) line, most
//! recent first, capped at `--limit` (default
//! [`crate::args::DEFAULT_AUDIT_LIMIT`]).
//!
//! # Ordering is best-effort, not authoritative
//!
//! Lines are ordered by `recorded_at` (a [`WallClockTime`] reading,
//! descending), tie-broken by `event_id.sequence` (also descending) so
//! the order is still deterministic when two lines share a timestamp or
//! a clock read backward — `record.rs`'s own module docs are explicit
//! that a wall clock "can move backward... this fact can never silently
//! affect an authorization decision." Nothing here feeds an
//! authorization decision, but the same caution applies to *display*
//! order: a clock jump can make "most recent first" imprecise across
//! restarts or a corrected clock, and this command does not claim
//! otherwise. Within a single agent instance, `event_id.sequence` is the
//! only ground truth for ordering — [`eltanin_audit::explain`]'s own
//! selectors are what should be used when strict per-instance ordering
//! matters, not this command's cross-instance display convenience.

use eltanin_audit::explain::{render, render_agent_event};
use eltanin_audit::record::{AgentEventRecord, AuditRecord, WallClockTime};

use crate::args::AuditInvocation;
use crate::explain::{read_scan, resolve_log_path};
use crate::failure::LaunchFailure;

/// The result of one `eltanin audit` invocation — mirrors
/// [`crate::explain::ExplainCliOutcome`] exactly, including "no audit log
/// yet" and "log is empty" both being a successful, informational `Ok`.
pub enum AuditCliOutcome {
    Ok(String),
    Failure(LaunchFailure),
}

/// One line of the log, tagged by which arm produced it — the merge key
/// this module sorts and renders through, so the sort/limit/render logic
/// never needs to know which arm it's holding until it actually renders.
enum Line<'a> {
    Decision(&'a AuditRecord),
    Agent(&'a AgentEventRecord),
}

impl Line<'_> {
    fn recorded_at(&self) -> WallClockTime {
        match self {
            Line::Decision(record) => record.recorded_at,
            Line::Agent(event) => event.recorded_at,
        }
    }

    fn sequence(&self) -> u64 {
        match self {
            Line::Decision(record) => record.event_id.sequence,
            Line::Agent(event) => event.event_id.sequence,
        }
    }

    fn render(&self) -> String {
        match self {
            Line::Decision(record) => render(record),
            Line::Agent(event) => render_agent_event(event),
        }
    }
}

/// Run a parsed [`AuditInvocation`].
#[must_use]
pub fn run(invocation: &AuditInvocation) -> AuditCliOutcome {
    let log_path = match resolve_log_path(invocation.log_path.clone()) {
        Ok(path) => path,
        Err(failure) => return AuditCliOutcome::Failure(failure),
    };
    let scan = match read_scan(&log_path) {
        Ok(Some(scan)) => scan,
        Ok(None) => {
            return AuditCliOutcome::Ok(format!(
                "no audit log found at {} (yet)",
                log_path.display()
            ))
        }
        Err(failure) => return AuditCliOutcome::Failure(failure),
    };

    let mut lines: Vec<Line<'_>> = scan
        .records
        .iter()
        .map(Line::Decision)
        .chain(scan.agent_events.iter().map(Line::Agent))
        .collect();

    if lines.is_empty() {
        return AuditCliOutcome::Ok("audit log is empty".to_string());
    }

    // Descending: most recent first, tie-broken by sequence (see the
    // module docs above on why sequence is the tie-breaker, not a
    // second wall-clock field).
    lines.sort_by(|a, b| {
        let by_time = (b.recorded_at().unix_secs, b.recorded_at().nanos)
            .cmp(&(a.recorded_at().unix_secs, a.recorded_at().nanos));
        by_time.then_with(|| b.sequence().cmp(&a.sequence()))
    });
    lines.truncate(invocation.limit);

    let mut out = String::new();
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(&line.render());
    }
    AuditCliOutcome::Ok(out)
}
