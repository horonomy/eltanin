//! Explain: read an audit log and answer "what happened for this
//! decision" (F-M1-009, HORO-824).
//!
//! This module only *reads* the log — see
//! `crates/eltanin-agent/tests/audit_reader_isolation.rs` for the
//! mechanical guard that `eltanin-agent`'s own source never calls into
//! it: the agent writes the trail and never reads it, so no edited log
//! line can reach an authorization decision.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use eltanin_core::envelope::{Versioned, DOMAIN_SCHEMA_VERSION};
use eltanin_core::lease::{IssuerInstanceId, LeaseId};

use crate::record::AuditRecord;

/// What went wrong reading one line of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnreadableReason {
    UnsupportedVersion { found: u16, expected: u16 },
    Malformed { reason: String },
}

/// One log line that could not be turned into an [`AuditRecord`] —
/// reported explicitly, never silently skipped and never fatal to
/// reading the rest of the log. Mirrors `Versioned::into_current`'s own
/// "fail explicitly, don't guess" stance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableLine {
    pub line_number: u64,
    pub reason: UnreadableReason,
}

/// The result of scanning an audit log: every record that parsed, every
/// line that didn't, and every sequence gap observed per issuer
/// instance.
#[derive(Debug, Clone, Default)]
pub struct LogScan {
    pub records: Vec<AuditRecord>,
    pub unreadable: Vec<UnreadableLine>,
    /// Event ids whose sequence number falls strictly between the
    /// lowest and highest sequence actually observed for their
    /// `instance`, but which never appeared as a readable record or an
    /// unreadable line. [`AuditFileSink`](crate::sink::AuditFileSink)
    /// reserves a sequence number before attempting a write and never
    /// reuses it on failure, so a gap here is the honest, structural
    /// signal that a record *may* be missing because persistence
    /// failed — distinct from an id that was simply never issued at
    /// all (which cannot appear here, since it's outside every
    /// instance's observed sequence range).
    pub gaps: Vec<crate::record::AuditEventId>,
}

/// Why [`read_log`] could not be performed at all (distinct from a
/// per-line [`UnreadableLine`], which doesn't stop the read).
#[derive(Debug, thiserror::Error)]
pub enum ExplainError {
    #[error("failed to read audit log: {reason}")]
    Io { reason: String },
}

/// Read and parse every line of the audit log at `path`.
///
/// # Errors
///
/// Returns [`ExplainError::Io`] if `path` cannot be read at all. A
/// malformed or wrong-version *line* is not an error here — see
/// [`LogScan::unreadable`].
pub fn read_log(path: &Path) -> Result<LogScan, ExplainError> {
    let contents = fs::read_to_string(path).map_err(|e| ExplainError::Io {
        reason: e.to_string(),
    })?;
    let mut records = Vec::new();
    let mut unreadable = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_number = u64::try_from(index).unwrap_or(u64::MAX) + 1;
        // Check the version before attempting to parse the payload as an
        // AuditRecord: a version-mismatched line's payload shape is, by
        // definition, not guaranteed to match this build's AuditRecord
        // at all, so parsing it directly would misreport a version
        // mismatch as a generic parse failure.
        match serde_json::from_str::<Versioned<serde_json::Value>>(line) {
            Ok(envelope) if envelope.version != DOMAIN_SCHEMA_VERSION => {
                unreadable.push(UnreadableLine {
                    line_number,
                    reason: UnreadableReason::UnsupportedVersion {
                        found: envelope.version,
                        expected: DOMAIN_SCHEMA_VERSION,
                    },
                });
            }
            Ok(_) => match serde_json::from_str::<Versioned<AuditRecord>>(line) {
                Ok(envelope) => records.push(envelope.payload),
                Err(e) => unreadable.push(UnreadableLine {
                    line_number,
                    reason: UnreadableReason::Malformed {
                        reason: e.to_string(),
                    },
                }),
            },
            Err(e) => unreadable.push(UnreadableLine {
                line_number,
                reason: UnreadableReason::Malformed {
                    reason: e.to_string(),
                },
            }),
        }
    }
    let gaps = detect_gaps(&records, &unreadable);
    Ok(LogScan {
        records,
        unreadable,
        gaps,
    })
}

/// For each issuer instance observed (readable or not — an unreadable
/// line's sequence isn't known, so this only ranges over what *is*
/// known: readable records), find sequence numbers strictly between the
/// min and max observed that never appeared.
fn detect_gaps(
    records: &[AuditRecord],
    _unreadable: &[UnreadableLine],
) -> Vec<crate::record::AuditEventId> {
    let mut by_instance: BTreeMap<IssuerInstanceId, Vec<u64>> = BTreeMap::new();
    for record in records {
        by_instance
            .entry(record.event_id.instance.clone())
            .or_default()
            .push(record.event_id.sequence);
    }
    let mut gaps = Vec::new();
    for (instance, mut sequences) in by_instance {
        sequences.sort_unstable();
        if let (Some(&min), Some(&max)) = (sequences.first(), sequences.last()) {
            let present: std::collections::HashSet<u64> = sequences.into_iter().collect();
            for sequence in min..=max {
                if !present.contains(&sequence) {
                    gaps.push(crate::record::AuditEventId {
                        instance: instance.clone(),
                        sequence,
                    });
                }
            }
        }
    }
    gaps
}

/// How a caller selects which record(s) they want explained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Event(crate::record::AuditEventId),
    Lease(LeaseId),
    /// Every record naming this pid as the peer — returned in file
    /// order, **not** narrowed to "the most recent," since pids are
    /// reused and each record's own `process_start` evidence is what
    /// actually distinguishes them (same three-state discipline the
    /// rest of this codebase uses for identity comparison).
    Pid(u32),
}

/// The result of resolving one [`Selector`] against a [`LogScan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionResult<'a> {
    Found(Vec<&'a AuditRecord>),
    NotFound,
    /// The selected [`Selector::Event`] id falls inside an observed
    /// sequence gap for its instance — the record may exist and simply
    /// failed to persist, distinct from an id that was never issued.
    PossiblyLost,
}

/// Resolve `selector` against `scan`.
#[must_use]
pub fn select<'a>(scan: &'a LogScan, selector: &Selector) -> SelectionResult<'a> {
    match selector {
        Selector::Event(id) => {
            if let Some(record) = scan.records.iter().find(|r| &r.event_id == id) {
                return SelectionResult::Found(vec![record]);
            }
            if scan.gaps.contains(id) {
                return SelectionResult::PossiblyLost;
            }
            SelectionResult::NotFound
        }
        Selector::Lease(lease_id) => {
            let matches: Vec<&AuditRecord> = scan
                .records
                .iter()
                .filter(|r| r.lease_id() == Some(lease_id))
                .collect();
            if matches.is_empty() {
                SelectionResult::NotFound
            } else {
                SelectionResult::Found(matches)
            }
        }
        Selector::Pid(pid) => {
            let matches: Vec<&AuditRecord> = scan
                .records
                .iter()
                .filter(|r| r.peer.credential.pid == *pid)
                .collect();
            if matches.is_empty() {
                SelectionResult::NotFound
            } else {
                SelectionResult::Found(matches)
            }
        }
    }
}

/// Render one record as human-readable text.
#[must_use]
pub fn render(record: &AuditRecord) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "event: {}", record.event_id);
    let _ = writeln!(
        out,
        "recorded_at: unix {}s.{:09}n",
        record.recorded_at.unix_secs, record.recorded_at.nanos
    );
    let _ = writeln!(out, "operation: {:?}", record.operation);
    let _ = writeln!(out, "requested: {:?}", record.requested);
    let _ = writeln!(
        out,
        "peer: pid={} consistency={:?}",
        record.peer.credential.pid, record.peer.consistency
    );
    let _ = writeln!(
        out,
        "workload: uid={:?} executable_path={:?} executable_hash={:?} cgroup={:?}",
        record.peer.observed.workload.uid,
        record.peer.observed.workload.executable_path,
        record.peer.observed.workload.executable_hash,
        record.peer.observed.cgroup_path,
    );
    let _ = writeln!(out, "outcome: {:?}", record.outcome);
    let _ = writeln!(out, "response: {:?}", record.response);
    if matches!(
        record.requested,
        crate::record::RecordedRequest::ReleaseLease { .. }
    ) {
        out.push_str(
            "note: a release record does not name a resource — correlate to the grant record \
             for the same lease id to recover it.\n",
        );
    }
    out
}
