//! Explain: read an audit log and answer "what happened for this
//! decision" (F-M1-009, HORO-824).
//!
//! This module only *reads* the log — see
//! `crates/eltanin-agent/tests/audit_reader_isolation.rs` for the
//! mechanical guard that `eltanin-agent`'s own source never calls into
//! it: the agent writes the trail and never reads it, so no edited log
//! line can reach an authorization decision.
//!
//! # Reading across a rotation (AC6)
//!
//! [`crate::sink::AuditFileSink`] rotates a path-backed log into two
//! files on disk: the previous generation at `<path>.1` and the current
//! one at `<path>`. [`read_log`] reads both, `.1` first, concatenated in
//! that order, so a caller never has to know rotation happened at all
//! unless it asks — see [`UnreadableLine::generation`] and
//! [`LogScan::retention_floor`] for the pieces that let a caller find
//! out anyway.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use eltanin_core::envelope::{Versioned, DOMAIN_SCHEMA_VERSION};
use eltanin_core::lease::{IssuerInstanceId, LeaseId};

use crate::record::{AgentEventRecord, AuditRecord, LogEntry, RecordedAgentEvent};
use crate::sink::rotated_path;

/// What went wrong reading one line of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnreadableReason {
    UnsupportedVersion { found: u16, expected: u16 },
    Malformed { reason: String },
}

/// Which on-disk generation a scanned line came from — needed once a
/// log spans two files (see this module's docs on reading across a
/// rotation) so a line number alone stays meaningful: "line 3" is
/// ambiguous once there are two files, "line 3 of the rotated
/// generation" is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogGeneration {
    /// The renamed `<path>.1` file — the previous generation.
    Rotated,
    /// The live file at `<path>` — the current generation.
    Current,
}

/// One log line that could not be turned into a [`LogEntry`] —
/// reported explicitly, never silently skipped and never fatal to
/// reading the rest of the log. Mirrors `Versioned::into_current`'s own
/// "fail explicitly, don't guess" stance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableLine {
    pub generation: LogGeneration,
    pub line_number: u64,
    pub reason: UnreadableReason,
    /// The event id recovered from the line's envelope, when the
    /// envelope itself parsed even though its payload couldn't be read
    /// as this build's [`LogEntry`] — e.g. an [`UnreadableReason::UnsupportedVersion`]
    /// line whose `event_id` field has a stable enough shape to extract.
    /// `None` when the line couldn't be parsed as an envelope at all.
    /// [`LogScan::gaps`] treats a recovered id as *present*, so a line that
    /// exists on disk under a different schema version never masquerades
    /// as a possibly-lost write.
    pub event_id: Option<crate::record::AuditEventId>,
}

/// The result of scanning an audit log: every decision record and agent
/// event that parsed, every line that didn't, and every sequence gap
/// observed per issuer instance.
#[derive(Debug, Clone, Default)]
pub struct LogScan {
    pub records: Vec<AuditRecord>,
    /// Agent-emitted events (e.g. [`RecordedAgentEvent::AuditLogRotated`])
    /// read from the log — kept separate from `records` so every
    /// existing `records`-based consumer (`Selector::Pid`/`Lease`,
    /// `render`) is unaffected by this type's addition.
    pub agent_events: Vec<AgentEventRecord>,
    pub unreadable: Vec<UnreadableLine>,
    /// Event ids whose sequence number falls between the retention floor
    /// (see [`Self::retention_floor`], `0` if none) and the highest
    /// sequence actually observed for their `instance` (as a readable
    /// entry or a recovered [`UnreadableLine::event_id`]), but which
    /// never appeared. [`AuditFileSink`](crate::sink::AuditFileSink)
    /// reserves a sequence number before attempting a write and never
    /// reuses it on failure, so a gap here is the honest, structural
    /// signal that a record *may* be missing because persistence
    /// failed. **Accepted limitation**: this cannot detect a lost
    /// *trailing* write — the highest sequence an instance ever attempted
    /// is only known from what was actually observed, so a lost last
    /// write (or every write from an instance) is indistinguishable from
    /// that instance never having run. See
    /// `docs/product/SECURITY_MODEL.md`'s "Audit & explain evidence"
    /// section.
    pub gaps: Vec<crate::record::AuditEventId>,
    /// Per issuer instance, the highest sequence number that has been
    /// permanently discarded by log rotation (inclusive) — derived from
    /// the most recent [`RecordedAgentEvent::AuditLogRotated`] marker's
    /// `discarded_through_sequence` observed for that instance. An
    /// instance absent from this map has never had anything discarded.
    /// [`select`] uses this to distinguish "genuinely discarded" from
    /// "possibly lost" from "never issued."
    pub retention_floor: BTreeMap<IssuerInstanceId, u64>,
}

/// Why [`read_log`] could not be performed at all (distinct from a
/// per-line [`UnreadableLine`], which doesn't stop the read).
#[derive(Debug, thiserror::Error)]
pub enum ExplainError {
    #[error("failed to read audit log: {reason}")]
    Io { reason: String },
}

/// Read and parse every line of the audit log at `path`, spanning a
/// rotation transparently: if `<path>.1` exists (see
/// [`crate::sink::rotated_path`]), it is read first, then `path` —
/// matching write order, since `<path>.1` always holds the *older*
/// generation.
///
/// # Errors
///
/// Returns [`ExplainError::Io`] if `path` cannot be read at all. A
/// malformed or wrong-version *line* is not an error here — see
/// [`LogScan::unreadable`].
pub fn read_log(path: &Path) -> Result<LogScan, ExplainError> {
    let mut records = Vec::new();
    let mut agent_events = Vec::new();
    let mut unreadable = Vec::new();

    let rotated = rotated_path(path);
    if rotated.exists() {
        let contents = fs::read_to_string(&rotated).map_err(|e| ExplainError::Io {
            reason: e.to_string(),
        })?;
        scan_generation(
            &contents,
            LogGeneration::Rotated,
            &mut records,
            &mut agent_events,
            &mut unreadable,
        );
    }

    let contents = fs::read_to_string(path).map_err(|e| ExplainError::Io {
        reason: e.to_string(),
    })?;
    scan_generation(
        &contents,
        LogGeneration::Current,
        &mut records,
        &mut agent_events,
        &mut unreadable,
    );

    let retention_floor = compute_retention_floor(&agent_events);
    let gaps = detect_gaps(&records, &agent_events, &unreadable, &retention_floor);
    Ok(LogScan {
        records,
        agent_events,
        unreadable,
        gaps,
        retention_floor,
    })
}

/// Scan one generation's raw file contents, appending readable entries
/// and unreadable lines (tagged with `generation`) into the caller's
/// accumulators.
fn scan_generation(
    contents: &str,
    generation: LogGeneration,
    records: &mut Vec<AuditRecord>,
    agent_events: &mut Vec<AgentEventRecord>,
    unreadable: &mut Vec<UnreadableLine>,
) {
    for (index, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_number = u64::try_from(index).unwrap_or(u64::MAX) + 1;
        // Check the version before attempting to parse the payload as a
        // LogEntry: a version-mismatched line's payload shape is, by
        // definition, not guaranteed to match this build's LogEntry at
        // all, so parsing it directly would misreport a version mismatch
        // as a generic parse failure.
        match serde_json::from_str::<Versioned<serde_json::Value>>(line) {
            Ok(envelope) if envelope.version != DOMAIN_SCHEMA_VERSION => {
                unreadable.push(UnreadableLine {
                    generation,
                    line_number,
                    reason: UnreadableReason::UnsupportedVersion {
                        found: envelope.version,
                        expected: DOMAIN_SCHEMA_VERSION,
                    },
                    event_id: recover_event_id(&envelope.payload),
                });
            }
            Ok(envelope) => match serde_json::from_str::<Versioned<LogEntry>>(line) {
                Ok(entry_envelope) => match entry_envelope.payload {
                    LogEntry::Decision(record) => records.push(record),
                    LogEntry::Agent(event) => agent_events.push(event),
                },
                Err(e) => unreadable.push(UnreadableLine {
                    generation,
                    line_number,
                    reason: UnreadableReason::Malformed {
                        reason: e.to_string(),
                    },
                    event_id: recover_event_id(&envelope.payload),
                }),
            },
            Err(e) => unreadable.push(UnreadableLine {
                generation,
                line_number,
                reason: UnreadableReason::Malformed {
                    reason: e.to_string(),
                },
                event_id: None,
            }),
        }
    }
}

/// Best-effort recovery of an `event_id` from a payload that didn't parse
/// as this build's [`LogEntry`] — used only so [`detect_gaps`] can treat
/// a line that exists on disk (just under a different schema version) as
/// *present*, never as a possibly-lost write. Both [`LogEntry::Decision`]
/// and [`LogEntry::Agent`] carry `event_id` as a top-level field once
/// their internal tag is flattened onto the same JSON object
/// (`{"record":"decision"/"agent", "event_id": {...}, ...}`), so this
/// generic lookup works unchanged for either arm — it never needs to
/// know which arm produced the line. `AuditEventId` serializes as
/// `{"instance": <string>, "sequence": <u64>}` (`IssuerInstanceId` is
/// `#[serde(transparent)]`); this shape is not expected to change across
/// schema versions, but recovery is intentionally best-effort — a
/// failure here just means the line contributes no extra gap-detection
/// precision, not a hard error.
fn recover_event_id(payload: &serde_json::Value) -> Option<crate::record::AuditEventId> {
    let event_id = payload.get("event_id")?;
    let instance = event_id.get("instance")?.as_str()?;
    let sequence = event_id.get("sequence")?.as_u64()?;
    Some(crate::record::AuditEventId {
        instance: IssuerInstanceId::new(instance),
        sequence,
    })
}

/// For each issuer instance observed, the highest sequence number
/// permanently discarded by rotation — the latest
/// [`RecordedAgentEvent::AuditLogRotated`] marker's
/// `discarded_through_sequence`, `.max()`-combined across every marker
/// seen for that instance (there are at most two on disk at once — one
/// from `<path>.1`'s own creation, one from `<path>`'s — and later
/// rotations only ever discard more, never less, so the max is always
/// the most current answer regardless of read order).
fn compute_retention_floor(agent_events: &[AgentEventRecord]) -> BTreeMap<IssuerInstanceId, u64> {
    let mut floor: BTreeMap<IssuerInstanceId, u64> = BTreeMap::new();
    for event in agent_events {
        if let RecordedAgentEvent::AuditLogRotated {
            discarded_through_sequence: Some(discarded),
            ..
        } = &event.event
        {
            floor
                .entry(event.event_id.instance.clone())
                .and_modify(|current| *current = (*current).max(*discarded))
                .or_insert(*discarded);
        }
    }
    floor
}

/// For each issuer instance observed — readable records and agent
/// events, plus any [`UnreadableLine`] whose `event_id` could be
/// recovered — find every sequence number from the instance's retention
/// floor (exclusive; see [`LogScan::retention_floor`]) up to the highest
/// observed that never appeared as present.
///
/// The range starts at `retention_floor + 1` (or `0` if there is no
/// floor), not always `0`: [`crate::sink::AuditFileSink`] always starts
/// an instance's sequence space at `0`, so a lost *first* write would
/// otherwise fall outside every observed range and be misreported as
/// "never issued" rather than "possibly lost" — but once rotation has
/// discarded a range, starting from `0` would instead flood false
/// "possibly lost" reports for sequences that were never lost, only
/// rotated away on purpose. This does **not** close the symmetric case
/// at the *trailing* edge — a lost *last* write, or every write from an
/// instance that never persisted anything, is structurally
/// indistinguishable from that instance never having run; see
/// `docs/product/SECURITY_MODEL.md`'s "Audit & explain evidence" section
/// for this accepted limitation of a purely local, best-effort log.
fn detect_gaps(
    records: &[AuditRecord],
    agent_events: &[AgentEventRecord],
    unreadable: &[UnreadableLine],
    retention_floor: &BTreeMap<IssuerInstanceId, u64>,
) -> Vec<crate::record::AuditEventId> {
    let mut by_instance: BTreeMap<IssuerInstanceId, BTreeSet<u64>> = BTreeMap::new();
    for record in records {
        by_instance
            .entry(record.event_id.instance.clone())
            .or_default()
            .insert(record.event_id.sequence);
    }
    for event in agent_events {
        by_instance
            .entry(event.event_id.instance.clone())
            .or_default()
            .insert(event.event_id.sequence);
    }
    for line in unreadable {
        if let Some(id) = &line.event_id {
            by_instance
                .entry(id.instance.clone())
                .or_default()
                .insert(id.sequence);
        }
    }
    let mut gaps = Vec::new();
    for (instance, present) in by_instance {
        let Some(&max) = present.iter().max() else {
            continue;
        };
        let start = retention_floor
            .get(&instance)
            .map_or(0, |floor| floor.saturating_add(1));
        for sequence in start..=max {
            if !present.contains(&sequence) {
                gaps.push(crate::record::AuditEventId {
                    instance: instance.clone(),
                    sequence,
                });
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
    /// No record with this id was found, and it does not fall inside any
    /// observed [`LogScan::gaps`] or below the instance's
    /// [`LogScan::retention_floor`]. Ordinarily this means the id was
    /// never issued — but see the accepted trailing-edge limitation on
    /// [`LogScan::gaps`]: an id beyond the highest sequence this instance
    /// was ever observed to reach is reported `NotFound` even if it was
    /// in fact reserved and lost, since nothing in a purely local log can
    /// distinguish that case from "never issued" without an independent
    /// liveness signal.
    NotFound,
    /// The selected [`Selector::Event`] id falls inside an observed
    /// sequence gap for its instance — the record may exist and simply
    /// failed to persist, distinct from an id that was never issued.
    PossiblyLost,
    /// The selected [`Selector::Event`] id falls at or below its
    /// instance's [`LogScan::retention_floor`] — it was legitimately
    /// issued and recorded, but its generation has since been rotated
    /// away by [`crate::sink::AuditFileSink`]'s bounded-retention policy.
    /// Distinct from [`Self::PossiblyLost`] (which signals a possible
    /// persistence failure) and from [`Self::NotFound`] (which signals
    /// the id was likely never issued at all).
    RetentionDiscarded,
}

/// Resolve `selector` against `scan`.
#[must_use]
pub fn select<'a>(scan: &'a LogScan, selector: &Selector) -> SelectionResult<'a> {
    match selector {
        Selector::Event(id) => {
            // A record physically present in the scan always wins, even
            // if its sequence happens to be at or below a
            // `retention_floor` derived from a *different* rotation
            // history than the one that actually produced this record
            // (e.g. a hand-crafted log, or one instance's floor spuriously
            // overlapping another's range) — presence on disk is ground
            // truth, the floor is only an inference for what's absent.
            if let Some(record) = scan.records.iter().find(|r| &r.event_id == id) {
                return SelectionResult::Found(vec![record]);
            }
            if scan
                .retention_floor
                .get(&id.instance)
                .is_some_and(|floor| id.sequence <= *floor)
            {
                return SelectionResult::RetentionDiscarded;
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
