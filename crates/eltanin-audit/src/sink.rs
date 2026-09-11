//! Append-only NDJSON audit sink (F-M1-009, HORO-824).
//!
//! One `Versioned<AuditRecord>` JSON document per line, opened
//! append-only at file mode `0600` (Unix). [`AuditFileSink`] mints the
//! [`AuditEventId`] and [`crate::record::WallClockTime`] for every entry — a caller
//! supplies only what it observed ([`AuditEntry`]), never the id or
//! timestamp, so nothing outside this sink can forge or backdate a
//! record.
//!
//! # Durability is best-effort, by explicit founder decision
//!
//! [`crate::record::AuditRecord`]'s own docs state "audit is evidence,
//! not authority." Consistent with that: a write failure here is
//! reported to the caller (so `eltanin-agent`'s adapter can log it
//! loudly) but **never changes an already-computed authorization
//! result** — `eltanin_agent::authz::event::EventSink::record`'s
//! signature returns `()`, a decision already made by the time this
//! sink is even called (HORO-840, Feature-Done). Reopening that
//! contract to make audit I/O authoritative was explicitly rejected:
//! an agent that denies access because its *disk* is unhappy is a new,
//! separately-designed failure mode, not an MVP 1.0 requirement.
//!
//! Instead: [`AuditFileSink::append`] reserves a sequence number
//! *before* attempting the write, unconditionally, and
//! [`AuditFileSink::failed_writes`] counts failures — so a gap between
//! two observed sequence numbers in the log is the caller-visible,
//! honest signal that a record *may* be missing because persistence
//! failed, distinguishable by [`crate::explain`] from an id that was
//! simply never issued. See [`crate::explain::LogScan::gaps`].

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use eltanin_core::envelope::Versioned;
use eltanin_core::lease::IssuerInstanceId;

use crate::record::{AuditClock, SystemWallClock};
use crate::record::{
    AuditEventId, AuditRecord, RecordedOperation, RecordedOutcome, RecordedPeer, RecordedRequest,
};

/// What a caller observed for one request — everything in
/// [`AuditRecord`] except the id and timestamp, which only
/// [`AuditFileSink`] mints.
pub struct AuditEntry {
    pub operation: RecordedOperation,
    pub requested: RecordedRequest,
    pub peer: RecordedPeer,
    pub outcome: RecordedOutcome,
    pub response: eltanin_protocol::response::AgentResponse,
}

/// Why [`AuditFileSink::open`] or [`AuditFileSink::append`] failed.
#[derive(Debug, thiserror::Error)]
pub enum AuditSinkError {
    #[error("audit log I/O error: {reason}")]
    Io { reason: String },
    #[error("failed to serialize audit record: {reason}")]
    Serialize { reason: String },
}

/// An append-only NDJSON audit log for one agent instance. Writes
/// through an arbitrary [`Write`], not necessarily a plain file — see
/// [`Self::from_writer`], which exists specifically so a test can inject
/// a writer that reliably fails, rather than relying on filesystem
/// races (permission changes, deleted-but-open files) that don't
/// reliably fail a write already in flight on every platform.
pub struct AuditFileSink {
    /// The writer and the next sequence number live behind one lock so a
    /// sequence is reserved and its line written in the same critical
    /// section — otherwise two threads could reserve sequences 5 and 6
    /// but race for the writer in the opposite order, leaving sequence 6
    /// physically before sequence 5 in the file even though callers
    /// (`explain::Selector::Pid`/`Lease`, `render`) rely on file order.
    state: Mutex<SinkState>,
    instance: IssuerInstanceId,
    failed_writes: AtomicU64,
    clock: Arc<dyn AuditClock>,
}

struct SinkState {
    writer: Box<dyn Write + Send>,
    next_sequence: u64,
}

impl AuditFileSink {
    /// Open (creating if absent) the audit log at `path` for `instance`.
    /// Created at mode `0600` on Unix — this file is evidence, not
    /// meant for sharing, and contains process ancestry / executable
    /// paths per the redaction contract in `docs/product/SECURITY_MODEL.md`.
    ///
    /// # Errors
    ///
    /// Returns [`AuditSinkError::Io`] if `path` cannot be opened.
    pub fn open(path: &Path, instance: IssuerInstanceId) -> Result<Self, AuditSinkError> {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|e| AuditSinkError::Io {
            reason: e.to_string(),
        })?;
        Ok(Self::from_writer(file, instance))
    }

    /// Build a sink over an arbitrary [`Write`] — the general
    /// constructor `open` is implemented in terms of. Public because
    /// "write NDJSON audit entries somewhere other than a plain file" is
    /// a legitimate use, not just a test hook.
    #[must_use]
    pub fn from_writer(writer: impl Write + Send + 'static, instance: IssuerInstanceId) -> Self {
        Self {
            state: Mutex::new(SinkState {
                writer: Box::new(writer),
                next_sequence: 0,
            }),
            instance,
            failed_writes: AtomicU64::new(0),
            clock: Arc::new(SystemWallClock),
        }
    }

    /// Override the clock — tests only, for deterministic
    /// `recorded_at` values.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn AuditClock>) -> Self {
        self.clock = clock;
        self
    }

    /// How many [`Self::append`] calls have failed so far. Exposed so a
    /// caller (e.g. `eltanin-agentd`) can surface audit-persistence
    /// degradation through whatever observability it already has,
    /// without this crate inventing a new metrics subsystem.
    #[must_use]
    pub fn failed_writes(&self) -> u64 {
        self.failed_writes.load(Ordering::SeqCst)
    }

    /// Append `entry`, minting its [`AuditEventId`] and
    /// [`crate::record::WallClockTime`].
    ///
    /// The sequence number is reserved and the line written under the
    /// *same* lock, so sequence order and file (write) order are always
    /// identical — a reader relying on file order (e.g.
    /// `explain::Selector::Pid`/`Lease`) never observes sequence 6
    /// physically before sequence 5. The sequence is never reused on
    /// failure — a failure still advances the sequence space, leaving a
    /// detectable gap in the log rather than a silently reused id. See
    /// [`crate::explain::LogScan::gaps`].
    ///
    /// # Errors
    ///
    /// Returns [`AuditSinkError`] if serialization or the write itself
    /// fails. The caller decides what to do — this sink never blocks or
    /// retries.
    pub fn append(&self, entry: AuditEntry) -> Result<AuditEventId, AuditSinkError> {
        let recorded_at = self.clock.now();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let sequence = state.next_sequence;
        state.next_sequence += 1;
        let event_id = AuditEventId {
            instance: self.instance.clone(),
            sequence,
        };
        let record = AuditRecord {
            event_id: event_id.clone(),
            recorded_at,
            operation: entry.operation,
            requested: entry.requested,
            peer: entry.peer,
            outcome: entry.outcome,
            response: entry.response,
        };
        let result = Self::write_line(&mut state.writer, &record);
        drop(state);
        if result.is_err() {
            self.failed_writes.fetch_add(1, Ordering::SeqCst);
        }
        result.map(|()| event_id)
    }

    fn write_line(writer: &mut dyn Write, record: &AuditRecord) -> Result<(), AuditSinkError> {
        let mut line = serde_json::to_string(&Versioned::current(record)).map_err(|e| {
            AuditSinkError::Serialize {
                reason: e.to_string(),
            }
        })?;
        line.push('\n');
        writer
            .write_all(line.as_bytes())
            .and_then(|()| writer.flush())
            .map_err(|e| AuditSinkError::Io {
                reason: e.to_string(),
            })
    }
}
