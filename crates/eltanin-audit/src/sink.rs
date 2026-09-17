//! Append-only NDJSON audit sink (F-M1-009, HORO-824).
//!
//! One `Versioned<LogEntry>` JSON document per line — a
//! [`crate::record::LogEntry::Decision`] for every appended [`AuditEntry`],
//! plus a [`crate::record::LogEntry::Agent`] marker whenever this sink
//! rotates the log to a new generation (see "Bounded retention" below) —
//! opened append-only at file mode `0600` (Unix). [`AuditFileSink`]
//! mints the [`AuditEventId`] and [`crate::record::WallClockTime`] for
//! every entry — a caller supplies only what it observed
//! ([`AuditEntry`]), never the id or timestamp, so nothing outside this
//! sink can forge or backdate a record.
//!
//! # Bounded retention (AC6)
//!
//! A path-backed sink (built via [`AuditFileSink::open`]) rotates to a
//! new generation once the current one would exceed
//! [`AuditFileSink::with_max_bytes`]'s threshold (64 MiB by default):
//! the current file is renamed to `<path>.1` (overwriting any prior
//! `.1`, which is deliberately discarded — this is the one retained
//! generation, bounding total storage at ~128 MiB with zero
//! configuration), a fresh file is opened at `<path>`, and a
//! [`crate::record::RecordedAgentEvent::AuditLogRotated`] marker is
//! written as the new generation's first entry. A [`AuditFileSink::from_writer`]
//! sink has no path to rotate to and never rotates.
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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use eltanin_core::envelope::Versioned;
use eltanin_core::lease::IssuerInstanceId;

use crate::record::{
    AgentEventRecord, AuditEventId, AuditRecord, LogEntry, RecordedAgentEvent,
    RecordedEnforcementMode, RecordedOperation, RecordedOutcome, RecordedPeer, RecordedRequest,
};
use crate::record::{AuditClock, SystemWallClock};

/// Default rotation threshold: 64 MiB per generation. [`AuditFileSink`]
/// retains exactly one prior generation (the renamed `.1` file), so this
/// bounds total on-disk audit storage at ~128 MiB with zero
/// configuration — AC6's "bounded default."
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// The on-disk sibling path a rotatable log rotates into: `<path>.1`.
/// Shared between [`AuditFileSink`] (which writes it) and
/// [`crate::explain::read_log`] (which reads it) so the naming
/// convention lives in exactly one place.
#[must_use]
pub fn rotated_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".1");
    PathBuf::from(s)
}

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
    /// Rotation happens under this same lock (see [`Self::append`]) so
    /// there is never a window where a concurrent write could interleave
    /// with a rotation in progress.
    state: Mutex<SinkState>,
    instance: IssuerInstanceId,
    failed_writes: AtomicU64,
    clock: Arc<dyn AuditClock>,
    /// The real file path this sink was opened at, or `None` for a
    /// [`Self::from_writer`] sink. Rotation requires a path to rename
    /// to/from, so `from_writer`-constructed sinks **never rotate**,
    /// regardless of how many bytes are written — see
    /// [`Self::from_writer`]'s own doc comment.
    path: Option<PathBuf>,
    max_bytes: u64,
}

struct SinkState {
    writer: Box<dyn Write + Send>,
    next_sequence: u64,
    /// Bytes written into the *current* generation so far — seeded from
    /// the real file's size on [`AuditFileSink::open`] so a reopened sink
    /// continues counting from where a previous process run left off.
    /// Always `0` for a `from_writer` sink (irrelevant there, since such
    /// a sink never rotates).
    bytes_written: u64,
    /// The previous rotation's own `rotated_at_sequence`, kept only in
    /// memory. **Accepted limitation**: this does not survive a process
    /// restart — if the agent restarts between two rotations, the next
    /// rotation after restart reports `discarded_through_sequence: None`
    /// even though an earlier rotation already discarded a generation.
    /// This under-reports discarded ranges; it never over-reports one,
    /// so [`crate::explain`]'s retention-floor calculation stays a safe
    /// (if occasionally conservative) lower bound rather than a false
    /// claim.
    last_rotation_sequence: Option<u64>,
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
        let bytes_written = file
            .metadata()
            .map_err(|e| AuditSinkError::Io {
                reason: e.to_string(),
            })?
            .len();
        let mut sink = Self::from_writer(file, instance);
        sink.path = Some(path.to_path_buf());
        sink.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .bytes_written = bytes_written;
        Ok(sink)
    }

    /// Build a sink over an arbitrary [`Write`] — the general
    /// constructor `open` is implemented in terms of. Public because
    /// "write NDJSON audit entries somewhere other than a plain file" is
    /// a legitimate use, not just a test hook.
    ///
    /// A sink built this way has no real path to rotate to/from, so it
    /// **never rotates** — [`Self::append`] never triggers rotation for
    /// it, regardless of `max_bytes` or how many bytes are written.
    #[must_use]
    pub fn from_writer(writer: impl Write + Send + 'static, instance: IssuerInstanceId) -> Self {
        Self {
            state: Mutex::new(SinkState {
                writer: Box::new(writer),
                next_sequence: 0,
                bytes_written: 0,
                last_rotation_sequence: None,
            }),
            instance,
            failed_writes: AtomicU64::new(0),
            clock: Arc::new(SystemWallClock),
            path: None,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }

    /// Override the clock — tests only, for deterministic
    /// `recorded_at` values.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn AuditClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Override the rotation threshold (default 64 MiB). Has no effect
    /// on a [`Self::from_writer`] sink, which never rotates regardless
    /// of this value.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
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

        // Decide rotation *before* reserving this entry's own sequence
        // number — using a probe record built at the sequence this entry
        // would get if no rotation happens. This ordering matters: if
        // rotation *does* happen, `maybe_rotate` consumes the next
        // sequence number for its marker, so the entry must get the
        // sequence number *after* that, never before it. Reserving the
        // entry's sequence first (and rotating after) would let a
        // smaller sequence number end up physically written after a
        // larger one — breaking the "sequence order == file order"
        // invariant this sink otherwise guarantees.
        let probe_sequence = state.next_sequence;
        let probe = LogEntry::Decision(AuditRecord {
            event_id: AuditEventId {
                instance: self.instance.clone(),
                sequence: probe_sequence,
            },
            recorded_at,
            operation: entry.operation,
            requested: entry.requested,
            peer: entry.peer,
            outcome: entry.outcome,
            response: entry.response,
            mode: RecordedEnforcementMode::Enforce,
            session: None,
        });

        let result = self.maybe_rotate(&mut state, &probe).and_then(|()| {
            let sequence = state.next_sequence;
            state.next_sequence += 1;
            let mut record = match probe {
                LogEntry::Decision(record) => record,
                LogEntry::Agent(_) => unreachable!("probe is always LogEntry::Decision"),
            };
            record.event_id.sequence = sequence;
            let line = LogEntry::Decision(record);
            let written = Self::write_line(&mut state.writer, &line)?;
            state.bytes_written += written as u64;
            Ok(sequence)
        });
        drop(state);
        if result.is_err() {
            self.failed_writes.fetch_add(1, Ordering::SeqCst);
        }
        result.map(|sequence| AuditEventId {
            instance: self.instance.clone(),
            sequence,
        })
    }

    /// Append an agent-emitted event (e.g. a lease expiring on its own —
    /// HORO-796 subtask 2), sharing this sink's sequence space with
    /// [`Self::append`] exactly as [`AgentEventRecord`]'s own docs
    /// require. Mirrors `append`'s "probe, maybe rotate, then reserve"
    /// ordering precisely — see that method's own doc comment for why
    /// the sequence must never be reserved before rotation is decided.
    ///
    /// # Errors
    ///
    /// Returns [`AuditSinkError`] if serialization or the write itself
    /// fails.
    pub fn append_agent_event(
        &self,
        event: RecordedAgentEvent,
    ) -> Result<AuditEventId, AuditSinkError> {
        let recorded_at = self.clock.now();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);

        let probe_sequence = state.next_sequence;
        let probe = LogEntry::Agent(AgentEventRecord {
            event_id: AuditEventId {
                instance: self.instance.clone(),
                sequence: probe_sequence,
            },
            recorded_at,
            event,
        });

        let result = self.maybe_rotate(&mut state, &probe).and_then(|()| {
            let sequence = state.next_sequence;
            state.next_sequence += 1;
            let mut record = match probe {
                LogEntry::Agent(record) => record,
                LogEntry::Decision(_) => unreachable!("probe is always LogEntry::Agent"),
            };
            record.event_id.sequence = sequence;
            let line = LogEntry::Agent(record);
            let written = Self::write_line(&mut state.writer, &line)?;
            state.bytes_written += written as u64;
            Ok(sequence)
        });
        drop(state);
        if result.is_err() {
            self.failed_writes.fetch_add(1, Ordering::SeqCst);
        }
        result.map(|sequence| AuditEventId {
            instance: self.instance.clone(),
            sequence,
        })
    }

    /// Rotate to a new generation, under the same lock as the write that
    /// triggered it, if `upcoming` would push the current generation
    /// past `self.max_bytes`. No-op for a [`Self::from_writer`] sink
    /// (`self.path.is_none()`), and a no-op while the current generation
    /// is still empty (`bytes_written == 0`) — the latter guards against
    /// a single entry larger than `max_bytes` triggering rotation on
    /// every single append.
    fn maybe_rotate(
        &self,
        state: &mut SinkState,
        upcoming: &LogEntry,
    ) -> Result<(), AuditSinkError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if state.bytes_written == 0 {
            return Ok(());
        }
        let upcoming_len = encoded_len(upcoming)?;
        if state.bytes_written + upcoming_len <= self.max_bytes {
            return Ok(());
        }

        state.writer.flush().map_err(|e| AuditSinkError::Io {
            reason: e.to_string(),
        })?;
        // Drop the old writer (closing its file descriptor) before
        // renaming — matches the design's "flush, drop, then rename"
        // ordering, and keeps this portable to a future Windows
        // transport where a rename can fail while the source is open.
        let old_writer = std::mem::replace(&mut state.writer, Box::new(std::io::sink()));
        drop(old_writer);
        std::fs::rename(path, rotated_path(path)).map_err(|e| AuditSinkError::Io {
            reason: e.to_string(),
        })?;

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
        state.writer = Box::new(file);

        let marker_sequence = state.next_sequence;
        state.next_sequence += 1;
        let discarded_through_sequence = state
            .last_rotation_sequence
            .and_then(|prev| prev.checked_sub(1));
        state.last_rotation_sequence = Some(marker_sequence);

        let marker = LogEntry::Agent(AgentEventRecord {
            event_id: AuditEventId {
                instance: self.instance.clone(),
                sequence: marker_sequence,
            },
            recorded_at: self.clock.now(),
            event: RecordedAgentEvent::AuditLogRotated {
                rotated_at_sequence: marker_sequence,
                discarded_through_sequence,
            },
        });
        let marker_len = Self::write_line(&mut state.writer, &marker)?;
        state.bytes_written = marker_len as u64;
        Ok(())
    }

    fn write_line(writer: &mut dyn Write, entry: &LogEntry) -> Result<usize, AuditSinkError> {
        let mut line = serde_json::to_string(&Versioned::current(entry)).map_err(|e| {
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
            })?;
        Ok(line.len())
    }
}

/// The exact number of bytes [`AuditFileSink::write_line`] would write
/// for `entry` — used only to decide *before* writing whether rotation
/// is needed, so rotation and the eventual real write agree on size.
fn encoded_len(entry: &LogEntry) -> Result<u64, AuditSinkError> {
    let mut line = serde_json::to_string(&Versioned::current(entry)).map_err(|e| {
        AuditSinkError::Serialize {
            reason: e.to_string(),
        }
    })?;
    line.push('\n');
    Ok(line.len() as u64)
}
