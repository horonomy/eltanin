//! Argv parsing for `eltanin run` (F-M1-008, HORO-845).
//!
//! Reads `OsString` throughout — never `String` — so arbitrary bytes
//! (non-UTF-8 paths, embedded shell metacharacters) round-trip unchanged
//! into the spawned child's argv. See
//! `docs/product/CLI_CONTRACT.md`'s "Argv grammar" section.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::time::Duration;

use eltanin_audit::explain::Selector;
use eltanin_audit::record::AuditEventId;
use eltanin_core::approval::{ApprovalDisposition, ApprovalId};
use eltanin_core::lease::{IssuerInstanceId, LeaseId};

use crate::profile::ProfileName;

/// Default `eltanin audit` line limit (F-M2-006, HORO-796 subtask 4) —
/// deliberately small: this command is a human-facing recent-activity
/// browse, not a full log dump (`eltanin-explain`'s file-order read
/// already serves that need).
pub const DEFAULT_AUDIT_LIMIT: usize = 20;

/// A fully parsed `eltanin run` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunInvocation {
    pub profile: ProfileName,
    pub program: OsString,
    pub args: Vec<OsString>,
}

/// A fully parsed `eltanin session <start|list|end>` invocation
/// (F-M2-001, HORO-791). `eltanin run --profile <p> -- <cmd>` (above)
/// stays completely unchanged — this is a new, independent top-level
/// subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionInvocation {
    /// `eltanin session start --profile <name> [--profile <name>...] --ttl <duration>`.
    /// `profiles` is never empty — [`parse_session`] rejects a `start`
    /// with no `--profile` at all.
    Start {
        profiles: Vec<ProfileName>,
        ttl: Duration,
    },
    /// `eltanin session list`.
    List,
    /// `eltanin session end`.
    End,
}

/// A fully parsed `eltanin approve <record|list|forget>` invocation
/// (F-M2-002, HORO-792). `eltanin run`/`eltanin session ...` stay
/// completely unchanged — this is a new, independent top-level
/// subcommand, mirroring `SessionInvocation`'s own shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproveInvocation {
    /// `eltanin approve --profile <name> (--once|--remember|--deny)`.
    Record {
        profile: ProfileName,
        disposition: ApprovalDisposition,
    },
    /// `eltanin approve list`.
    List,
    /// `eltanin approve forget <id>`.
    Forget { id: ApprovalId },
}

/// A fully parsed `eltanin explain (--event|--lease|--pid) <v> [--chain]
/// [--log <path>]` invocation (F-M2-006, HORO-796 subtask 4).
/// `log_path` is `None` when neither `--log` nor `ELTANIN_AUDIT_LOG` (see
/// `crate::explain`) resolves one — reported as a failure at run time,
/// not a usage error, mirroring `eltanin-explain`'s own binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplainInvocation {
    pub selector: Selector,
    /// Follow the causal chain (originating lease grant, related
    /// session, delegation ancestry) rather than just the direct
    /// selection — see `crate::explain`'s module docs for exactly what
    /// this expands.
    pub chain: bool,
    pub log_path: Option<PathBuf>,
}

/// A fully parsed `eltanin audit [--limit N] [--log <path>]` invocation
/// (F-M2-006, HORO-796 subtask 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditInvocation {
    pub limit: usize,
    pub log_path: Option<PathBuf>,
}

/// A fully parsed `eltanin status` invocation (F-M2-006, HORO-796
/// subtask 4). Takes no arguments — a struct rather than a unit type so
/// a future flag is additive, matching this crate's other invocation
/// types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusInvocation;

/// A fully parsed `eltanin dogfood-evidence [--log <path>]` invocation
/// (HORO-1376): a read-only projection of the audit log into the
/// ADR-0012 v1 `DogFood` evidence schema — see `eltanin_dogfood`. Mirrors
/// [`AuditInvocation`]'s own `--log` resolution exactly; this command
/// takes no other argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DogfoodEvidenceInvocation {
    pub log_path: Option<PathBuf>,
}

/// Any of the seven top-level subcommands this binary understands.
/// `eltanin run`'s own argument grammar (see [`parse_run`]) is
/// byte-for-byte unchanged by this type's introduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    Run(RunInvocation),
    Session(SessionInvocation),
    Approve(ApproveInvocation),
    Explain(ExplainInvocation),
    Audit(AuditInvocation),
    Status(StatusInvocation),
    DogfoodEvidence(DogfoodEvidenceInvocation),
}

/// Why argv parsing rejected the invocation — always maps to
/// [`crate::exit::ExitCode::Usage`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    #[error("expected the first argument to be \"run\", got {found:?}")]
    NotRunSubcommand { found: Option<OsString> },
    #[error("expected the first argument to be \"session\", got {found:?}")]
    NotSessionSubcommand { found: Option<OsString> },
    #[error("expected the first argument to be \"approve\", got {found:?}")]
    NotApproveSubcommand { found: Option<OsString> },
    #[error("expected the first argument to be \"explain\", got {found:?}")]
    NotExplainSubcommand { found: Option<OsString> },
    #[error("expected the first argument to be \"audit\", got {found:?}")]
    NotAuditSubcommand { found: Option<OsString> },
    #[error("expected the first argument to be \"status\", got {found:?}")]
    NotStatusSubcommand { found: Option<OsString> },
    #[error("expected the first argument to be \"dogfood-evidence\", got {found:?}")]
    NotDogfoodEvidenceSubcommand { found: Option<OsString> },
    #[error(
        "expected the first argument to be \"run\", \"session\", \"approve\", \"explain\", \
         \"audit\", \"status\", or \"dogfood-evidence\", got {found:?}"
    )]
    UnknownSubcommand { found: Option<OsString> },
    #[error("exactly one of --event, --lease, or --pid is required")]
    SelectorMissing,
    #[error("--event, --lease, and --pid are mutually exclusive")]
    SelectorGivenTwice,
    #[error("--event requires a value")]
    EventMissingValue,
    #[error("--event value {found:?} is not valid (expected <instance>#<sequence>): {reason}")]
    InvalidEvent { found: OsString, reason: String },
    #[error("--lease requires a value")]
    LeaseMissingValue,
    #[error("--lease value {found:?} is not valid (expected <instance>#<sequence>): {reason}")]
    InvalidLease { found: OsString, reason: String },
    #[error("--pid requires a value")]
    PidMissingValue,
    #[error("--pid value {found:?} is not a valid process id: {reason}")]
    InvalidPid { found: OsString, reason: String },
    #[error("--log requires a value")]
    LogMissingValue,
    #[error("--limit requires a value")]
    LimitMissingValue,
    #[error("--limit value {found:?} is not a valid non-negative integer: {reason}")]
    InvalidLimit { found: OsString, reason: String },
    #[error("\"eltanin status\" takes no arguments, got {found:?}")]
    UnexpectedStatusArgument { found: OsString },
    #[error(
        "expected \"approve\" to be followed by \"list\", \"forget\", or --profile, got {found:?}"
    )]
    UnknownApproveAction { found: Option<OsString> },
    #[error("exactly one of --once, --remember, or --deny is required")]
    DispositionMissing,
    #[error("--once, --remember, and --deny are mutually exclusive")]
    DispositionGivenTwice,
    #[error("\"eltanin approve forget\" requires exactly one <id> argument, got none")]
    ForgetIdMissing,
    #[error("\"eltanin approve forget\" takes exactly one argument, got extra: {found:?}")]
    UnexpectedApproveArgument { found: OsString },
    #[error(
        "expected \"session\" to be followed by \"start\", \"list\", or \"end\", got {found:?}"
    )]
    UnknownSessionAction { found: Option<OsString> },
    #[error("--profile requires a value")]
    ProfileMissingValue,
    #[error("--profile was given more than once")]
    ProfileGivenTwice,
    #[error("--profile is required")]
    ProfileMissing,
    #[error("--ttl requires a value")]
    TtlMissingValue,
    #[error("--ttl was given more than once")]
    TtlGivenTwice,
    #[error("--ttl is required")]
    TtlMissing,
    #[error("--ttl value {found:?} is not a valid duration (expected e.g. \"30m\", \"2h\", \"3600s\", or a bare number of seconds)")]
    InvalidTtl { found: OsString },
    #[error("unrecognized argument before \"--\": {found:?}")]
    UnrecognizedArgument { found: OsString },
    #[error(
        "expected \"--\" to separate eltanin run's own flags from the command to launch, but \
         none was found"
    )]
    MissingSeparator,
    #[error("expected a command to run after \"--\", but none was given")]
    EmptyCommand,
    #[error("\"eltanin session {action}\" takes no arguments, got {found:?}")]
    UnexpectedSessionArgument {
        action: &'static str,
        found: OsString,
    },
    #[error(transparent)]
    InvalidProfileName(#[from] crate::profile::ProfileNameError),
}

/// Parse an `eltanin run --profile <name> -- <program> [args...]`
/// invocation. `argv` is everything after the program name itself (i.e.
/// `env::args_os().skip(1)`), starting with the `run` subcommand.
///
/// # Errors
///
/// Returns [`UsageError`] on any malformed invocation — never panics,
/// never guesses a default for a missing required value.
pub fn parse_run(argv: impl IntoIterator<Item = OsString>) -> Result<RunInvocation, UsageError> {
    let mut argv = argv.into_iter();

    let first = argv.next();
    if first.as_deref() != Some(std::ffi::OsStr::new("run")) {
        return Err(UsageError::NotRunSubcommand { found: first });
    }

    let mut profile: Option<ProfileName> = None;
    let mut separator_found = false;
    let mut command: Vec<OsString> = Vec::new();

    while let Some(arg) = argv.next() {
        if separator_found {
            command.push(arg);
            continue;
        }
        if arg == OsStr::new("--") {
            separator_found = true;
            continue;
        }
        if arg == OsStr::new("--profile") {
            if profile.is_some() {
                return Err(UsageError::ProfileGivenTwice);
            }
            let value = argv.next().ok_or(UsageError::ProfileMissingValue)?;
            profile = Some(ProfileName::parse(&value)?);
            continue;
        }
        return Err(UsageError::UnrecognizedArgument { found: arg });
    }

    if !separator_found {
        return Err(UsageError::MissingSeparator);
    }
    let profile = profile.ok_or(UsageError::ProfileMissing)?;
    let mut command = command.into_iter();
    let program = command.next().ok_or(UsageError::EmptyCommand)?;
    let workload_args = command.collect();

    Ok(RunInvocation {
        profile,
        program,
        args: workload_args,
    })
}

/// Parse the top-level argv into either [`Invocation::Run`] (delegating
/// to [`parse_run`], unchanged) or [`Invocation::Session`] (delegating
/// to [`parse_session`]). `argv` is everything after the program name
/// itself, exactly as [`parse_run`] already expects.
///
/// # Errors
///
/// Returns [`UsageError`] — [`UsageError::UnknownSubcommand`] if the
/// first token is neither `"run"` nor `"session"`, or whatever
/// [`parse_run`]/[`parse_session`] themselves return.
pub fn parse(argv: impl IntoIterator<Item = OsString>) -> Result<Invocation, UsageError> {
    let argv: Vec<OsString> = argv.into_iter().collect();
    match argv.first().map(OsString::as_os_str) {
        Some(s) if s == OsStr::new("run") => Ok(Invocation::Run(parse_run(argv)?)),
        Some(s) if s == OsStr::new("session") => Ok(Invocation::Session(parse_session(argv)?)),
        Some(s) if s == OsStr::new("approve") => Ok(Invocation::Approve(parse_approve(argv)?)),
        Some(s) if s == OsStr::new("explain") => Ok(Invocation::Explain(parse_explain(argv)?)),
        Some(s) if s == OsStr::new("audit") => Ok(Invocation::Audit(parse_audit(argv)?)),
        Some(s) if s == OsStr::new("status") => Ok(Invocation::Status(parse_status(argv)?)),
        Some(s) if s == OsStr::new("dogfood-evidence") => {
            Ok(Invocation::DogfoodEvidence(parse_dogfood_evidence(argv)?))
        }
        other => Err(UsageError::UnknownSubcommand {
            found: other.map(OsStr::to_os_string),
        }),
    }
}

/// Parse an `eltanin explain (--event|--lease|--pid) <v> [--chain]
/// [--log <path>]` invocation. `argv` starts with the `explain` token
/// itself, mirroring [`parse_session`]'s own convention.
///
/// # Errors
///
/// Returns [`UsageError`] on any malformed invocation.
pub fn parse_explain(
    argv: impl IntoIterator<Item = OsString>,
) -> Result<ExplainInvocation, UsageError> {
    let mut argv = argv.into_iter();

    let first = argv.next();
    if first.as_deref() != Some(OsStr::new("explain")) {
        return Err(UsageError::NotExplainSubcommand { found: first });
    }

    let mut selector: Option<Selector> = None;
    let mut chain = false;
    let mut log_path: Option<PathBuf> = None;

    while let Some(arg) = argv.next() {
        if arg == OsStr::new("--chain") {
            chain = true;
            continue;
        }
        if arg == OsStr::new("--log") {
            let value = argv.next().ok_or(UsageError::LogMissingValue)?;
            log_path = Some(PathBuf::from(value));
            continue;
        }
        if arg == OsStr::new("--event") {
            let value = argv.next().ok_or(UsageError::EventMissingValue)?;
            let event_id = parse_event_id(&value).map_err(|reason| UsageError::InvalidEvent {
                found: value.clone(),
                reason,
            })?;
            set_selector(&mut selector, Selector::Event(event_id))?;
            continue;
        }
        if arg == OsStr::new("--lease") {
            let value = argv.next().ok_or(UsageError::LeaseMissingValue)?;
            let event_id = parse_event_id(&value).map_err(|reason| UsageError::InvalidLease {
                found: value.clone(),
                reason,
            })?;
            let lease_id = LeaseId {
                issuer: event_id.instance,
                sequence: event_id.sequence,
            };
            set_selector(&mut selector, Selector::Lease(lease_id))?;
            continue;
        }
        if arg == OsStr::new("--pid") {
            let value = argv.next().ok_or(UsageError::PidMissingValue)?;
            let pid: u32 = value.to_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                UsageError::InvalidPid {
                    found: value.clone(),
                    reason: "expected a non-negative integer".to_string(),
                }
            })?;
            set_selector(&mut selector, Selector::Pid(pid))?;
            continue;
        }
        return Err(UsageError::UnrecognizedArgument { found: arg });
    }

    let selector = selector.ok_or(UsageError::SelectorMissing)?;
    Ok(ExplainInvocation {
        selector,
        chain,
        log_path,
    })
}

fn set_selector(selector: &mut Option<Selector>, value: Selector) -> Result<(), UsageError> {
    if selector.is_some() {
        return Err(UsageError::SelectorGivenTwice);
    }
    *selector = Some(value);
    Ok(())
}

/// Parse `<instance>#<sequence>` into an [`AuditEventId`] — the same
/// grammar `crates/eltanin-audit/src/bin/eltanin-explain.rs` already
/// establishes for `--event`/`--lease`.
fn parse_event_id(raw: &OsStr) -> Result<AuditEventId, String> {
    let text = raw.to_str().ok_or_else(|| "not valid UTF-8".to_string())?;
    let (instance, sequence) = text
        .rsplit_once('#')
        .ok_or_else(|| format!("expected <instance>#<sequence>, got {text:?}"))?;
    let sequence: u64 = sequence
        .parse()
        .map_err(|e| format!("invalid sequence in {text:?}: {e}"))?;
    Ok(AuditEventId {
        instance: IssuerInstanceId::new(instance),
        sequence,
    })
}

/// Parse an `eltanin audit [--limit N] [--log <path>]` invocation.
/// `argv` starts with the `audit` token itself.
///
/// # Errors
///
/// Returns [`UsageError`] on any malformed invocation.
pub fn parse_audit(
    argv: impl IntoIterator<Item = OsString>,
) -> Result<AuditInvocation, UsageError> {
    let mut argv = argv.into_iter();

    let first = argv.next();
    if first.as_deref() != Some(OsStr::new("audit")) {
        return Err(UsageError::NotAuditSubcommand { found: first });
    }

    let mut limit = DEFAULT_AUDIT_LIMIT;
    let mut log_path: Option<PathBuf> = None;

    while let Some(arg) = argv.next() {
        if arg == OsStr::new("--limit") {
            let value = argv.next().ok_or(UsageError::LimitMissingValue)?;
            limit = value.to_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                UsageError::InvalidLimit {
                    found: value.clone(),
                    reason: "expected a non-negative integer".to_string(),
                }
            })?;
            continue;
        }
        if arg == OsStr::new("--log") {
            let value = argv.next().ok_or(UsageError::LogMissingValue)?;
            log_path = Some(PathBuf::from(value));
            continue;
        }
        return Err(UsageError::UnrecognizedArgument { found: arg });
    }

    Ok(AuditInvocation { limit, log_path })
}

/// Parse an `eltanin status` invocation. `argv` starts with the
/// `status` token itself; it takes no further arguments.
///
/// # Errors
///
/// Returns [`UsageError`] on any malformed invocation.
pub fn parse_status(
    argv: impl IntoIterator<Item = OsString>,
) -> Result<StatusInvocation, UsageError> {
    let mut argv = argv.into_iter();

    let first = argv.next();
    if first.as_deref() != Some(OsStr::new("status")) {
        return Err(UsageError::NotStatusSubcommand { found: first });
    }
    if let Some(found) = argv.next() {
        return Err(UsageError::UnexpectedStatusArgument { found });
    }
    Ok(StatusInvocation)
}

/// Parse an `eltanin dogfood-evidence [--log <path>]` invocation
/// (HORO-1376). `argv` starts with the `dogfood-evidence` token itself,
/// mirroring [`parse_audit`]'s own `--log` grammar exactly — this
/// command takes no other argument.
///
/// # Errors
///
/// Returns [`UsageError`] on any malformed invocation.
pub fn parse_dogfood_evidence(
    argv: impl IntoIterator<Item = OsString>,
) -> Result<DogfoodEvidenceInvocation, UsageError> {
    let mut argv = argv.into_iter();

    let first = argv.next();
    if first.as_deref() != Some(OsStr::new("dogfood-evidence")) {
        return Err(UsageError::NotDogfoodEvidenceSubcommand { found: first });
    }

    let mut log_path: Option<PathBuf> = None;
    while let Some(arg) = argv.next() {
        if arg == OsStr::new("--log") {
            let value = argv.next().ok_or(UsageError::LogMissingValue)?;
            log_path = Some(PathBuf::from(value));
            continue;
        }
        return Err(UsageError::UnrecognizedArgument { found: arg });
    }

    Ok(DogfoodEvidenceInvocation { log_path })
}

/// Parse an `eltanin approve ...` invocation. `argv` starts with the
/// `approve` token itself, mirroring [`parse_session`]'s own
/// convention.
///
/// # Errors
///
/// Returns [`UsageError`] on any malformed invocation.
pub fn parse_approve(
    argv: impl IntoIterator<Item = OsString>,
) -> Result<ApproveInvocation, UsageError> {
    let mut argv = argv.into_iter();

    let first = argv.next();
    if first.as_deref() != Some(OsStr::new("approve")) {
        return Err(UsageError::NotApproveSubcommand { found: first });
    }

    let mut argv = argv.peekable();
    match argv.peek().and_then(|a| a.to_str()) {
        Some("list") => {
            argv.next();
            reject_extra_arguments(argv, "list")?;
            Ok(ApproveInvocation::List)
        }
        Some("forget") => {
            argv.next();
            let id = argv.next().ok_or(UsageError::ForgetIdMissing)?;
            if let Some(extra) = argv.next() {
                return Err(UsageError::UnexpectedApproveArgument { found: extra });
            }
            let id = id.to_str().ok_or(UsageError::ForgetIdMissing)?;
            Ok(ApproveInvocation::Forget {
                id: ApprovalId::from_raw(id.to_string()),
            })
        }
        _ => parse_approve_record(argv),
    }
}

fn parse_approve_record(
    argv: impl Iterator<Item = OsString>,
) -> Result<ApproveInvocation, UsageError> {
    let mut argv = argv;
    let mut profile: Option<ProfileName> = None;
    let mut disposition: Option<ApprovalDisposition> = None;

    while let Some(arg) = argv.next() {
        if arg == OsStr::new("--profile") {
            if profile.is_some() {
                return Err(UsageError::ProfileGivenTwice);
            }
            let value = argv.next().ok_or(UsageError::ProfileMissingValue)?;
            profile = Some(ProfileName::parse(&value)?);
            continue;
        }
        let this_disposition = if arg == OsStr::new("--once") {
            Some(ApprovalDisposition::Once)
        } else if arg == OsStr::new("--remember") {
            Some(ApprovalDisposition::Remember)
        } else if arg == OsStr::new("--deny") {
            Some(ApprovalDisposition::Deny)
        } else {
            None
        };
        if let Some(this_disposition) = this_disposition {
            if disposition.is_some() {
                return Err(UsageError::DispositionGivenTwice);
            }
            disposition = Some(this_disposition);
            continue;
        }
        return Err(UsageError::UnrecognizedArgument { found: arg });
    }

    let profile = profile.ok_or(UsageError::ProfileMissing)?;
    let disposition = disposition.ok_or(UsageError::DispositionMissing)?;
    Ok(ApproveInvocation::Record {
        profile,
        disposition,
    })
}

/// Parse an `eltanin session <start|list|end> ...` invocation. `argv`
/// starts with the `session` token itself, mirroring [`parse_run`]'s own
/// convention.
///
/// # Errors
///
/// Returns [`UsageError`] on any malformed invocation.
pub fn parse_session(
    argv: impl IntoIterator<Item = OsString>,
) -> Result<SessionInvocation, UsageError> {
    let mut argv = argv.into_iter();

    let first = argv.next();
    if first.as_deref() != Some(OsStr::new("session")) {
        return Err(UsageError::NotSessionSubcommand { found: first });
    }

    let action = argv.next();
    match action.as_deref().and_then(OsStr::to_str) {
        Some("start") => parse_session_start(argv),
        Some("list") => {
            reject_extra_arguments(argv, "list")?;
            Ok(SessionInvocation::List)
        }
        Some("end") => {
            reject_extra_arguments(argv, "end")?;
            Ok(SessionInvocation::End)
        }
        _ => Err(UsageError::UnknownSessionAction { found: action }),
    }
}

fn reject_extra_arguments(
    mut argv: impl Iterator<Item = OsString>,
    action: &'static str,
) -> Result<(), UsageError> {
    match argv.next() {
        None => Ok(()),
        Some(found) => Err(UsageError::UnexpectedSessionArgument { action, found }),
    }
}

fn parse_session_start(
    argv: impl Iterator<Item = OsString>,
) -> Result<SessionInvocation, UsageError> {
    let mut argv = argv;
    let mut profiles: Vec<ProfileName> = Vec::new();
    let mut ttl: Option<Duration> = None;

    while let Some(arg) = argv.next() {
        if arg == OsStr::new("--profile") {
            let value = argv.next().ok_or(UsageError::ProfileMissingValue)?;
            profiles.push(ProfileName::parse(&value)?);
            continue;
        }
        if arg == OsStr::new("--ttl") {
            if ttl.is_some() {
                return Err(UsageError::TtlGivenTwice);
            }
            let value = argv.next().ok_or(UsageError::TtlMissingValue)?;
            ttl = Some(parse_duration(&value)?);
            continue;
        }
        return Err(UsageError::UnrecognizedArgument { found: arg });
    }

    if profiles.is_empty() {
        return Err(UsageError::ProfileMissing);
    }
    let ttl = ttl.ok_or(UsageError::TtlMissing)?;
    Ok(SessionInvocation::Start { profiles, ttl })
}

/// Parse a `--ttl` value: a bare non-negative integer (seconds), or an
/// integer followed by one of `s`/`m`/`h` (seconds/minutes/hours).
/// Deliberately not a general duration-parsing dependency — this is the
/// entire grammar `docs/product/CLI_CONTRACT.md`'s `eltanin session`
/// section documents, and adding one is additive.
///
/// # Errors
///
/// Returns [`UsageError::InvalidTtl`] if `raw` is not valid UTF-8, is
/// empty, has an unrecognized suffix, or its numeric part does not
/// parse as a `u64`.
fn parse_duration(raw: &OsStr) -> Result<Duration, UsageError> {
    let invalid = || UsageError::InvalidTtl {
        found: raw.to_os_string(),
    };
    let text = raw.to_str().ok_or_else(invalid)?;
    if text.is_empty() {
        return Err(invalid());
    }
    let (digits, multiplier) = match text.strip_suffix('h') {
        Some(digits) => (digits, 3600),
        None => match text.strip_suffix('m') {
            Some(digits) => (digits, 60),
            None => match text.strip_suffix('s') {
                Some(digits) => (digits, 1),
                None => (text, 1),
            },
        },
    };
    let value: u64 = digits.parse().map_err(|_| invalid())?;
    Ok(Duration::from_secs(value.saturating_mul(multiplier)))
}
