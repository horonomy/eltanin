//! Argv parsing for `eltanin run` (F-M1-008, HORO-845).
//!
//! Reads `OsString` throughout — never `String` — so arbitrary bytes
//! (non-UTF-8 paths, embedded shell metacharacters) round-trip unchanged
//! into the spawned child's argv. See
//! `docs/product/CLI_CONTRACT.md`'s "Argv grammar" section.

use std::ffi::{OsStr, OsString};
use std::time::Duration;

use crate::profile::ProfileName;

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

/// Either of the two top-level subcommands this binary understands.
/// `eltanin run`'s own argument grammar (see [`parse_run`]) is
/// byte-for-byte unchanged by this type's introduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    Run(RunInvocation),
    Session(SessionInvocation),
}

/// Why argv parsing rejected the invocation — always maps to
/// [`crate::exit::ExitCode::Usage`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    #[error("expected the first argument to be \"run\", got {found:?}")]
    NotRunSubcommand { found: Option<OsString> },
    #[error("expected the first argument to be \"session\", got {found:?}")]
    NotSessionSubcommand { found: Option<OsString> },
    #[error("expected the first argument to be \"run\" or \"session\", got {found:?}")]
    UnknownSubcommand { found: Option<OsString> },
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
        other => Err(UsageError::UnknownSubcommand {
            found: other.map(OsStr::to_os_string),
        }),
    }
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
