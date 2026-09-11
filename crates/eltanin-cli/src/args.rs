//! Argv parsing for `eltanin run` (F-M1-008, HORO-845).
//!
//! Reads `OsString` throughout — never `String` — so arbitrary bytes
//! (non-UTF-8 paths, embedded shell metacharacters) round-trip unchanged
//! into the spawned child's argv. See
//! `docs/product/CLI_CONTRACT.md`'s "Argv grammar" section.

use std::ffi::{OsStr, OsString};

use crate::profile::ProfileName;

/// A fully parsed `eltanin run` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunInvocation {
    pub profile: ProfileName,
    pub program: OsString,
    pub args: Vec<OsString>,
}

/// Why `parse_run` rejected the argv — always maps to
/// [`crate::exit::ExitCode::Usage`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    #[error("expected the first argument to be \"run\", got {found:?}")]
    NotRunSubcommand { found: Option<OsString> },
    #[error("--profile requires a value")]
    ProfileMissingValue,
    #[error("--profile was given more than once")]
    ProfileGivenTwice,
    #[error("--profile is required")]
    ProfileMissing,
    #[error("unrecognized argument before \"--\": {found:?}")]
    UnrecognizedArgument { found: OsString },
    #[error(
        "expected \"--\" to separate eltanin run's own flags from the command to launch, but \
         none was found"
    )]
    MissingSeparator,
    #[error("expected a command to run after \"--\", but none was given")]
    EmptyCommand,
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
