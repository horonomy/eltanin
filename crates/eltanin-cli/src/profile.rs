//! `--profile` name and document shape (F-M1-008, HORO-845).
//!
//! A profile is a **client-side intent alias only**: it resolves
//! `--profile <name>` to the `(ResourceIdentity, Action)` pair
//! `eltanin_protocol::request::LeaseRequest` needs, and never reaches
//! the wire itself — the agent's `PolicySet` evaluation is unaffected by
//! how a client arrived at those two values. See
//! `docs/product/CLI_CONTRACT.md`'s "Profiles" section.
//!
//! HORO-845 defines the name validation and the document shape only.
//! The filesystem search path that resolves a [`ProfileName`] to a
//! [`ProfileDocument`] is HORO-846's to add.

use std::ffi::OsStr;

use eltanin_core::resource::{Action, ResourceIdentity};
use serde::{Deserialize, Serialize};

const MAX_PROFILE_NAME_LEN: usize = 64;

/// A validated `--profile` name. Rejects anything shaped like a path
/// component escape (`/`, `..`) since a future loader resolves this name
/// to a file path — validating early, in the CLI's own argv parsing,
/// means a hostile or malformed name is rejected before it ever reaches
/// a filesystem lookup.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileName(String);

/// Why a `--profile` value was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileNameError {
    #[error("--profile name must not be empty")]
    Empty,
    #[error("--profile name must not contain '/'")]
    ContainsSlash,
    #[error("--profile name must not be \".\" or \"..\"")]
    PathTraversal,
    #[error("--profile name must be at most {MAX_PROFILE_NAME_LEN} bytes, got {0}")]
    TooLong(usize),
    #[error("--profile name must be valid UTF-8")]
    NotUtf8,
    #[error("--profile name must not contain a control character")]
    ContainsControlCharacter,
}

impl ProfileName {
    /// Validate `raw` as a profile name.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileNameError`] if `raw` is empty, too long, not
    /// UTF-8, contains a path separator or control character, or is
    /// `.`/`..`.
    pub fn parse(raw: &OsStr) -> Result<Self, ProfileNameError> {
        let raw = raw.to_str().ok_or(ProfileNameError::NotUtf8)?;
        if raw.is_empty() {
            return Err(ProfileNameError::Empty);
        }
        if raw.len() > MAX_PROFILE_NAME_LEN {
            return Err(ProfileNameError::TooLong(raw.len()));
        }
        if raw.contains('/') {
            return Err(ProfileNameError::ContainsSlash);
        }
        if raw == "." || raw == ".." {
            return Err(ProfileNameError::PathTraversal);
        }
        // A future loader resolves this name to a filesystem path
        // (`crate` docs above) — reject NUL and other control
        // characters here, at the argv-validation boundary this ticket
        // owns, rather than letting them reach that loader as a
        // confusing path-construction error later.
        if raw.chars().any(char::is_control) {
            return Err(ProfileNameError::ContainsControlCharacter);
        }
        Ok(Self(raw.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The resolved contents of a profile: exactly what `LeaseRequest`
/// needs, nothing else. Deliberately has **no** executable-identity
/// field — see `docs/product/CLI_CONTRACT.md`'s MVP 1.0 limitation
/// statement for why a workload-executable condition cannot be
/// expressed or enforced through `eltanin run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileDocument {
    pub resource: ResourceIdentity,
    pub action: Action,
}
