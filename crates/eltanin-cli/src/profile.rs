//! `--profile` name and document shape (F-M1-008, HORO-845).
//!
//! A profile is a **client-side intent alias only**: it resolves
//! `--profile <name>` to the `(ResourceIdentity, Action)` pair
//! `eltanin_protocol::request::LeaseRequest` needs, and never reaches
//! the wire itself — the agent's `PolicySet` evaluation is unaffected by
//! how a client arrived at those two values. See
//! `docs/product/CLI_CONTRACT.md`'s "Profiles" section.
//!
//! HORO-845 defined the name validation and the document shape.
//! HORO-846 (this loader) resolves a [`ProfileName`] to a
//! [`ProfileDocument`] from a single search directory — deliberately
//! not a multi-directory search (that introduces shadowing semantics
//! nobody has asked for; adding one later is additive).
//!
//! **Tampering a profile cannot escalate.** A profile carries only
//! `(resource, action)` — ordinary `RequestLease` fields any client
//! could supply directly — and default-deny policy evaluation is
//! unaffected by how a client arrived at them (see the module docs
//! above). So, unlike `eltanin-agent`'s socket-directory ownership
//! validation (`listener.rs::BoundSocket::bind`), this loader adds no
//! permission/ownership checks of its own: a tampered or malicious
//! profile document can only cause a denial, never a grant it
//! shouldn't have.

use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use eltanin_core::envelope::Versioned;
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

/// Why a profile could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum ProfileLoadError {
    #[error(
        "no profile search directory: set ELTANIN_PROFILE_DIR, or HOME/XDG_CONFIG_HOME so \
         one can be derived"
    )]
    NoSearchDir,
    #[error("profile {name:?} not found at {path}", path = path.display())]
    NotFound { name: String, path: PathBuf },
    #[error("failed to read profile at {path}: {reason}", path = path.display())]
    Io { path: PathBuf, reason: String },
    #[error("profile at {path} is not valid JSON: {reason}", path = path.display())]
    Json { path: PathBuf, reason: String },
    #[error("profile at {path}: {source}", path = path.display())]
    Version {
        path: PathBuf,
        #[source]
        source: eltanin_core::envelope::UnsupportedVersion,
    },
}

/// Resolve the profile search directory: `ELTANIN_PROFILE_DIR` if set
/// (no search — an explicit override is authoritative), else
/// `$XDG_CONFIG_HOME/eltanin/profiles`, else
/// `$HOME/.config/eltanin/profiles`.
///
/// # Errors
///
/// Returns [`ProfileLoadError::NoSearchDir`] if none of the above can be
/// resolved.
pub fn profile_dir() -> Result<PathBuf, ProfileLoadError> {
    if let Some(dir) = env::var_os("ELTANIN_PROFILE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("eltanin").join("profiles"));
    }
    if let Some(home) = env::var_os("HOME") {
        return Ok(PathBuf::from(home)
            .join(".config")
            .join("eltanin")
            .join("profiles"));
    }
    Err(ProfileLoadError::NoSearchDir)
}

/// Load and validate the profile named `name` from `dir`.
///
/// `name` is already validated by [`ProfileName::parse`] (rejects
/// empty, `/`, `.`/`..`, control characters, non-UTF-8), so
/// `dir.join(format!("{name}.json"))` is safe by construction — no
/// further path sanitization is needed here.
///
/// # Errors
///
/// Returns [`ProfileLoadError`] if the file doesn't exist, can't be
/// read, isn't valid JSON, or names an unsupported schema version.
pub fn load_profile_from_dir(
    dir: &Path,
    name: &ProfileName,
) -> Result<ProfileDocument, ProfileLoadError> {
    let path = dir.join(format!("{}.json", name.as_str()));
    let contents = std::fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ProfileLoadError::NotFound {
                name: name.as_str().to_string(),
                path: path.clone(),
            }
        } else {
            ProfileLoadError::Io {
                path: path.clone(),
                reason: e.to_string(),
            }
        }
    })?;
    let envelope: Versioned<ProfileDocument> =
        serde_json::from_str(&contents).map_err(|e| ProfileLoadError::Json {
            path: path.clone(),
            reason: e.to_string(),
        })?;
    envelope
        .into_current()
        .map_err(|source| ProfileLoadError::Version { path, source })
}

/// Resolve the search directory ([`profile_dir`]) and load `name` from
/// it — the entry point `eltanin run` actually calls.
///
/// # Errors
///
/// Returns [`ProfileLoadError`] under the same conditions as
/// [`profile_dir`] and [`load_profile_from_dir`].
pub fn load_profile(name: &ProfileName) -> Result<ProfileDocument, ProfileLoadError> {
    let dir = profile_dir()?;
    load_profile_from_dir(&dir, name)
}
