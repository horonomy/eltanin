//! Versioned serialization envelope for domain types.
//!
//! Every domain type that crosses a serialization boundary (disk, IPC,
//! audit log) is wrapped in [`Versioned`] so a schema change is explicit
//! rather than a silent reinterpretation of old bytes as a new shape.

use serde::{Deserialize, Serialize};

/// Current domain schema version. Bump when a wrapped type's wire shape
/// changes in a way that isn't backward compatible.
pub const DOMAIN_SCHEMA_VERSION: u16 = 1;

/// Wraps a domain payload with an explicit schema version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Versioned<T> {
    pub version: u16,
    pub payload: T,
}

impl<T> Versioned<T> {
    /// Wrap `payload` at the current schema version.
    pub fn current(payload: T) -> Self {
        Self { version: DOMAIN_SCHEMA_VERSION, payload }
    }
}

/// Error returned when decoding a [`Versioned`] envelope whose version
/// this build does not understand.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unsupported domain schema version: found {found}, expected {expected}")]
pub struct UnsupportedVersion {
    pub found: u16,
    pub expected: u16,
}

impl<T> Versioned<T> {
    /// Decode `self`, failing explicitly if its version isn't the one
    /// this build supports. MVP 1.0 supports exactly one version — there
    /// is no migration path yet, and pretending otherwise would be a
    /// silent compatibility promise this codebase doesn't keep.
    pub fn into_current(self) -> Result<T, UnsupportedVersion> {
        if self.version == DOMAIN_SCHEMA_VERSION {
            Ok(self.payload)
        } else {
            Err(UnsupportedVersion { found: self.version, expected: DOMAIN_SCHEMA_VERSION })
        }
    }
}
