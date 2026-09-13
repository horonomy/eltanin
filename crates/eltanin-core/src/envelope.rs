//! Versioned serialization envelope for domain types.
//!
//! Every domain type that crosses a serialization boundary (disk, IPC,
//! audit log) is wrapped in [`Versioned`] so a schema change is explicit
//! rather than a silent reinterpretation of old bytes as a new shape.

use serde::{Deserialize, Serialize};

/// Current domain schema version. Bump when a wrapped type's wire shape
/// changes in a way that isn't backward compatible.
///
/// Bumped to `2` for HORO-791/F-M2-001: `eltanin-protocol`'s
/// `ClientRequest`/`AgentResponse` are internally tagged
/// (`#[serde(tag = "op"/"result", deny_unknown_fields)]`) with no
/// `#[serde(other)]` catch-all, so a v1 agent decoding a v2 client's
/// `create_session` request (or vice versa) does not silently drop the
/// new variant — it fails `into_current` outright on the version
/// mismatch. That is exactly this constant's own documented criterion
/// ("a wrapped type's wire shape changes in a way that isn't backward
/// compatible"), not a judgment call.
///
/// Bumped to `3` for HORO-792/F-M2-002, by the same criterion: `approve`/
/// `list_approvals`/`forget_approval` are new `ClientRequest`/
/// `AgentResponse` variants under the same internally-tagged,
/// `deny_unknown_fields`, no-`#[serde(other)]` enums. A side effect
/// this bump is deliberately allowed to have: every `Approval` stored
/// under the previous schema version embeds `schema_version:
/// DOMAIN_SCHEMA_VERSION` in its recorded `PolicyProvenance` (security
/// posture), so this bump alone makes every pre-existing durable
/// approval fail `recall`'s security-posture dimension and require
/// re-approval — a deliberate consequence of the schema version being
/// part of what "security posture" means, not a bug to work around.
pub const DOMAIN_SCHEMA_VERSION: u16 = 3;

/// Wraps a domain payload with an explicit schema version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Versioned<T> {
    pub version: u16,
    pub payload: T,
}

impl<T> Versioned<T> {
    /// Wrap `payload` at the current schema version.
    pub fn current(payload: T) -> Self {
        Self {
            version: DOMAIN_SCHEMA_VERSION,
            payload,
        }
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
    ///
    /// # Errors
    ///
    /// Returns [`UnsupportedVersion`] if `self.version` is not
    /// [`DOMAIN_SCHEMA_VERSION`].
    pub fn into_current(self) -> Result<T, UnsupportedVersion> {
        if self.version == DOMAIN_SCHEMA_VERSION {
            Ok(self.payload)
        } else {
            Err(UnsupportedVersion {
                found: self.version,
                expected: DOMAIN_SCHEMA_VERSION,
            })
        }
    }
}
