//! The frozen `schema_version: 1` `DogFood` evidence event (ADR-0012 §3)
//! and its adapter-local sibling.
//!
//! # Deliberate deviations from ADR-0012 §3, and why
//!
//! - **`event_id` is not a `UUIDv7`.** §3 asks for "generated once at
//!   capture... stable across every retry." This adapter has no write-back
//!   store to persist a minted id in, and re-running the projection against
//!   the same NDJSON line must reproduce the same `event_id` (that stability
//!   requirement is what DFC-SCHEMA-02 actually tests). Eltanin's own
//!   `eltanin_audit::record::AuditEventId` (`{instance, sequence}`) is
//!   already unique per agent lifetime and immutable once written, so
//!   [`derive_event_id`] deterministically derives a v7-shaped UUID string
//!   from it instead of minting fresh entropy. This is a legitimate v7
//!   shape (v7 does not require `rand_a`/`rand_b` to be random, only
//!   present) with the timestamp bits taken from `recorded_at` and the
//!   random bits taken from `SHA-256(instance#sequence)` — deterministic,
//!   not random.
//! - **`ingested_at` is not store-append latency.** Eltanin's NDJSON log
//!   line carries exactly one timestamp (`recorded_at`); there is no
//!   second, separately-recorded "store accepted this append" instant to
//!   read back. `occurred_at` is `recorded_at`; `ingested_at` is this
//!   adapter's own projection time, which is a real, distinct instant
//!   (satisfying §3's "never equal-by-construction" rule and
//!   DFC-SCHEMA-04's "distinct" check) but is **not** a capture-latency
//!   measurement. See [`unsupported::INGESTED_AT_IS_PROJECTION_TIME`].
//! - **`origin_profile` is not recoverable from the native log.** Eltanin's
//!   audit records carry no profile concept at all; `origin_profile` here
//!   is the profile configured at *projection* time
//!   (`ELTANIN_DOGFOOD_PROFILE`), not a value latched at original capture
//!   time. Consequence is inert in practice — Eltanin is `local_only` with
//!   no upload leg (ADR-0012 §12), so §8's corporate-wall enforcement never
//!   has an opportunity to matter here — but the deviation from §3's literal
//!   "profile at capture time" definition must not be silently implied.

use eltanin_audit::record::{AuditEventId, WallClockTime};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::rfc3339::format_rfc3339_millis;

/// This adapter's own crate version — `adapter_version` (ADR-0012 §3),
/// distinct from `product_version` so a conformance failure is
/// attributable to the adapter, not the product build.
pub const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// ADR-0012 §3's frozen product enum value for this adapter.
pub const PRODUCT: &str = "eltanin";

/// This adapter's `DogFood` evidence `schema_version` — ADR-0012 §3's own
/// versioning, wholly independent of `eltanin_core::envelope::
/// DOMAIN_SCHEMA_VERSION` (Eltanin's internal wire/audit schema version).
/// The two numbers happening to differ is expected, not a bug: they
/// version different contracts.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Personal,
    Corporate,
}

impl Profile {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Personal => "personal",
            Profile::Corporate => "corporate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionMode {
    Observe,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActualAction {
    Allow,
    Deny,
    Warn,
    NoOp,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    Full,
    Partial,
    Gap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    BufferOverflow,
    DiskCap,
    AdapterUnsupported,
    SourceUnavailable,
    RedactionFailed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadClassification {
    MetadataOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportState {
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Eligibility {
    ReplayableEvidence,
    NonReplayableOperation,
}

/// ADR-0012 §6 integrity envelope. `content_hash` is computed over the
/// canonicalized event with this member itself omitted — see
/// [`crate::canon`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Integrity {
    pub canonicalization: &'static str,
    pub content_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContentHash {
    pub alg: &'static str,
    pub value: String,
}

/// The frozen `schema_version: 1` `DogFood` evidence event (ADR-0012 §3).
/// Field set is exactly §3's — no extra fields. `unsupported`/adapter
/// health notes live in [`crate::adapter::Summary`], never here: adding a
/// field to this struct would silently break cross-product `content_hash`
/// comparability (`dogfood-evidence-canonicalization-v1.md`), which §3
/// itself gates behind a minor ADR revision.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Event {
    pub event_id: String,
    pub schema_version: u32,
    pub product: &'static str,
    pub product_version: String,
    pub adapter_version: String,
    pub occurred_at: String,
    pub ingested_at: String,
    pub profile: Profile,
    pub origin_profile: Profile,
    pub decision_mode: DecisionMode,
    pub scope_id: Option<String>,
    pub actual_action: ActualAction,
    pub would_action: Option<ActualAction>,
    pub coverage: Coverage,
    pub gap_reason: Option<GapReason>,
    pub dropped_count: u64,
    pub payload_classification: PayloadClassification,
    pub integrity: Integrity,
    pub destination: &'static str,
    pub tenant_id: Option<String>,
    pub transport_state: TransportState,
    pub eligibility: Eligibility,
    pub permanently_ineligible: bool,
    pub imported: bool,
}

/// Deterministically derive a DFC-SCHEMA-02-stable `event_id` string from
/// an [`AuditEventId`] and its record's own `recorded_at` — see this
/// module's doc comment for why this is not a random `UUIDv7`. Shaped as a
/// `UUIDv7` string (version nibble `7`, RFC 4122 variant bits `10`), with
/// every remaining bit deterministically derived rather than randomly
/// generated.
#[must_use]
pub fn derive_event_id(id: &AuditEventId, recorded_at: WallClockTime) -> String {
    let millis: u64 = if recorded_at.unix_secs >= 0 {
        u64::try_from(recorded_at.unix_secs)
            .unwrap_or(0)
            .saturating_mul(1000)
            .saturating_add(u64::from(recorded_at.nanos) / 1_000_000)
    } else {
        0
    };
    let ts48 = millis & 0xFFFF_FFFF_FFFF; // low 48 bits

    let mut hasher = Sha256::new();
    hasher.update(id.instance.as_str().as_bytes());
    hasher.update(b"#");
    hasher.update(id.sequence.to_le_bytes());
    let digest = hasher.finalize();

    // 12 bits of rand_a, 62 bits of rand_b, deterministically taken from
    // the digest rather than randomly generated (legal per RFC 9562 — v7
    // only requires the version/variant bits to be fixed, not the rest to
    // be random).
    let rand_a = (u16::from(digest[0]) << 4 | u16::from(digest[1] >> 4)) & 0x0FFF;
    let mut rand_b_bytes = [0u8; 8];
    rand_b_bytes.copy_from_slice(&digest[2..10]);
    let rand_b = u64::from_be_bytes(rand_b_bytes) & 0x3FFF_FFFF_FFFF_FFFF;

    let time_hi = (ts48 >> 16) & 0xFFFF_FFFF;
    let time_lo = ts48 & 0xFFFF;
    let ver_rand_a = 0x7000u16 | rand_a;
    let variant_rand_b_hi = 0x8000_0000_0000_0000u64 | (rand_b & 0x3FFF_FFFF_FFFF_FFFF);

    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        time_hi,
        time_lo,
        ver_rand_a,
        (variant_rand_b_hi >> 48) & 0xFFFF,
        variant_rand_b_hi & 0xFFFF_FFFF_FFFF
    )
}

/// Wrapper for [`format_rfc3339_millis`] that never panics — a formatting
/// failure (pre-epoch reading) is reported inline as an obviously-invalid
/// sentinel rather than aborting the whole projection, since one bad
/// timestamp must not take down an otherwise-readable log scan.
#[must_use]
pub fn format_timestamp_or_sentinel(time: WallClockTime) -> String {
    format_rfc3339_millis(time).unwrap_or_else(|_| "1970-01-01T00:00:00.000Z".to_string())
}

/// Reasons this adapter could not populate a field the way ADR-0012 §3
/// would ideally want, surfaced in [`crate::adapter::Summary::unsupported`]
/// — never inside [`Event`] itself (see this module's top doc comment).
pub mod unsupported {
    pub const INGESTED_AT_IS_PROJECTION_TIME: &str =
        "ingested_at_is_projection_time_not_store_append_latency";
    pub const ORIGIN_PROFILE_NOT_RECOVERABLE_FROM_LOG: &str =
        "origin_profile_not_recoverable_from_native_log";
    pub const EXACT_DROPPED_COUNT_BELOW_RETENTION_FLOOR: &str =
        "exact_dropped_count_below_retention_floor";
    pub const DEVICE_LEVEL_GPU_ENFORCEMENT: &str = "device_level_gpu_enforcement";
}
