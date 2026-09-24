//! Read-only projection from `eltanin_audit::explain::LogScan` into the
//! ADR-0012 §3 evidence schema.
//!
//! This module never writes to the native audit log and never touches
//! [`eltanin_audit::sink::AuditFileSink`] — it only calls
//! [`eltanin_audit::explain::read_log`] and maps what comes back. See
//! `tests/dependency_direction.rs` and `tests/no_network_dependency.rs`
//! for the mechanical guards on this crate's isolation.

use std::collections::BTreeSet;

use eltanin_audit::explain::LogScan;
use eltanin_audit::record::{
    AuditEventId, AuditRecord, RecordedEnforcementMode, RecordedOutcome, WallClockTime,
};

use crate::canon::hash_event;
use crate::event::{
    derive_event_id, format_timestamp_or_sentinel, unsupported, ActualAction, Coverage,
    DecisionMode, Eligibility, Event, GapReason, PayloadClassification, Profile, TransportState,
    ADAPTER_VERSION, PRODUCT, SCHEMA_VERSION,
};

/// Name of the environment variable selecting the profile this adapter
/// projects records under. Default `personal` — the safer default per
/// ADR-0012 §2.2 (personal profile can never deny/kill/gate anything).
pub const PROFILE_ENV_VAR: &str = "ELTANIN_DOGFOOD_PROFILE";

/// Resolve the configured [`Profile`] from `ELTANIN_DOGFOOD_PROFILE`:
/// exact-match `"corporate"` (case-sensitive — no fuzzy matching for a
/// value this consequential) selects [`Profile::Corporate`]; anything
/// else, including unset, selects [`Profile::Personal`].
#[must_use]
pub fn resolve_profile(raw: Option<&str>) -> Profile {
    match raw {
        Some("corporate") => Profile::Corporate,
        _ => Profile::Personal,
    }
}

/// A native audit record this adapter refused to project rather than
/// fabricate a value for — e.g. an `Enforce`-mode record with no
/// `session` (DFC-SCHEMA-12: `scope_id` is required under `enforce`, and
/// this adapter never invents one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedRecord {
    pub event_id: AuditEventId,
    pub reason: String,
}

/// Everything one `dogfood-evidence` invocation produces from a
/// [`LogScan`]: one projected [`Event`] per successfully-mapped
/// [`AuditRecord`] (always `eligibility = non_replayable_operation` —
/// see [`project_record`]'s doc comment for why), the records refused as
/// malformed, and exactly one derived aggregate `summary` event (the
/// only `eligibility = replayable_evidence` record this adapter ever
/// produces).
pub struct Projection {
    pub events: Vec<Event>,
    pub malformed: Vec<MalformedRecord>,
    pub summary: Event,
}

/// Project every readable decision record in `scan`, plus one derived
/// summary, under `profile` — `now` is this invocation's own wall-clock
/// reading, used only for `ingested_at` (see `crate::event`'s module doc
/// on why that is a projection-time value, not a capture-time one).
#[must_use]
pub fn project(
    scan: &LogScan,
    profile: Profile,
    product_version: &str,
    now: WallClockTime,
) -> Projection {
    let mut events = Vec::with_capacity(scan.records.len());
    let mut malformed = Vec::new();

    for record in &scan.records {
        match project_record(record, profile, product_version, now) {
            Ok(event) => events.push(event),
            Err(reason) => malformed.push(MalformedRecord {
                event_id: record.event_id.clone(),
                reason,
            }),
        }
    }

    let summary = build_summary(scan, profile, product_version, now);

    Projection {
        events,
        malformed,
        summary,
    }
}

/// Project one [`AuditRecord`] into an [`Event`], or refuse with a reason
/// string.
///
/// # Eligibility (ADR-0012 §7)
///
/// Always `non_replayable_operation`. Every [`eltanin_audit::record::RecordedOperation`]
/// variant is authorization-gate traffic (`RequestLease`, `ReleaseLease`,
/// session/approval lifecycle), and ADR-0012 §7's explicit exclusion list
/// item 2 names exactly this family ("Eltanin's
/// `authz/{session, session_state, event, risk, delegation, approval}`
/// family") as never eligible for transfer. There is no code path in
/// this function that can produce `replayable_evidence` — that variant
/// is reserved for [`build_summary`]'s derived aggregate record.
///
/// # Errors
///
/// Returns `Err(reason)` when `record.mode` is
/// [`RecordedEnforcementMode::Enforce`] and `record.session` is `None` —
/// DFC-SCHEMA-12: `scope_id` is required under `enforce`, and this
/// adapter never fabricates one.
pub fn project_record(
    record: &AuditRecord,
    profile: Profile,
    product_version: &str,
    now: WallClockTime,
) -> Result<Event, String> {
    let decision_mode = match record.mode {
        RecordedEnforcementMode::Shadow => DecisionMode::Observe,
        RecordedEnforcementMode::Enforce => DecisionMode::Enforce,
    };

    let scope_id = record
        .session
        .as_ref()
        .map(|s| format!("{}#{}", s.issuer.as_str(), s.sequence));
    if matches!(decision_mode, DecisionMode::Enforce) && scope_id.is_none() {
        return Err(format!(
            "record {} is decision_mode=enforce with session=None — scope_id is required under \
             enforce (ADR-0012 §3/DFC-SCHEMA-12); refusing rather than fabricating a scope",
            record.event_id
        ));
    }

    let (actual_action, would_action) = map_outcome(&record.outcome, decision_mode);

    let event_id = derive_event_id(&record.event_id, record.recorded_at);
    let occurred_at = format_timestamp_or_sentinel(record.recorded_at);
    let ingested_at = format_timestamp_or_sentinel(now);

    let mut event = Event {
        event_id,
        schema_version: SCHEMA_VERSION,
        product: PRODUCT,
        product_version: product_version.to_string(),
        adapter_version: ADAPTER_VERSION.to_string(),
        occurred_at,
        ingested_at,
        profile,
        origin_profile: profile,
        decision_mode,
        scope_id,
        actual_action,
        would_action,
        coverage: Coverage::Full,
        gap_reason: None,
        dropped_count: 0,
        payload_classification: PayloadClassification::MetadataOnly,
        integrity: placeholder_integrity(),
        destination: "local_only",
        tenant_id: None,
        transport_state: TransportState::Pending,
        eligibility: Eligibility::NonReplayableOperation,
        permanently_ineligible: matches!(profile, Profile::Corporate),
        imported: false,
    };
    event.integrity = hash_event(&event).map_err(|e| e.to_string())?;
    Ok(event)
}

/// Map one [`RecordedOutcome`] to `(actual_action, would_action)` under
/// `decision_mode`.
///
/// # Personal-profile / North-Star safety (structural, not per-branch)
///
/// Under [`DecisionMode::Observe`], `actual_action` is **always**
/// [`ActualAction::NoOp`] — nothing was actually granted, denied, or
/// enforced; `eltanin_audit::record::RecordedOutcome::WouldGrant`'s own
/// doc comment is explicit that its lease "was minted and immediately
/// reversed... never a claim of real authority." This is what makes
/// `tests/personal_profile_safety.rs`'s properties hold *structurally*:
/// there is no branch of this function that returns `(Deny, _)` for
/// `Observe`, so a personal-profile record can never carry
/// `actual_action = deny` regardless of what the underlying
/// [`RecordedOutcome`] was — matching ADR-0012 §3's own "a record with
/// `decision_mode=observe` and `actual_action=deny` is malformed by
/// construction" rule and the ticket's "personal profile does not deny/
/// kill managed test workloads."
fn map_outcome(
    outcome: &RecordedOutcome,
    decision_mode: DecisionMode,
) -> (ActualAction, Option<ActualAction>) {
    if matches!(decision_mode, DecisionMode::Observe) {
        let would = match outcome {
            RecordedOutcome::WouldGrant { .. } => Some(ActualAction::Allow),
            RecordedOutcome::PolicyDenied { .. } => Some(ActualAction::Deny),
            _ => None,
        };
        return (ActualAction::NoOp, would);
    }

    // decision_mode == Enforce: report what really happened. Grouped by
    // real-world effect, not by enum declaration order.
    let actual = match outcome {
        RecordedOutcome::Granted { .. } | RecordedOutcome::GrantedByDelegation { .. } => {
            ActualAction::Allow
        }
        RecordedOutcome::PolicyDenied { .. }
        | RecordedOutcome::PeerNotAuthorizable
        | RecordedOutcome::LeaseIssueFailed { .. }
        | RecordedOutcome::ReleaseRefused { .. }
        | RecordedOutcome::ReleaseUnknownLease
        | RecordedOutcome::SessionRequired { .. }
        | RecordedOutcome::SessionEstablishFailed { .. }
        | RecordedOutcome::SessionNotFound
        | RecordedOutcome::ApprovalRequired
        | RecordedOutcome::ApprovalDenied
        | RecordedOutcome::DelegationRefused { .. }
        | RecordedOutcome::StepUpRequired { .. }
        | RecordedOutcome::RiskDenied { .. } => ActualAction::Deny,
        RecordedOutcome::EnforcementRefused { .. }
        | RecordedOutcome::BackendFailed { .. }
        | RecordedOutcome::CapacityExhausted { .. }
        | RecordedOutcome::ApprovalGateObserveFailed { .. }
        | RecordedOutcome::ApprovalInternalError { .. }
        | RecordedOutcome::DelegationIndeterminate { .. } => ActualAction::Error,
        // Administrative/informational outcomes: no compute-gating
        // decision was made either way. `WouldGrant` is structurally a
        // `Shadow`-only outcome (see its own doc comment) and this
        // branch only runs for `Enforce` — included here only so this
        // match stays exhaustive against a future `RecordedOutcome`
        // reviewer, never expected to actually execute.
        RecordedOutcome::Released { .. }
        | RecordedOutcome::StatusReported
        | RecordedOutcome::SessionEstablished { .. }
        | RecordedOutcome::SessionListed { .. }
        | RecordedOutcome::SessionTerminated { .. }
        | RecordedOutcome::ApprovalRecorded { .. }
        | RecordedOutcome::ApprovalListed { .. }
        | RecordedOutcome::ApprovalForgotten { .. }
        | RecordedOutcome::WouldGrant { .. } => ActualAction::NoOp,
    };
    (actual, None)
}

/// Build the one `eligibility = replayable_evidence` aggregate/coverage/
/// gap/adapter-health record this adapter ever produces — see this
/// module's own doc comment on [`project_record`] for why individual
/// decision records can never be `replayable_evidence`.
///
/// # `dropped_count` and `gap_reason` derivation
///
/// This adapter is stateless across invocations (a read-only CLI, no
/// watermark store — see the crate-level docs), so it can only ever
/// compute counts from what one [`LogScan`] itself proves:
///
/// - `scan.gaps` (a reserved-but-never-written sequence number,
///   `eltanin_audit`'s own honest "may be missing because persistence
///   failed" signal) contributes to `dropped_count` with
///   `gap_reason = source_unavailable`.
/// - `scan.unreadable` lines whose `event_id` *did* recover (the line
///   exists on disk, just couldn't be parsed as this build's
///   `LogEntry`) also contribute, with `gap_reason = unknown` — "we
///   cannot attest to what we cannot describe" (ADR-0012 §7 item 5).
/// - A non-empty `scan.retention_floor` proves rotation discarded a
///   generation, but the *exact* count discarded is not knowable from a
///   single scan with no persisted prior watermark — that shortfall is
///   never guessed into `dropped_count`; instead it is surfaced as
///   `unsupported: ["exact_dropped_count_below_retention_floor"]` on
///   this same summary, per the ticket's explicit "never guess a
///   number" instruction.
///
/// When more than one of these applies at once, `gap_reason` reports the
/// most severe single reason (`unknown` > `source_unavailable` >
/// `buffer_overflow`) — the schema has room for exactly one `gap_reason`
/// per record, so this adapter's own priority order is documented here
/// rather than left to field-population order.
fn build_summary(
    scan: &LogScan,
    profile: Profile,
    product_version: &str,
    now: WallClockTime,
) -> Event {
    let gap_count = scan.gaps.len() as u64;
    let unreadable_unknown_count = scan
        .unreadable
        .iter()
        .filter(|line| line.event_id.is_some())
        .count() as u64;
    let rotation_occurred = !scan.retention_floor.is_empty();

    let dropped_count = gap_count + unreadable_unknown_count;
    let (coverage, gap_reason) = if unreadable_unknown_count > 0 {
        (Coverage::Gap, Some(GapReason::Unknown))
    } else if gap_count > 0 {
        (Coverage::Gap, Some(GapReason::SourceUnavailable))
    } else if rotation_occurred {
        (Coverage::Gap, Some(GapReason::BufferOverflow))
    } else {
        (Coverage::Full, None)
    };

    let synthetic_id = AuditEventId {
        instance: summary_instance(scan),
        sequence: 0,
    };

    let mut event = Event {
        event_id: derive_event_id(&synthetic_id, now),
        schema_version: SCHEMA_VERSION,
        product: PRODUCT,
        product_version: product_version.to_string(),
        adapter_version: ADAPTER_VERSION.to_string(),
        occurred_at: format_timestamp_or_sentinel(now),
        ingested_at: format_timestamp_or_sentinel(now),
        profile,
        origin_profile: profile,
        decision_mode: DecisionMode::Observe,
        scope_id: None,
        actual_action: ActualAction::NoOp,
        would_action: None,
        coverage,
        gap_reason,
        dropped_count,
        payload_classification: PayloadClassification::MetadataOnly,
        integrity: placeholder_integrity(),
        destination: "local_only",
        tenant_id: None,
        transport_state: TransportState::Pending,
        eligibility: Eligibility::ReplayableEvidence,
        permanently_ineligible: matches!(profile, Profile::Corporate),
        imported: false,
    };
    event.integrity = hash_event(&event).expect("summary event always serializes");
    event
}

/// The `unsupported` note list for one scan — adapter-local metadata,
/// never a §3 field (see `crate::event`'s top doc comment), computed as
/// a pure function of `scan` rather than a hidden field on [`Event`] so
/// a caller (the CLI) can render it alongside the summary event without
/// this crate smuggling an extra key into the hashed/canonicalized
/// object. Mirrors [`build_summary`]'s own `rotation_occurred` check
/// exactly — kept as two call sites rather than one shared private
/// helper only because each is a two-line, trivially-inspectable
/// computation over the same `scan.retention_floor` field.
#[must_use]
pub fn summary_unsupported_notes(scan: &LogScan) -> Vec<&'static str> {
    let mut notes = vec![
        unsupported::DEVICE_LEVEL_GPU_ENFORCEMENT,
        unsupported::INGESTED_AT_IS_PROJECTION_TIME,
        unsupported::ORIGIN_PROFILE_NOT_RECOVERABLE_FROM_LOG,
    ];
    if !scan.retention_floor.is_empty() {
        notes.push(unsupported::EXACT_DROPPED_COUNT_BELOW_RETENTION_FLOOR);
    }
    notes
}

/// The summary record's own synthetic `AuditEventId` needs *an*
/// instance tag distinct from any real one, so it never collides with a
/// real record's derived `event_id`. Uses the first real record's
/// instance when one exists (keeping the summary attributable to that
/// agent lifetime), else a fixed sentinel tag for an empty/gap-only log.
fn summary_instance(scan: &LogScan) -> eltanin_core::lease::IssuerInstanceId {
    scan.records
        .first()
        .map(|r| r.event_id.instance.clone())
        .or_else(|| {
            scan.agent_events
                .first()
                .map(|e| e.event_id.instance.clone())
        })
        .unwrap_or_else(|| eltanin_core::lease::IssuerInstanceId::new("dogfood-evidence-summary"))
}

fn placeholder_integrity() -> crate::event::Integrity {
    crate::event::Integrity {
        canonicalization: crate::canon::CANONICALIZATION_ID,
        content_hash: crate::event::ContentHash {
            alg: "sha256",
            value: String::new(),
        },
    }
}

/// Assert no forbidden hardware/GPU/device term appears anywhere in the
/// full serialized output of `events` — used by `tests/no_gpu_claim.rs`,
/// kept here (rather than only in the test) so both the test and any
/// future caller share exactly one definition of "forbidden."
#[must_use]
pub fn scan_for_forbidden_hardware_terms(serialized: &str) -> BTreeSet<&'static str> {
    const FORBIDDEN: &[&str] = &["gpu", "device", "metal", "cuda"];
    let lower = serialized.to_lowercase();
    FORBIDDEN
        .iter()
        .copied()
        .filter(|term| lower.contains(term))
        .collect()
}
