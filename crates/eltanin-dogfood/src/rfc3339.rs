//! Hand-rolled `WallClockTime` → RFC3339 UTC formatting.
//!
//! ADR-0012 §3 requires `occurred_at`/`ingested_at` as RFC3339 UTC
//! strings, but this workspace has no `time`/`chrono` dependency (see the
//! workspace `Cargo.toml` — only `serde`, `serde_json`, `thiserror`,
//! `sha2` are workspace dependencies anywhere), and this crate must not
//! add one (ADR-0012 §12's Eltanin row: "no networking dependency
//! added" — a general policy this crate reads narrowly as "add nothing
//! new," not just "add nothing that dials a socket"). So this module
//! implements the minimal civil-calendar conversion itself, using
//! Howard Hinnant's well-known `civil_from_days` algorithm (public
//! domain; <http://howardhinnant.github.io/date_algorithms.html>).
//!
//! Millisecond precision, matching the worked example in
//! `dogfood-evidence-canonicalization-v1.md`
//! (`"2026-09-24T10:15:03.001Z"`).

use eltanin_audit::record::WallClockTime;

/// Format `time` as an RFC3339 UTC string with millisecond precision
/// (e.g. `"2026-09-24T10:15:03.001Z"`).
///
/// # Errors
///
/// Returns `Err` for a pre-epoch (`unix_secs < 0`) reading — this
/// module implements only the post-epoch civil calendar, deliberately:
/// `WallClockTime`'s own docs already note a wall clock "can move
/// backward," and a record whose reading predates 1970-01-01 is far
/// more likely a clock fault than a real observation this adapter
/// should silently render as some arbitrary pre-epoch civil date.
pub fn format_rfc3339_millis(time: WallClockTime) -> Result<String, String> {
    if time.unix_secs < 0 {
        return Err(format!(
            "cannot format a pre-epoch WallClockTime (unix_secs={})",
            time.unix_secs
        ));
    }
    let days = time.unix_secs.div_euclid(86400);
    let secs_of_day = time.unix_secs.rem_euclid(86400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    let millis = time.nanos / 1_000_000;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
    ))
}

/// Howard Hinnant's `civil_from_days`: days since the Unix epoch
/// (`1970-01-01`, non-negative here — see [`format_rfc3339_millis`])
/// into a `(year, month, day)` proleptic-Gregorian civil date.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (
        y,
        u32::try_from(m).unwrap_or(0),
        u32::try_from(d).unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wct(unix_secs: i64, nanos: u32) -> WallClockTime {
        WallClockTime { unix_secs, nanos }
    }

    /// DFC-SCHEMA-04 support: a handful of known instant → string pairs,
    /// including a leap-year/leap-day date, pin the hand-rolled
    /// conversion against real-world reference values rather than only
    /// round-tripping against itself.
    #[test]
    fn known_instants_format_correctly() {
        assert_eq!(
            format_rfc3339_millis(wct(0, 0)).unwrap(),
            "1970-01-01T00:00:00.000Z"
        );
        // 2026-09-24T10:15:03.001Z — the canon doc's own worked example.
        assert_eq!(
            format_rfc3339_millis(wct(1_790_244_903, 1_000_000)).unwrap(),
            "2026-09-24T10:15:03.001Z"
        );
        // 2024-02-29T12:00:00.000Z — leap day.
        assert_eq!(
            format_rfc3339_millis(wct(1_709_208_000, 0)).unwrap(),
            "2024-02-29T12:00:00.000Z"
        );
        // 2000-01-01T00:00:00.000Z — century leap-year boundary.
        assert_eq!(
            format_rfc3339_millis(wct(946_684_800, 0)).unwrap(),
            "2000-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn pre_epoch_is_refused_not_guessed() {
        assert!(format_rfc3339_millis(wct(-1, 0)).is_err());
    }
}
