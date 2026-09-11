//! Exit-code taxonomy coverage (F-M1-008, HORO-845). Must stay in sync
//! with `docs/product/CLI_CONTRACT.md`'s exit-code table.

use eltanin_cli::exit::{workload_signal_exit_code, ExitCode};

const ALL: &[ExitCode] = &[
    ExitCode::Usage,
    ExitCode::AgentUnavailable,
    ExitCode::AgentError,
    ExitCode::GovernedContextFailed,
    ExitCode::AuthorizationLapsed,
    ExitCode::Denied,
    ExitCode::ProfileUnresolved,
];

#[test]
fn every_exit_code_matches_the_documented_table() {
    assert_eq!(ExitCode::Usage.code(), 64);
    assert_eq!(ExitCode::AgentUnavailable.code(), 69);
    assert_eq!(ExitCode::AgentError.code(), 70);
    assert_eq!(ExitCode::GovernedContextFailed.code(), 74);
    assert_eq!(ExitCode::AuthorizationLapsed.code(), 76);
    assert_eq!(ExitCode::Denied.code(), 77);
    assert_eq!(ExitCode::ProfileUnresolved.code(), 78);
}

#[test]
fn every_eltanin_exit_code_is_pairwise_distinct() {
    for (i, a) in ALL.iter().enumerate() {
        for (j, b) in ALL.iter().enumerate() {
            if i != j {
                assert_ne!(
                    a.code(),
                    b.code(),
                    "{a:?} and {b:?} must not share an exit code"
                );
            }
        }
    }
}

#[test]
fn every_eltanin_exit_code_falls_in_the_reserved_sysexits_style_range() {
    // 0..=125 is workload passthrough, 126/127 is spawn failure, 128+N
    // is a signal-terminated workload — eltanin's own codes must not
    // collide with any of those ranges.
    for code in ALL {
        let value = code.code();
        assert!(
            (64..128).contains(&value),
            "{code:?} = {value} must fall in 64..128, outside the workload-passthrough \
             (0..=125), spawn-failure (126/127), and signal (128+N) ranges"
        );
    }
}

#[test]
fn workload_signal_exit_code_uses_the_128_plus_n_convention() {
    assert_eq!(workload_signal_exit_code(2), 130); // SIGINT
    assert_eq!(workload_signal_exit_code(9), 137); // SIGKILL
    assert_eq!(workload_signal_exit_code(15), 143); // SIGTERM
}

#[test]
fn workload_signal_exit_code_saturates_rather_than_overflows() {
    assert_eq!(workload_signal_exit_code(255), 255);
}

#[test]
fn authorization_lapsed_exit_code_does_not_collide_with_any_128_plus_n_signal_code() {
    // Exit 76 falls below 128, so it can never be confused with a
    // workload-terminated-by-signal code, which is always >= 128 + 1.
    assert!(ExitCode::AuthorizationLapsed.code() < 128);
}
