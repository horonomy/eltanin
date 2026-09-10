//! Adversarial and regression coverage for `WorkloadIdentity`/
//! `ExecutionContext` (F-M1-003, HORO-833). Closes F-M1-003 with the
//! spoof/PID-reuse/exit-race/missing-evidence scenarios named in
//! HORO-833's AC. Complements `identity_golden.rs` (HORO-831), which
//! already covers the baseline `compare_process` truth table — this
//! file adds the adversarial framing and scenarios HORO-833 requires.

use eltanin_core::identity::{
    Evidence, EvidenceSource, IdentityComparison, ProcessStartToken, WorkloadIdentity,
};

fn identity_with(
    pid: u32,
    start: Evidence<ProcessStartToken>,
    uid_source: EvidenceSource,
    executable_path: &str,
) -> WorkloadIdentity {
    WorkloadIdentity {
        pid,
        process_start: start,
        uid: Evidence::Present {
            value: 1000,
            source: uid_source,
        },
        gid: Evidence::Present {
            value: 1000,
            source: uid_source,
        },
        executable_path: Evidence::Present {
            value: executable_path.to_string(),
            source: uid_source,
        },
        executable_hash: Evidence::Missing {
            reason: "hashing not implemented".into(),
        },
        ancestry: Vec::new(),
    }
}

fn present(value: u64) -> Evidence<ProcessStartToken> {
    Evidence::Present {
        value: ProcessStartToken(value),
        source: EvidenceSource::KernelObserved,
    }
}

/// **Scenario**: a malicious workload re-executes itself under a
/// different binary while claiming (via self-reported metadata a naive
/// caller might trust) to be the same, already-authorized process at the
/// same PID.
///
/// The type system does not let this succeed silently: comparing the two
/// observed identities on their `process_start` tokens — the one field a
/// same-UID attacker cannot forge by making claims about itself — must
/// report `Different`, never `Same`, once the token actually differs.
#[test]
fn same_pid_different_binary_disguised_as_restart_is_not_reported_same() {
    let original = identity_with(
        4242,
        present(1_000),
        EvidenceSource::KernelObserved,
        "/usr/bin/trusted-tool",
    );
    let attacker = identity_with(
        4242,
        present(1_001),
        EvidenceSource::KernelObserved,
        "/usr/bin/trusted-tool",
    );
    assert_eq!(
        original.compare_process(&attacker),
        IdentityComparison::Different,
        "same pid + same claimed path but a different start token must never compare as Same"
    );
}

/// **Scenario**: PID reuse — the original process exits, the kernel
/// reissues its PID to an unrelated process, and a caller holding a
/// stale `WorkloadIdentity` for that PID re-collects. This must be
/// reported as `Different`, not conflated with "the same long-running
/// process is still here."
#[test]
fn pid_reused_by_unrelated_process_is_reported_different_not_same() {
    let original_holder = identity_with(
        777,
        present(500),
        EvidenceSource::KernelObserved,
        "/usr/bin/original",
    );
    let new_occupant = identity_with(
        777,
        present(999),
        EvidenceSource::KernelObserved,
        "/usr/bin/unrelated",
    );
    assert_eq!(
        original_holder.compare_process(&new_occupant),
        IdentityComparison::Different
    );
}

/// **Scenario**: process exit race — the collector observes a process
/// mid-exit and cannot read its `/proc/<pid>/stat` a second time (the
/// concrete `eltanin-linux` behavior; here exercised at the type level
/// via `Evidence::Missing`, which is what that collector actually
/// produces on such a read failure — see `eltanin-linux`'s
/// `nonexistent_pid_reports_explicit_missing_not_panic`). The comparison
/// must fail safe: `Indeterminate`, never `Same` (which would wrongly
/// vouch for continuity) and never `Different` (which could wrongly
/// imply a confirmed identity change to a caller distinguishing the two).
#[test]
fn process_exit_race_reports_indeterminate_not_a_confirmed_answer() {
    let before_exit = identity_with(
        555,
        present(300),
        EvidenceSource::KernelObserved,
        "/usr/bin/short-lived",
    );
    let mut after_exit = identity_with(
        555,
        present(300),
        EvidenceSource::KernelObserved,
        "/usr/bin/short-lived",
    );
    after_exit.process_start = Evidence::Missing {
        reason: "process exited mid-read".into(),
    };
    let result = before_exit.compare_process(&after_exit);
    assert_eq!(result, IdentityComparison::Indeterminate);
    assert_ne!(result, IdentityComparison::Same);
    assert_ne!(result, IdentityComparison::Different);
}

/// **Scenario**: an attacker controls a process's self-reported fields
/// (the only fields a process can assert about itself) and claims a
/// trusted executable path and UID. `EvidenceSource::SelfAsserted`
/// exists precisely so this claim is representable without being
/// indistinguishable from a kernel-verified one — `Evidence<T>`'s
/// `PartialEq` includes the `source`, so a self-asserted claim of the
/// exact same value a kernel-observed reading would produce still does
/// not compare equal to it.
#[test]
fn self_asserted_claim_never_compares_equal_to_the_same_kernel_observed_value() {
    let claimed = Evidence::Present {
        value: "/usr/bin/trusted-tool".to_string(),
        source: EvidenceSource::SelfAsserted,
    };
    let observed = Evidence::Present {
        value: "/usr/bin/trusted-tool".to_string(),
        source: EvidenceSource::KernelObserved,
    };
    assert_ne!(
        claimed, observed,
        "identical claimed value must still be distinguishable from a kernel-observed one by source"
    );
}

/// **Scenario**: same executable *path* string reused by two workloads
/// that are not actually the same authorized binary (e.g. an attacker
/// places a malicious binary at a path a policy might allowlist by
/// string). `WorkloadIdentity` equality must not collapse two otherwise
/// distinct identities just because their claimed `executable_path`
/// strings match — the full struct, including `executable_hash` and
/// `pid`/`process_start`, participates in equality.
#[test]
fn same_claimed_path_with_different_process_start_is_not_the_same_identity() {
    let legitimate = identity_with(
        88,
        present(10),
        EvidenceSource::KernelObserved,
        "/usr/bin/tool",
    );
    let impostor = identity_with(
        89,
        present(20),
        EvidenceSource::KernelObserved,
        "/usr/bin/tool",
    );
    assert_ne!(legitimate, impostor);
    assert_eq!(
        legitimate.compare_process(&impostor),
        IdentityComparison::Different
    );
}

/// **Scenario**: missing evidence regression — once a field is
/// `Evidence::Missing`, no comparison or accessor may treat it as
/// present. This pins the `Evidence::value()`/`is_present()` contract
/// against a future change accidentally defaulting a missing value.
#[test]
fn missing_evidence_never_reports_present_or_yields_a_value() {
    let missing: Evidence<u32> = Evidence::Missing {
        reason: "permission denied".into(),
    };
    assert!(!missing.is_present());
    assert_eq!(missing.value(), None);

    let unsupported: Evidence<u32> = Evidence::Unsupported;
    assert!(!unsupported.is_present());
    assert_eq!(unsupported.value(), None);
}
