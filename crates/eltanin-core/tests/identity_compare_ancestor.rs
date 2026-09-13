//! Unit coverage for `WorkloadIdentity::compare_ancestor` (HORO-793).
//! Mirrors `compare_process`'s own truth-table coverage
//! (`identity_golden.rs`) for the ancestry-linkage comparison
//! `delegation::delegated_admission` relies on.

use eltanin_core::identity::{
    Evidence, EvidenceSource, IdentityComparison, ProcessAncestor, ProcessStartToken,
    WorkloadIdentity,
};

fn holder(pid: u32, start: Evidence<ProcessStartToken>) -> WorkloadIdentity {
    WorkloadIdentity {
        pid,
        process_start: start,
        uid: Evidence::Present {
            value: 1000,
            source: EvidenceSource::KernelObserved,
        },
        gid: Evidence::Present {
            value: 1000,
            source: EvidenceSource::KernelObserved,
        },
        executable_path: Evidence::Present {
            value: "/usr/bin/eltanin-run".to_string(),
            source: EvidenceSource::KernelObserved,
        },
        executable_hash: Evidence::Missing {
            reason: "not collected".into(),
        },
        ancestry: Vec::new(),
    }
}

fn ancestor(pid: u32, start: Evidence<ProcessStartToken>) -> ProcessAncestor {
    ProcessAncestor {
        pid,
        start,
        executable_path: Evidence::Present {
            value: "/usr/bin/eltanin-run".to_string(),
            source: EvidenceSource::KernelObserved,
        },
    }
}

fn present(value: u64) -> Evidence<ProcessStartToken> {
    Evidence::Present {
        value: ProcessStartToken(value),
        source: EvidenceSource::KernelObserved,
    }
}

#[test]
fn same_pid_and_start_token_is_same() {
    let h = holder(42, present(100));
    let a = ancestor(42, present(100));
    assert_eq!(h.compare_ancestor(&a), IdentityComparison::Same);
}

#[test]
fn same_pid_different_start_token_is_different() {
    let h = holder(42, present(100));
    let a = ancestor(42, present(999));
    assert_eq!(h.compare_ancestor(&a), IdentityComparison::Different);
}

#[test]
fn different_pid_is_different() {
    let h = holder(42, present(100));
    let a = ancestor(7, present(100));
    assert_eq!(h.compare_ancestor(&a), IdentityComparison::Different);
}

#[test]
fn missing_ancestor_start_token_is_indeterminate_never_same() {
    let h = holder(42, present(100));
    let a = ancestor(
        42,
        Evidence::Missing {
            reason: "permission denied".into(),
        },
    );
    assert_eq!(h.compare_ancestor(&a), IdentityComparison::Indeterminate);
}

#[test]
fn self_asserted_ancestor_start_token_is_indeterminate_never_same() {
    let h = holder(42, present(100));
    let a = ancestor(
        42,
        Evidence::Present {
            value: ProcessStartToken(100),
            source: EvidenceSource::SelfAsserted,
        },
    );
    assert_eq!(h.compare_ancestor(&a), IdentityComparison::Indeterminate);
}

#[test]
fn self_asserted_holder_start_token_is_indeterminate_never_same() {
    let h = holder(
        42,
        Evidence::Present {
            value: ProcessStartToken(100),
            source: EvidenceSource::SelfAsserted,
        },
    );
    let a = ancestor(42, present(100));
    assert_eq!(h.compare_ancestor(&a), IdentityComparison::Indeterminate);
}
