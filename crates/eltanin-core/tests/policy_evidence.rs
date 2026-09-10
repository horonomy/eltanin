//! `TrustFloor`/`EvidenceMatch` unit coverage (F-M1-004, HORO-834).

use eltanin_core::identity::{Evidence, EvidenceSource};
use eltanin_core::policy::{EvidenceMatch, TrustFloor};

#[test]
fn no_trust_floor_admits_self_asserted_evidence() {
    // The core security property of this module: EvidenceSource has
    // three variants, but TrustFloor has only two, and neither of them
    // maps to SelfAsserted. This is exhaustive by construction — there
    // is no floor value a rule author could pick that would admit it.
    assert!(!TrustFloor::KernelObserved.admits(EvidenceSource::SelfAsserted));
    assert!(!TrustFloor::BestEffort.admits(EvidenceSource::SelfAsserted));
}

#[test]
fn kernel_observed_floor_rejects_best_effort() {
    assert!(!TrustFloor::KernelObserved.admits(EvidenceSource::BestEffort));
    assert!(TrustFloor::KernelObserved.admits(EvidenceSource::KernelObserved));
}

#[test]
fn best_effort_floor_admits_both_unforgeable_sources() {
    assert!(TrustFloor::BestEffort.admits(EvidenceSource::BestEffort));
    assert!(TrustFloor::BestEffort.admits(EvidenceSource::KernelObserved));
}

#[test]
fn missing_evidence_never_matches_regardless_of_floor() {
    let m = EvidenceMatch {
        expected: 1000u32,
        min_trust: TrustFloor::BestEffort,
    };
    let missing: Evidence<u32> = Evidence::Missing {
        reason: "permission denied".into(),
    };
    assert!(!m.matches(&missing));
}

#[test]
fn unsupported_evidence_never_matches_regardless_of_floor() {
    let m = EvidenceMatch {
        expected: 1000u32,
        min_trust: TrustFloor::BestEffort,
    };
    let unsupported: Evidence<u32> = Evidence::Unsupported;
    assert!(!m.matches(&unsupported));
}

#[test]
fn present_evidence_below_the_trust_floor_does_not_match() {
    let m = EvidenceMatch {
        expected: 1000u32,
        min_trust: TrustFloor::KernelObserved,
    };
    let self_asserted = Evidence::Present {
        value: 1000u32,
        source: EvidenceSource::SelfAsserted,
    };
    assert!(!m.matches(&self_asserted));
}

#[test]
fn present_evidence_at_or_above_the_trust_floor_with_matching_value_matches() {
    let m = EvidenceMatch {
        expected: 1000u32,
        min_trust: TrustFloor::KernelObserved,
    };
    let observed = Evidence::Present {
        value: 1000u32,
        source: EvidenceSource::KernelObserved,
    };
    assert!(m.matches(&observed));
}

#[test]
fn present_evidence_with_a_different_value_does_not_match_even_at_full_trust() {
    let m = EvidenceMatch {
        expected: 1000u32,
        min_trust: TrustFloor::KernelObserved,
    };
    let observed = Evidence::Present {
        value: 1001u32,
        source: EvidenceSource::KernelObserved,
    };
    assert!(!m.matches(&observed));
}
