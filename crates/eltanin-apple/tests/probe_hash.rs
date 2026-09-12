//! Hardware-free, deterministic coverage for
//! `eltanin_apple::probe::fnv1a_64` (F-M1-010, HORO-1014): the function
//! `metal_workload_fixture`'s "workload input hash/config" evidence
//! field and `crate::probe::ComputeProbeReport::input_hash` both depend
//! on. Unconditional (no `target_os` gate) and runs on every CI platform
//! this workspace has, including `ubuntu-latest` — the "Result is
//! deterministic and independently checked" Acceptance Criterion is
//! checked here against the published FNV-1a-64 reference test vectors
//! (<http://www.isthe.com/chongo/tech/comp/fnv/index.html>), not merely
//! against whatever this implementation happens to compute.

use eltanin_apple::probe::fnv1a_64;

#[test]
fn empty_input_hashes_to_the_fnv_offset_basis() {
    // FNV-1a's loop body never runs for an empty slice, so the result is
    // exactly the algorithm's defined 64-bit offset basis.
    assert_eq!(fnv1a_64(b""), 0xcbf2_9ce4_8422_2325);
}

#[test]
fn known_answer_test_vectors_match_the_published_fnv_1a_64_reference() {
    // Reference values from the canonical FNV test vector suite.
    let cases: &[(&[u8], u64)] = &[
        (b"a", 0xaf63_dc4c_8601_ec8c),
        (b"foobar", 0x8594_4171_f739_67e8),
    ];
    for (input, expected) in cases {
        assert_eq!(
            fnv1a_64(input),
            *expected,
            "fnv1a_64({input:?}) did not match the published FNV-1a-64 reference vector"
        );
    }
}

#[test]
fn hashing_is_deterministic_across_repeated_calls() {
    let input = b"eltanin-apple-metal-workload-fixture";
    let first = fnv1a_64(input);
    let second = fnv1a_64(input);
    assert_eq!(
        first, second,
        "fnv1a_64 must be a pure, deterministic function of its input"
    );
}

#[test]
fn a_single_differing_byte_changes_the_hash() {
    // Not a security property (this hash makes no such claim — see
    // `probe.rs`'s doc comment) — just confirms the fixture's
    // "input_hash" field is actually sensitive to its input, not a
    // constant that would silently satisfy any workload.
    assert_ne!(fnv1a_64(b"input-a"), fnv1a_64(b"input-b"));
}
