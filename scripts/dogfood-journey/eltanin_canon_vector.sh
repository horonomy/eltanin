#!/usr/bin/env bash
# Eltanin cross-product canonicalization-vector agreement journey
# (HORO-1381 sub-ticket 6).
#
# Runs on `next/mvp-2.0` -- the DogFood adapter does not exist on `main`
# (ADR-0012 section 11.4).
#
# Implements tools/dogfood-conformance/JOURNEY-CONTRACT.md
# (horonomy/internal-docs). Reads this repo's own bundled copy of
# vectors/canon-v1-vector-001.json, builds and runs the new
# crates/eltanin-dogfood/examples/canon_vector.rs against it (which
# hand-constructs the real, shipped eltanin_dogfood::event::Event from
# the vector's own field values and calls the real, shipped
# eltanin_dogfood::canon::{canonicalize, hash_event}), and compares the
# result against the vector's own bundled `canonical`/`content_hash`
# pin. Unlike Horologium/Libra Governor, this product can emit BOTH the
# canonical string and the hash, so both are compared here -- comparing
# the example's own canonical string against the pin additionally
# catches transcription drift in the example's hand-construction, not
# just a hashing bug. Agreement here plus the same agreement
# independently reproduced by circinus, ophiuchus, libra-governor, and
# horologium against the SAME pin is what proves five-way cross-product
# canonicalization agreement.
#
# stdout: ONLY one NDJSON check row. Everything else -> stderr.
#
# This script never modifies crates/eltanin-dogfood/src/ or
# Cargo.toml -- it only builds and drives the new, non-shipping
# `examples/canon_vector.rs` target.
#
# Infrastructure-failure rule (pin, do not deviate): a `cargo run
# --example` build failure, an unrecognized field value the example's
# RawEvent/parse_* helpers cannot map, or a missing vector file produces
# empty stdout and a nonzero exit -- an infrastructure failure, never a
# fabricated FAILED row.

set -uo pipefail

log() { printf '%s\n' "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VECTOR_PATH="${REPO_ROOT}/scripts/dogfood-journey/vectors/canon-v1-vector-001.json"

if ! command -v cargo >/dev/null 2>&1; then
    die "cargo not found on PATH"
fi

if [[ ! -f "${VECTOR_PATH}" ]]; then
    die "vector file missing: ${VECTOR_PATH}"
fi

EXAMPLE_STDERR="$(mktemp "${TMPDIR:-/tmp}/eltanin_canon_vector.stderr.XXXXXX")"
trap 'rm -f "${EXAMPLE_STDERR}"' EXIT

EXAMPLE_OUTPUT="$(cd "${REPO_ROOT}" && cargo run -q -p eltanin-dogfood --example canon_vector < "${VECTOR_PATH}" 2>"${EXAMPLE_STDERR}")"
EXAMPLE_EXIT=$?

if [[ -s "${EXAMPLE_STDERR}" ]]; then
    log "example stderr: $(cat "${EXAMPLE_STDERR}")"
fi

if [[ ${EXAMPLE_EXIT} -ne 0 ]]; then
    die "cargo run --example canon_vector exited ${EXAMPLE_EXIT} (build/parse/setup failure -- infrastructure failure, not a check result)"
fi

if [[ -z "${EXAMPLE_OUTPUT}" ]]; then
    die "cargo run --example canon_vector produced no output"
fi

VECTOR_PATH="${VECTOR_PATH}" EXAMPLE_OUTPUT="${EXAMPLE_OUTPUT}" python3 - <<'PYEOF'
import json
import os
import sys

vector_path = os.environ["VECTOR_PATH"]
example_output = os.environ["EXAMPLE_OUTPUT"]

try:
    with open(vector_path, encoding="utf-8") as fh:
        vector = json.load(fh)
except (OSError, json.JSONDecodeError) as exc:
    print(f"FATAL: could not read/parse vector file: {exc}", file=sys.stderr)
    sys.exit(1)

try:
    observed = json.loads(example_output.strip().splitlines()[-1])
except (json.JSONDecodeError, IndexError) as exc:
    print(f"FATAL: could not parse example stdout as JSON: {exc}; raw={example_output!r}", file=sys.stderr)
    sys.exit(1)

expected_canonical = vector["canonical"]
expected_hash = vector["content_hash"]
observed_canonical = observed.get("canonical")
observed_hash = observed.get("content_hash")

canonical_matches = observed_canonical == expected_canonical
hash_matches = observed_hash == expected_hash

row = {
    "product": "eltanin",
    "dfc_id": "DFC-SCHEMA-09",
    "virtual_time": False,
}

if canonical_matches and hash_matches:
    row["result"] = "PROVEN"
    row["assertion"] = (
        "eltanin-dogfood's shipped canon::canonicalize/canon::hash_event "
        "reproduces pinned vector canon-v1-vector-001's canonical string "
        "and content_hash"
    )
    row["rationale"] = f"computed {observed_hash['value']}, matches the vector's bundled pin"
else:
    row["result"] = "FAILED"
    row["assertion"] = (
        "eltanin-dogfood's shipped canon::canonicalize/canon::hash_event "
        "reproduces pinned vector canon-v1-vector-001's canonical string "
        "and content_hash"
    )
    row["rationale"] = (
        f"mismatch: expected canonical={expected_canonical!r} content_hash={expected_hash!r}; "
        f"observed canonical={observed_canonical!r} content_hash={observed_hash!r}"
    )

print(json.dumps(row))
PYEOF
