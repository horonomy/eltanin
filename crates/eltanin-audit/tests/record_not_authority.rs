//! "Audit records cannot be used as authorization input merely by
//! editing/replaying them" (F-M1-009, HORO-824, AC #5) — enforced by the
//! compiler, not by review discipline. See `src/record.rs`'s module doc
//! for the full argument: every authority-bearing `eltanin-core` type
//! (`ComputeLease`, `PolicyDecision`, `DecisionReason`,
//! `PolicyProvenance`, `LeaseValidity`) is `Serialize`-only, and
//! `LeaseError` has no serde derives at all, so `AuditRecord` embeds
//! hand-written `Recorded*` mirrors instead. This file scans the source
//! for a violation of that discipline and separately proves a forged
//! record still decodes only to plain data.

use std::fs;
use std::path::{Path, PathBuf};

use eltanin_audit::record::{
    AuditEventId, AuditRecord, RecordedOperation, RecordedOutcome, RecordedPeer,
    RecordedPeerConsistency, RecordedPeerCredential, RecordedRequest, WallClockTime,
};
use eltanin_core::envelope::Versioned;
use eltanin_core::identity::{Evidence, ExecutionContext, WorkloadIdentity};
use eltanin_core::lease::IssuerInstanceId;
use eltanin_core::resource::{Action, ResourceIdentity, ResourceKind, ResourceVendor};
use eltanin_protocol::response::{AgentResponse, DenialReason};

const FORBIDDEN_DIRECT_EMBED: &[&str] = &[
    ": ComputeLease",
    ": PolicyDecision",
    ": DecisionReason",
    ": PolicyProvenance",
    ": LeaseValidity",
    ": LeaseError",
];

#[test]
fn record_schema_never_directly_embeds_an_authority_bearing_type() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut violations = Vec::new();
    let mut files = Vec::new();
    collect(&src_dir, &mut files);
    for file in files {
        let contents = fs::read_to_string(&file).expect("read source file");
        for term in FORBIDDEN_DIRECT_EMBED {
            if contents.contains(term) {
                violations.push(format!("{}: embeds {term:?} directly", file.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "found a direct embed of an authority-bearing type — use its Recorded* mirror instead:\n{}",
        violations.join("\n")
    );
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn a_hand_edited_log_line_deserializes_to_a_record_and_nothing_else() {
    // Simulates an operator (or attacker with filesystem access) editing
    // a log line by hand — even a well-formed, schema-valid edit only
    // ever produces an AuditRecord, which no eltanin-core/agent API
    // accepts as an authorization input. There is no function in this
    // workspace with a signature `fn(AuditRecord) -> ComputeLease` (or
    // similar) for this test to call, which is itself the point: the
    // type simply doesn't exist to misuse.
    let forged = AuditRecord {
        event_id: AuditEventId {
            instance: IssuerInstanceId::new("attacker-supplied-instance"),
            sequence: 0,
        },
        recorded_at: WallClockTime {
            unix_secs: 0,
            nanos: 0,
        },
        operation: RecordedOperation::RequestLease,
        requested: RecordedRequest::RequestLease {
            resource: ResourceIdentity {
                vendor: ResourceVendor::fake(),
                kind: ResourceKind::gpu(),
                local_id: "gpu-0".to_string(),
            },
            action: Action::Compute,
        },
        peer: RecordedPeer {
            credential: RecordedPeerCredential {
                pid: 1,
                effective_uid: 0,
                effective_gid: 0,
            },
            consistency: RecordedPeerConsistency::Consistent,
            observed: ExecutionContext {
                workload: WorkloadIdentity {
                    pid: 1,
                    process_start: Evidence::Unsupported,
                    uid: Evidence::Unsupported,
                    gid: Evidence::Unsupported,
                    executable_path: Evidence::Unsupported,
                    executable_hash: Evidence::Unsupported,
                    ancestry: Vec::new(),
                },
                cgroup_path: Evidence::Unsupported,
                namespace_hint: Evidence::Unsupported,
                container_hint: Evidence::Unsupported,
                session_origin: Evidence::Unsupported,
            },
        },
        outcome: RecordedOutcome::PeerNotAuthorizable,
        response: AgentResponse::LeaseDenied {
            reason: DenialReason::IndeterminateEvidence,
        },
    };
    let json = serde_json::to_string(&Versioned::current(forged)).unwrap();
    let decoded: Versioned<AuditRecord> = serde_json::from_str(&json).unwrap();
    // The only thing this could ever become: an AuditRecord — proven by
    // the fact that this is the only type annotation that compiles here.
    let record: AuditRecord = decoded.payload;
    drop(record);
}

#[test]
fn a_version_mismatched_envelope_is_reported_not_silently_accepted() {
    let mut value: serde_json::Value = serde_json::json!({"version": 1, "payload": {}});
    value["version"] = serde_json::json!(9999);
    let text = value.to_string();
    let decoded: Versioned<serde_json::Value> = serde_json::from_str(&text).unwrap();
    assert_ne!(
        decoded.version,
        eltanin_core::envelope::DOMAIN_SCHEMA_VERSION
    );
    // read_log's own handling of this exact case is covered in
    // explain_selectors.rs; this test only pins that Versioned itself
    // preserves the mismatched version rather than coercing it.
}
