//! Golden and behavioral tests for `WorkloadIdentity`/`ExecutionContext`
//! (HORO-831). Complements `resource_golden.rs`'s pattern.

use eltanin_core::identity::{
    Evidence, EvidenceSource, ExecutionContext, ProcessAncestor, ProcessStartToken,
    WorkloadIdentity,
};

fn sample_identity(pid: u32, start: u64) -> WorkloadIdentity {
    WorkloadIdentity {
        pid,
        process_start: Evidence::Present {
            value: ProcessStartToken(start),
            source: EvidenceSource::KernelObserved,
        },
        uid: Evidence::Present {
            value: 1000,
            source: EvidenceSource::KernelObserved,
        },
        gid: Evidence::Present {
            value: 1000,
            source: EvidenceSource::KernelObserved,
        },
        executable_path: Evidence::Present {
            value: "/usr/bin/example".into(),
            source: EvidenceSource::BestEffort,
        },
        executable_hash: Evidence::Missing {
            reason: "hashing not yet implemented".into(),
        },
        ancestry: vec![ProcessAncestor {
            pid: 1,
            start: Evidence::Unsupported,
            executable_path: Evidence::Unsupported,
        }],
    }
}

#[test]
fn workload_identity_golden_json() {
    let identity = sample_identity(42, 100);
    let json = serde_json::to_string_pretty(&identity).unwrap();
    let expected = r#"{
  "pid": 42,
  "process_start": {
    "state": "present",
    "value": 100,
    "source": "kernel_observed"
  },
  "uid": {
    "state": "present",
    "value": 1000,
    "source": "kernel_observed"
  },
  "gid": {
    "state": "present",
    "value": 1000,
    "source": "kernel_observed"
  },
  "executable_path": {
    "state": "present",
    "value": "/usr/bin/example",
    "source": "best_effort"
  },
  "executable_hash": {
    "state": "missing",
    "reason": "hashing not yet implemented"
  },
  "ancestry": [
    {
      "pid": 1,
      "start": {
        "state": "unsupported"
      },
      "executable_path": {
        "state": "unsupported"
      }
    }
  ]
}"#;
    assert_eq!(json, expected);
}

#[test]
fn workload_identity_roundtrips() {
    let original = sample_identity(42, 100);
    let json = serde_json::to_string(&original).unwrap();
    let decoded: WorkloadIdentity = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn same_pid_same_start_is_the_same_process() {
    let a = sample_identity(42, 100);
    let b = sample_identity(42, 100);
    assert!(a.same_process(&b));
}

#[test]
fn same_pid_different_start_is_pid_reuse_not_the_same_process() {
    let a = sample_identity(42, 100);
    let b = sample_identity(42, 200);
    assert!(!a.same_process(&b));
}

#[test]
fn missing_start_token_is_never_assumed_to_be_the_same_process() {
    // If either side's process_start is not Present, the comparison must
    // return false, not silently fall back to comparing pid alone —
    // that would let an indeterminate observation masquerade as a
    // confirmed identity match.
    let mut a = sample_identity(42, 100);
    a.process_start = Evidence::Missing {
        reason: "permission denied".into(),
    };
    let b = sample_identity(42, 100);
    assert!(!a.same_process(&b));
    assert!(!b.same_process(&a));
}

#[test]
fn unsupported_start_token_is_never_assumed_to_be_the_same_process() {
    let mut a = sample_identity(42, 100);
    a.process_start = Evidence::Unsupported;
    let b = sample_identity(42, 100);
    assert!(!a.same_process(&b));
}

#[test]
fn different_pid_is_never_the_same_process_regardless_of_start() {
    let a = sample_identity(42, 100);
    let b = sample_identity(43, 100);
    assert!(!a.same_process(&b));
}

#[test]
fn spoof_prone_fields_alone_cannot_be_used_to_assert_trust() {
    // uid/executable_path/ancestry are present as Evidence, not as a
    // boolean "trusted" flag — nothing in the type system lets a caller
    // ask "is this trusted" without inspecting the actual EvidenceSource.
    // This test exercises that every one of them requires an explicit
    // source before a caller could even consider weighing it.
    let identity = sample_identity(42, 100);
    assert_eq!(identity.uid.value(), Some(&1000));
    if let Evidence::Present { source, .. } = &identity.uid {
        assert_eq!(*source, EvidenceSource::KernelObserved);
    } else {
        panic!("expected uid to be Present with an explicit source");
    }
    // Ancestry (parent == trusted) is explicitly Unsupported here, and
    // callers must handle that rather than assume presence.
    assert!(!identity.ancestry[0].start.is_present());
}

#[test]
fn execution_context_carries_workload_and_cgroup_evidence() {
    let context = ExecutionContext {
        workload: sample_identity(42, 100),
        cgroup_path: Evidence::Present {
            value: "/sys/fs/cgroup/user.slice".into(),
            source: EvidenceSource::KernelObserved,
        },
        namespace_hint: Evidence::Unsupported,
        container_hint: Evidence::Unsupported,
        session_origin: Evidence::Missing {
            reason: "no session manager detected".into(),
        },
    };
    let json = serde_json::to_string(&context).unwrap();
    let decoded: ExecutionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, context);
}
