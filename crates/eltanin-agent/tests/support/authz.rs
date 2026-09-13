//! Shared test support for `authz_*.rs` integration tests (F-M1-006,
//! HORO-840).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use eltanin_agent::authz::Clock;
use eltanin_backend::fake::FakeBackend;
use eltanin_core::identity::{
    Evidence, EvidenceSource, ExecutionContext, ProcessStartToken, WorkloadIdentity,
};
use eltanin_core::lease::MonotonicTime;
use eltanin_core::peer::{PeerConsistency, PeerContext, PeerCredential};
use eltanin_core::policy::PolicyId;
use eltanin_core::policy::{
    Condition, Effect, EvidenceMatch, PolicyDocument, PolicySet, Rule, RuleId, TrustFloor,
};
use eltanin_core::resource::{
    AcceleratorMemory, Action, Capability, ComputeRequest, ProtectedResource, ResourceCapabilities,
    ResourceIdentity, ResourceKind, ResourceVendor,
};

/// A fully-specified fake peer identity, distinct instances of which
/// represent distinct clients (different `pid`/`process_start`).
#[derive(Clone)]
pub struct TestPeer {
    pub pid: u32,
    pub process_start: u64,
    pub uid: u32,
    pub executable_hash: &'static str,
}

static NEXT_PID: AtomicU64 = AtomicU64::new(5000);

impl TestPeer {
    /// A fresh peer with a unique pid/start token, so two calls produce
    /// two identities `compare_process` reports as `Different`.
    pub fn fresh(uid: u32, executable_hash: &'static str) -> Self {
        let pid = NEXT_PID.fetch_add(1, Ordering::SeqCst);
        Self {
            pid: u32::try_from(pid).expect("test pid fits u32"),
            process_start: pid,
            uid,
            executable_hash,
        }
    }

    fn workload(&self) -> WorkloadIdentity {
        WorkloadIdentity {
            pid: self.pid,
            process_start: Evidence::Present {
                value: ProcessStartToken(self.process_start),
                source: EvidenceSource::KernelObserved,
            },
            uid: Evidence::Present {
                value: self.uid,
                source: EvidenceSource::KernelObserved,
            },
            gid: Evidence::Unsupported,
            // Present (not Unsupported) so F-M2-002/HORO-792's approval
            // gate — which needs a launcher path to bind an
            // ApprovalBinding — has something to observe. No existing
            // test asserts this field is Unsupported.
            executable_path: Evidence::Present {
                value: "/usr/bin/eltanin-test-workload".to_string(),
                source: EvidenceSource::KernelObserved,
            },
            executable_hash: Evidence::Present {
                value: self.executable_hash.to_string(),
                source: EvidenceSource::KernelObserved,
            },
            ancestry: Vec::new(),
        }
    }

    fn execution_context(&self) -> ExecutionContext {
        ExecutionContext {
            workload: self.workload(),
            cgroup_path: Evidence::Unsupported,
            namespace_hint: Evidence::Unsupported,
            container_hint: Evidence::Unsupported,
            session_origin: Evidence::Unsupported,
        }
    }

    /// A `Consistent`, `authorizable()`-passing [`PeerContext`] for this
    /// identity — as if `SO_PEERCRED` and `/proc` had agreed.
    pub fn context(&self) -> PeerContext {
        PeerContext::new(
            PeerCredential::new(self.pid, self.uid, self.uid),
            PeerConsistency::Consistent,
            self.execution_context(),
        )
    }

    /// A peer whose kernel credential and `/proc` evidence disagree —
    /// never `authorizable()`.
    pub fn inconsistent_context(&self) -> PeerContext {
        PeerContext::new(
            PeerCredential::new(self.pid, self.uid, self.uid),
            PeerConsistency::CredentialDivergence {
                peer_effective_uid: self.uid,
                observed_real_uid: Evidence::Present {
                    value: self.uid + 1,
                    source: EvidenceSource::KernelObserved,
                },
                observed_effective_uid: Evidence::Present {
                    value: self.uid + 1,
                    source: EvidenceSource::KernelObserved,
                },
            },
            self.execution_context(),
        )
    }
}

pub fn resource_identity() -> ResourceIdentity {
    ResourceIdentity {
        vendor: ResourceVendor::fake(),
        kind: ResourceKind::gpu(),
        local_id: "gpu-0".to_string(),
    }
}

pub fn compute_request() -> ComputeRequest {
    ComputeRequest {
        resource: resource_identity(),
        action: Action::Compute,
    }
}

/// A [`PolicySet`] with one allow rule matching `uid` and a
/// [`FakeBackend`] with `resource_identity()` present and supporting
/// `capabilities`.
pub fn allow_policy_for_uid(uid: u32) -> PolicySet {
    let rule = Rule {
        id: RuleId::new("allow-uid"),
        effect: Effect::Allow,
        resource: resource_identity(),
        action: Action::Compute,
        conditions: vec![Condition::Uid(EvidenceMatch {
            expected: uid,
            min_trust: TrustFloor::KernelObserved,
        })],
    };
    let document = PolicyDocument {
        id: PolicyId::new("test-policy"),
        revision: 1,
        rules: vec![rule],
    };
    PolicySet::from_document(document).expect("valid test policy")
}

/// A [`PolicySet`] with zero rules — default-deny denies everything.
pub fn deny_all_policy() -> PolicySet {
    let document = PolicyDocument {
        id: PolicyId::new("deny-all"),
        revision: 1,
        rules: vec![],
    };
    PolicySet::from_document(document).expect("valid empty policy")
}

pub fn backend_with_resource(capabilities: &[Capability]) -> Arc<FakeBackend> {
    let backend = Arc::new(FakeBackend::new());
    backend.insert(ProtectedResource {
        identity: resource_identity(),
        capabilities: ResourceCapabilities::new(capabilities.iter().copied()),
        memory: AcceleratorMemory::NotReportable,
    });
    backend
}

/// A [`Clock`] whose reading only ever advances when explicitly told to
/// — deterministic expiry testing without real sleeps.
pub struct FixedClock(Mutex<MonotonicTime>);

impl FixedClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(MonotonicTime::from_nanos(0))))
    }

    pub fn advance(&self, duration: std::time::Duration) {
        let mut guard = self.0.lock().expect("clock lock poisoned");
        *guard = guard
            .checked_add(duration)
            .expect("test clock advance does not overflow");
    }
}

impl Clock for FixedClock {
    fn now(&self) -> MonotonicTime {
        *self.0.lock().expect("clock lock poisoned")
    }
}
