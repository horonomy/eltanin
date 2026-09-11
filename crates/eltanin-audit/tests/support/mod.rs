//! Shared test support for `eltanin-audit` integration tests
//! (F-M1-009, HORO-824).
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};

use eltanin_audit::record::{
    AuditClock, RecordedPeer, RecordedPeerConsistency, RecordedPeerCredential, WallClockTime,
};
use eltanin_core::identity::{Evidence, ExecutionContext, WorkloadIdentity};

fn private_base_dir() -> PathBuf {
    static INIT: Once = Once::new();
    let real_tmp = std::fs::canonicalize("/tmp").unwrap_or_else(|_| PathBuf::from("/tmp"));
    let base = real_tmp.join(format!("eltanin-audit-tests-{}", std::process::id()));
    INIT.call_once(|| {
        std::fs::create_dir_all(&base).expect("create private test base dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))
                .expect("chmod private test base dir");
        }
    });
    base
}

pub fn temp_log_path(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    private_base_dir().join(format!("{tag}-{n}.ndjson"))
}

pub fn peer(pid: u32) -> RecordedPeer {
    RecordedPeer {
        credential: RecordedPeerCredential {
            pid,
            effective_uid: 1000,
            effective_gid: 1000,
        },
        consistency: RecordedPeerConsistency::Consistent,
        observed: ExecutionContext {
            workload: WorkloadIdentity {
                pid,
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
    }
}

struct FixedClock(Mutex<u64>);

impl AuditClock for FixedClock {
    fn now(&self) -> WallClockTime {
        let mut guard = self.0.lock().unwrap();
        *guard += 1;
        WallClockTime {
            unix_secs: i64::try_from(*guard).unwrap(),
            nanos: 0,
        }
    }
}

pub fn fixed_clock() -> Arc<dyn AuditClock> {
    Arc::new(FixedClock(Mutex::new(0)))
}
