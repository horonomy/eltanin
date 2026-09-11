//! Shared test support (F-M1-006, HORO-839/HORO-840).
//!
//! `#![allow(dead_code)]`: each `tests/*.rs` binary compiles this whole
//! module but only uses a subset of it — the unused-per-binary items are
//! not a real dead-code smell, just the shape of a shared support module
//! across many integration-test binaries.
#![allow(dead_code)]

pub mod authz;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;

/// A private (`0o700`), per-test-process base directory to bind test
/// sockets into. `/tmp` itself is world/group-writable (and, on macOS,
/// a symlink to `/private/tmp`) — `BoundSocket::bind`'s parent-directory
/// check correctly refuses to bind directly into it, so tests need
/// their own private subdirectory rather than exercising a case the
/// production code deliberately forbids.
fn private_base_dir() -> PathBuf {
    static INIT: Once = Once::new();
    let real_tmp = std::fs::canonicalize("/tmp").unwrap_or_else(|_| PathBuf::from("/tmp"));
    let base = real_tmp.join(format!("eltanin-agent-tests-{}", std::process::id()));
    INIT.call_once(|| {
        std::fs::create_dir_all(&base).expect("create private test base dir");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))
            .expect("chmod private test base dir");
    });
    base
}

/// A short, unique socket path inside [`private_base_dir`]. `sun_path`
/// (the kernel struct backing a Unix socket address) is ~107 bytes, so
/// the length is asserted explicitly rather than assumed.
pub fn temp_socket_path(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = private_base_dir().join(format!("{tag}-{n}.sock"));
    assert!(
        path.as_os_str().len() < 100,
        "socket path too long for sun_path: {}",
        path.display()
    );
    path
}
