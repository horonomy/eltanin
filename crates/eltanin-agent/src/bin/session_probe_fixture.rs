//! `session-probe-fixture` — a disposable, non-product test fixture
//! binary (F-M2-001, HORO-791).
//!
//! Calls `rustix::process::setsid()` at startup to detach into a fresh
//! POSIX session, prints its own pid, then blocks on stdin until the
//! test harness closes it (or kills this process). Exists so
//! `tests/authz_session.rs`'s AC2 sid-reuse/foreign-session test has a
//! real child process provably in a *different* session than the test
//! harness itself — no synthetic/fake `WorkloadIdentity` can honestly
//! stand in for this, since `eltanin_linux`/`eltanin_macos`'s
//! `collect_session_key` reads real kernel state for a real pid, never
//! an injectable value (see `crate::authz::session`'s own docs).
//!
//! Mirrors `crates/eltanin-apple/src/bin/metal_workload_fixture.rs`'s
//! existing precedent for a disposable test fixture binary: not part of
//! any product runtime path, not shipped as a documented CLI surface.
#![forbid(unsafe_code)]

use std::io::{Read, Write};

fn main() {
    // Best-effort: a shell that already made this process its own
    // session leader (rare, but possible under some test runners) makes
    // this a no-op success rather than a hard requirement — the test
    // harness verifies the *actual* resulting session id independently
    // via the real platform collector, never trusts this call's
    // `Ok`/`Err` alone.
    let _ = rustix::process::setsid();

    println!("ready pid={}", std::process::id());
    let _ = std::io::stdout().flush();

    // Block until stdin is closed by the test harness or a byte is
    // written to signal shutdown — whichever comes first.
    let mut buf = [0u8; 1];
    let _ = std::io::stdin().read(&mut buf);
}
