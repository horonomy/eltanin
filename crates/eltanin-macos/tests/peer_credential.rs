//! Peer credential derivation coverage (F-M1-010, HORO-1013 — mirrors
//! `crates/eltanin-linux/tests/peer_credential.rs`). Real
//! `LOCAL_PEERCRED`/`LOCAL_PEERPID` behavior only meaningfully validates
//! on macOS (this repo's `macos-latest` CI); on any other `target_os`
//! the documented `UnsupportedPlatform` fallback is what's validated
//! instead, so this test still compiles and passes on a Linux dev
//! machine.

#[cfg(target_os = "macos")]
use eltanin_core::peer::PeerConsistency;
#[cfg(not(target_os = "macos"))]
use eltanin_core::peer::PeerCredentialError;
use eltanin_macos::peer::collect_peer_context;

#[cfg(target_os = "macos")]
#[test]
fn a_self_connected_peer_reports_its_own_credential_as_consistent() {
    let (a, b) = std::os::unix::net::UnixStream::pair().expect("create a connected socket pair");
    let context = collect_peer_context(&a)
        .expect("LOCAL_PEERCRED/LOCAL_PEERPID must succeed on a live socket");
    drop(b); // keep the peer end alive until after derivation

    assert_eq!(context.credential().pid(), std::process::id());
    assert_eq!(context.consistency(), &PeerConsistency::Consistent);
    assert!(
        context.authorizable().is_some(),
        "a Consistent peer must be authorizable"
    );
    assert_eq!(context.observed().workload.pid, std::process::id());
}

#[cfg(target_os = "macos")]
#[test]
fn effective_uid_matches_the_process_real_uid() {
    let (a, b) = std::os::unix::net::UnixStream::pair().expect("create a connected socket pair");
    let context = collect_peer_context(&a)
        .expect("LOCAL_PEERCRED/LOCAL_PEERPID must succeed on a live socket");
    drop(b);

    // A non-setuid test process has real == effective uid, so
    // LOCAL_PEERCRED's effective uid must match what libproc reports as
    // this process's own real uid — exactly what the agent will
    // cross-check against a real client.
    let self_identity = eltanin_macos::collect_workload_identity(std::process::id());
    let real_uid = self_identity.uid.value().copied();
    assert_eq!(Some(context.credential().effective_uid()), real_uid);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn non_macos_build_reports_unsupported_platform() {
    let (a, _b) = std::os::unix::net::UnixStream::pair().expect("create a connected socket pair");
    assert_eq!(
        collect_peer_context(&a),
        Err(PeerCredentialError::UnsupportedPlatform)
    );
}
