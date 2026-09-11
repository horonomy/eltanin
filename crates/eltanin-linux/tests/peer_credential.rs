//! Peer credential derivation coverage (F-M1-006, HORO-839). Real
//! `SO_PEERCRED` behavior only meaningfully validates on Linux (this
//! repo's `ubuntu-latest` CI); on any other `target_os` the documented
//! `UnsupportedPlatform` fallback is what's validated instead, so this
//! test still compiles and passes on a macOS dev machine — same pattern
//! as `linux_integration.rs`.

use eltanin_linux::peer::collect_peer_context;
#[cfg(target_os = "linux")]
use eltanin_linux::peer::PeerConsistency;
#[cfg(not(target_os = "linux"))]
use eltanin_linux::peer::PeerCredentialError;

#[cfg(target_os = "linux")]
#[test]
fn a_self_connected_peer_reports_its_own_credential_as_consistent() {
    let (a, b) = std::os::unix::net::UnixStream::pair().expect("create a connected socket pair");
    let context = collect_peer_context(&a).expect("SO_PEERCRED must succeed on a live socket");
    drop(b); // keep the peer end alive until after derivation

    assert_eq!(context.credential().pid(), std::process::id());
    assert_eq!(context.consistency(), &PeerConsistency::Consistent);
    assert!(
        context.authorizable().is_some(),
        "a Consistent peer must be authorizable"
    );
    assert_eq!(context.observed().workload.pid, std::process::id());
}

#[cfg(target_os = "linux")]
#[test]
fn effective_uid_matches_the_process_euid() {
    let (a, b) = std::os::unix::net::UnixStream::pair().expect("create a connected socket pair");
    let context = collect_peer_context(&a).expect("SO_PEERCRED must succeed on a live socket");
    drop(b);

    // rustix has no portable "get own euid" without pulling in the
    // process feature; compare against the uid this process's own
    // /proc/<pid>/status reports for itself instead, which is exactly
    // what the agent will cross-check against a real client.
    let self_identity = eltanin_linux::collect_workload_identity(std::process::id());
    let real_uid = self_identity.uid.value().copied();
    assert_eq!(Some(context.credential().effective_uid()), real_uid);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_build_reports_unsupported_platform() {
    let (a, _b) = std::os::unix::net::UnixStream::pair().expect("create a connected socket pair");
    assert_eq!(
        collect_peer_context(&a),
        Err(PeerCredentialError::UnsupportedPlatform)
    );
}
