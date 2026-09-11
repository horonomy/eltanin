//! Socket bind/cleanup lifecycle coverage (F-M1-006, HORO-839).

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;

use eltanin_agent::config::{AgentConfig, MODE_ALL_LOCAL_USERS};
use eltanin_agent::listener::{BoundSocket, StartupError};
use support::temp_socket_path;

#[test]
fn bind_creates_a_socket_with_the_configured_mode() {
    let path = temp_socket_path("bind-mode");
    let config = AgentConfig::new(path.clone(), MODE_ALL_LOCAL_USERS);
    let socket = BoundSocket::bind(&config).expect("bind must succeed on a fresh path");

    assert_eq!(socket.path(), path);
    let mode = fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, MODE_ALL_LOCAL_USERS);
}

#[test]
fn drop_removes_the_socket_path() {
    let path = temp_socket_path("drop-cleanup");
    let config = AgentConfig::new(path.clone(), MODE_ALL_LOCAL_USERS);
    let socket = BoundSocket::bind(&config).unwrap();
    drop(socket);

    assert!(
        fs::symlink_metadata(&path).is_err(),
        "socket path must be gone after Drop"
    );
}

#[test]
fn a_clean_restart_can_rebind_the_same_path() {
    let path = temp_socket_path("clean-restart");
    let config = AgentConfig::new(path.clone(), MODE_ALL_LOCAL_USERS);
    drop(BoundSocket::bind(&config).unwrap());

    let second = BoundSocket::bind(&config);
    assert!(
        second.is_ok(),
        "rebinding after a clean shutdown must succeed, got {second:?}"
    );
}

#[test]
fn a_stale_socket_file_is_recovered_and_rebindable() {
    let path = temp_socket_path("stale-recovery");

    // Simulate a crashed agent without BoundSocket at all: a plain
    // UnixListener's Drop closes the fd (stops listening) but — unlike
    // BoundSocket — does not unlink the bound path, leaving exactly the
    // file-exists-but-nothing-listening state a crash produces.
    {
        let _leaked_file_no_listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    }
    assert!(
        fs::symlink_metadata(&path).is_ok(),
        "precondition: file exists"
    );

    let config = AgentConfig::new(path, MODE_ALL_LOCAL_USERS);
    let recovered = BoundSocket::bind(&config);
    assert!(
        recovered.is_ok(),
        "a stale (unconnectable) socket file must be recovered, got {recovered:?}"
    );
}

#[test]
fn a_live_agent_socket_is_never_unlinked() {
    let path = temp_socket_path("live-refusal");
    let config = AgentConfig::new(path.clone(), MODE_ALL_LOCAL_USERS);
    let live = BoundSocket::bind(&config).expect("first bind must succeed");

    let second = BoundSocket::bind(&config);
    assert!(
        matches!(second, Err(StartupError::SocketInUse { .. })),
        "expected SocketInUse while a live agent holds the socket, got {second:?}"
    );

    // The live agent's socket must still be connectable — the second
    // bind attempt must not have touched it.
    assert!(UnixStream::connect(&path).is_ok());
    drop(live);
}

#[test]
fn a_non_socket_file_at_the_path_is_refused_and_left_untouched() {
    let path = temp_socket_path("non-socket");
    fs::write(&path, b"not a socket").unwrap();

    let config = AgentConfig::new(path.clone(), MODE_ALL_LOCAL_USERS);
    let result = BoundSocket::bind(&config);
    assert!(
        matches!(result, Err(StartupError::StaleSocketPathNotASocket { .. })),
        "expected StaleSocketPathNotASocket, got {result:?}"
    );
    assert_eq!(
        fs::read(&path).unwrap(),
        b"not a socket",
        "a non-socket file must never be removed automatically"
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn a_group_writable_parent_directory_is_refused() {
    let base = temp_socket_path("bad-parent-dir");
    let dir = base.with_extension("dir");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();

    let socket_path = dir.join("agent.sock");
    let config = AgentConfig::new(socket_path, MODE_ALL_LOCAL_USERS);
    let result = BoundSocket::bind(&config);
    assert!(
        matches!(result, Err(StartupError::ParentDirectoryUnsafe { .. })),
        "expected ParentDirectoryUnsafe for a 0o777 parent, got {result:?}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_symlinked_parent_directory_is_refused() {
    let base = temp_socket_path("bad-parent-symlink");
    let real_dir = base.with_extension("realdir");
    let link_dir = base.with_extension("linkdir");
    fs::create_dir_all(&real_dir).unwrap();
    fs::set_permissions(&real_dir, fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

    let socket_path = link_dir.join("agent.sock");
    let config = AgentConfig::new(socket_path, MODE_ALL_LOCAL_USERS);
    let result = BoundSocket::bind(&config);
    assert!(
        matches!(result, Err(StartupError::ParentDirectoryUnsafe { .. })),
        "expected ParentDirectoryUnsafe for a symlinked parent, got {result:?}"
    );

    let _ = fs::remove_file(&link_dir);
    let _ = fs::remove_dir_all(&real_dir);
}

#[test]
fn a_missing_parent_directory_is_created_privately() {
    let base = temp_socket_path("missing-parent");
    let dir = base.with_extension("newdir");
    let _ = fs::remove_dir_all(&dir);
    assert!(
        fs::symlink_metadata(&dir).is_err(),
        "precondition: dir absent"
    );

    let socket_path = dir.join("agent.sock");
    let config = AgentConfig::new(socket_path, MODE_ALL_LOCAL_USERS);
    let socket = BoundSocket::bind(&config).expect("bind must create the parent directory");
    drop(socket);

    let mode = fs::symlink_metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o700,
        "a freshly created parent directory must be private"
    );
    let _ = fs::remove_dir_all(&dir);
}
