//! Shutdown determinism coverage (F-M1-006, HORO-839): a
//! [`ShutdownHandle`] must actually stop the accept loop, the socket
//! path must be gone afterward, and the path must be immediately
//! rebindable.

mod support;

use std::sync::Arc;
use std::time::Duration;

use eltanin_agent::config::AgentConfig;
use eltanin_agent::handler::StatusOnlyHandler;
use eltanin_agent::listener::BoundSocket;
use eltanin_agent::peer::LinuxPeerContextSource;
use eltanin_agent::server::AgentServer;
use support::temp_socket_path;

#[test]
fn shutdown_stops_the_accept_loop_and_cleans_up_the_socket() {
    let path = temp_socket_path("shutdown-cleanup");
    let config = AgentConfig::new(path.clone(), 0o600);
    let socket = BoundSocket::bind(&config).unwrap();
    let server = AgentServer::new(
        socket,
        config,
        Arc::new(StatusOnlyHandler),
        Arc::new(LinuxPeerContextSource),
    );
    let shutdown = server.shutdown_handle();

    let server_thread = std::thread::spawn(move || server.run());

    // Give the accept loop a moment to actually start blocking in
    // accept() before asking it to stop.
    std::thread::sleep(Duration::from_millis(100));
    shutdown.shutdown();

    let report = server_thread
        .join()
        .expect("server thread must not panic")
        .expect("run() must return Ok");
    assert_eq!(report.abandoned, 0, "no connections were ever opened");

    assert!(
        std::fs::symlink_metadata(&path).is_err(),
        "socket path must be removed after shutdown"
    );
}

#[test]
fn the_socket_path_is_rebindable_immediately_after_shutdown() {
    let path = temp_socket_path("shutdown-rebind");
    let config = AgentConfig::new(path.clone(), 0o600);
    let socket = BoundSocket::bind(&config).unwrap();
    let server = AgentServer::new(
        socket,
        config,
        Arc::new(StatusOnlyHandler),
        Arc::new(LinuxPeerContextSource),
    );
    let shutdown = server.shutdown_handle();
    let server_thread = std::thread::spawn(move || server.run());

    std::thread::sleep(Duration::from_millis(100));
    shutdown.shutdown();
    server_thread.join().unwrap().unwrap();

    let rebind_config = AgentConfig::new(path, 0o600);
    assert!(
        BoundSocket::bind(&rebind_config).is_ok(),
        "the path must be immediately rebindable after a clean shutdown"
    );
}

#[test]
fn shutdown_can_be_called_multiple_times_without_panicking() {
    let path = temp_socket_path("shutdown-idempotent");
    let config = AgentConfig::new(path.clone(), 0o600);
    let socket = BoundSocket::bind(&config).unwrap();
    let server = AgentServer::new(
        socket,
        config,
        Arc::new(StatusOnlyHandler),
        Arc::new(LinuxPeerContextSource),
    );
    let shutdown = server.shutdown_handle();
    let server_thread = std::thread::spawn(move || server.run());

    std::thread::sleep(Duration::from_millis(100));
    shutdown.shutdown();
    shutdown.shutdown();
    shutdown.shutdown();

    server_thread.join().unwrap().unwrap();
}
