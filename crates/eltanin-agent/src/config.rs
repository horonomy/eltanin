//! Agent configuration (F-M1-006, HORO-839).

use std::path::PathBuf;
use std::time::Duration;

/// Default socket path for a system-wide install. Not read from
/// anywhere automatically — a caller building [`AgentConfig`] chooses
/// it explicitly (or supplies its own path), consistent with this
/// crate's "no silent default for a security-relevant choice" stance
/// (see [`AgentConfig::new`]'s `socket_mode` parameter for the same
/// reasoning).
pub const DEFAULT_SOCKET_PATH: &str = "/run/eltanin/agent.sock";

/// Socket mode permitting any local user to connect. Connect permission
/// is **not** the authorization boundary — peer identity plus
/// default-deny policy is — so this mode is a reasonable default for a
/// single-tenant MVP 1.0 host where every local user is meant to be
/// able to request compute, not a security-critical hardening choice.
pub const MODE_ALL_LOCAL_USERS: u32 = 0o666;

/// Socket mode restricting connection to the socket's owner and group.
/// Choosing this mode when the agent runs as `root` means the group
/// must be a provisioned shared group — otherwise **no** unprivileged
/// client can connect at all, since group here means "root's group,"
/// not "any local user."
pub const MODE_OWNER_GROUP: u32 = 0o660;

const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_CONNECTIONS: usize = 64;
const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Configuration for one [`crate::server::AgentServer`] instance.
///
/// `socket_mode` has no default — it is a required constructor
/// parameter, mirroring `eltanin_core::lease::LeaseIssuer::new`'s
/// `max_ttl`: "short-lived is a bound this crate enforces, but the
/// actual number is a deployment decision," which applies identically
/// here to who may even attempt to connect.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    socket_path: PathBuf,
    socket_mode: u32,
    io_timeout: Duration,
    max_connections: usize,
    drain_timeout: Duration,
}

impl AgentConfig {
    #[must_use]
    pub fn new(socket_path: PathBuf, socket_mode: u32) -> Self {
        Self {
            socket_path,
            socket_mode,
            io_timeout: DEFAULT_IO_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        }
    }

    #[must_use]
    pub fn with_io_timeout(mut self, timeout: Duration) -> Self {
        self.io_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    #[must_use]
    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    #[must_use]
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    #[must_use]
    pub fn socket_mode(&self) -> u32 {
        self.socket_mode
    }

    #[must_use]
    pub fn io_timeout(&self) -> Duration {
        self.io_timeout
    }

    #[must_use]
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    #[must_use]
    pub fn drain_timeout(&self) -> Duration {
        self.drain_timeout
    }
}
