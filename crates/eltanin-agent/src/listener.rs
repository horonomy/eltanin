//! Socket bind/cleanup lifecycle (F-M1-006, HORO-839).
//!
//! [`BoundSocket::bind`] is the entire startup sequence a caller needs:
//! validate the parent directory, discriminate a stale socket file from
//! a live agent, bind, and set the final mode — in that order, each
//! step closing a specific attack rather than trusting the previous
//! step's absence of an error.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use crate::config::AgentConfig;

/// Why [`BoundSocket::bind`] could not establish the socket.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// The socket's parent directory is not safe to bind into: it is a
    /// symlink, not a directory, not owned by this process, or writable
    /// by a group/other principal. Binding anyway would let an
    /// unrelated party redirect or race the socket path.
    #[error("parent directory {path:?} is not safe to bind into: {reason}")]
    ParentDirectoryUnsafe { path: PathBuf, reason: String },
    /// A connect probe to the existing socket path succeeded — a live
    /// agent is already listening there. This path is never unlinked:
    /// doing so on a mere restart race would hijack a running agent's
    /// socket out from under it.
    #[error("a live agent is already listening on {path:?}")]
    SocketInUse { path: PathBuf },
    /// Something exists at the socket path that is not a socket at all
    /// (a regular file, directory, or symlink). Never unlinked
    /// automatically — an operator must resolve this by hand.
    #[error("{path:?} exists and is not a socket")]
    StaleSocketPathNotASocket { path: PathBuf },
    #[error("socket startup I/O error: {reason}")]
    Io { reason: String },
}

/// An owned, listening Unix Domain Socket. Removes its socket path on
/// [`Drop`], so a normally-exiting agent never leaves a stale file
/// behind for the next start to have to recover from.
#[derive(Debug)]
pub struct BoundSocket {
    listener: UnixListener,
    path: PathBuf,
}

impl BoundSocket {
    /// Establish the socket described by `config`. See the module docs
    /// for the exact ordering.
    ///
    /// # Errors
    ///
    /// See [`StartupError`]'s variants.
    pub fn bind(config: &AgentConfig) -> Result<Self, StartupError> {
        let path = config.socket_path().to_path_buf();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        ensure_parent_directory_is_safe(parent)?;

        let listener = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                recover_stale_socket(&path)?;
                UnixListener::bind(&path).map_err(|e| StartupError::Io {
                    reason: format!("bind {} after stale-socket recovery: {e}", path.display()),
                })?
            }
            Err(e) => {
                return Err(StartupError::Io {
                    reason: format!("bind {}: {e}", path.display()),
                })
            }
        };

        fs::set_permissions(&path, fs::Permissions::from_mode(config.socket_mode())).map_err(
            |e| StartupError::Io {
                reason: format!("chmod {}: {e}", path.display()),
            },
        )?;

        Ok(Self { listener, path })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn ensure_parent_directory_is_safe(parent: &Path) -> Result<(), StartupError> {
    match fs::symlink_metadata(parent) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(StartupError::ParentDirectoryUnsafe {
                    path: parent.to_path_buf(),
                    reason: "is a symlink".into(),
                });
            }
            if !meta.is_dir() {
                return Err(StartupError::ParentDirectoryUnsafe {
                    path: parent.to_path_buf(),
                    reason: "is not a directory".into(),
                });
            }
            if meta.mode() & 0o022 != 0 {
                return Err(StartupError::ParentDirectoryUnsafe {
                    path: parent.to_path_buf(),
                    reason: format!("is group/other-writable (mode {:o})", meta.mode() & 0o777),
                });
            }
            let own_euid = self_euid();
            if meta.uid() != own_euid {
                return Err(StartupError::ParentDirectoryUnsafe {
                    path: parent.to_path_buf(),
                    reason: format!(
                        "owned by uid {}, not this process's uid {own_euid}",
                        meta.uid()
                    ),
                });
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Created private (0o700) so the bind-then-chmod window on
            // the socket file itself is never reachable through a
            // wider-than-intended parent directory.
            fs::create_dir_all(parent).map_err(|e| StartupError::Io {
                reason: format!("create parent directory {}: {e}", parent.display()),
            })?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|e| {
                StartupError::Io {
                    reason: format!("chmod parent directory {}: {e}", parent.display()),
                }
            })
        }
        Err(e) => Err(StartupError::Io {
            reason: format!("stat parent directory {}: {e}", parent.display()),
        }),
    }
}

/// Distinguishes a socket file left behind by a crashed/killed agent
/// (safe to remove and rebind) from one a live agent is still listening
/// on (must never be touched). A connect probe is the only reliable
/// discriminator on Unix — the file existing tells you nothing about
/// whether anything is on the other end.
fn recover_stale_socket(path: &Path) -> Result<(), StartupError> {
    let meta = fs::symlink_metadata(path).map_err(|e| StartupError::Io {
        reason: format!("stat {}: {e}", path.display()),
    })?;
    if meta.file_type().is_symlink() || !is_socket(&meta) {
        return Err(StartupError::StaleSocketPathNotASocket {
            path: path.to_path_buf(),
        });
    }
    match UnixStream::connect(path) {
        Ok(_live) => Err(StartupError::SocketInUse {
            path: path.to_path_buf(),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => fs::remove_file(path)
            .map_err(|e| StartupError::Io {
                reason: format!("remove stale socket {}: {e}", path.display()),
            }),
        Err(e) => Err(StartupError::Io {
            reason: format!("probe {}: {e}", path.display()),
        }),
    }
}

#[cfg(unix)]
fn is_socket(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    meta.file_type().is_socket()
}

#[cfg(unix)]
fn self_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}
