//! In-memory + durable remembered-approval storage for one
//! [`crate::authz::AuthorizationHandler`] (F-M2-002, HORO-792).
//!
//! Mirrors `session_state.rs`'s/`state.rs`'s shape and locking
//! discipline exactly: held behind its own `Mutex`, recovered rather
//! than propagated on poison.
//!
//! `Remember`/`Deny` approvals are durable — held in an
//! [`eltanin_core::approval::ApprovalSet`], persisted to disk on every
//! mutation. `Once` approvals live only in `once`, this agent
//! instance's own memory, with a short TTL and are never written to
//! disk — see the module docs on `eltanin_core::approval` for why a
//! durable approval has no TTL at all while `Once` does.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use eltanin_core::approval::{
    Approval, ApprovalDisposition, ApprovalError, ApprovalId, ApprovalSet,
};
use eltanin_core::envelope::Versioned;
use eltanin_core::lease::MonotonicTime;
use eltanin_core::resource::{Action, ResourceIdentity};

/// Why loading/saving the durable approval store failed.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalStoreError {
    /// The store's parent directory (or the store file itself) is not
    /// safe to use: a symlink, not owned by this process, or
    /// group/other-writable. Same discriminants as
    /// `listener.rs::ensure_parent_directory_is_safe` — deliberately
    /// mirrored rather than reusing that function directly, since it is
    /// socket-specific (`bind`-then-`chmod` framing) where this is a
    /// plain-file read/write.
    #[error("{path:?} is not safe to use as the approval store: {reason}")]
    Unsafe { path: PathBuf, reason: String },
    #[error("approval store I/O error: {reason}")]
    Io { reason: String },
    #[error("approval store is not valid JSON: {reason}")]
    Json { reason: String },
    #[error(transparent)]
    Invalid(#[from] ApprovalError),
}

/// Owns the durable [`ApprovalSet`] plus every currently-live `Once`
/// approval for one agent instance.
pub(crate) struct ApprovalState {
    durable: ApprovalSet,
    once: HashMap<ApprovalId, (Approval, MonotonicTime)>,
}

impl ApprovalState {
    pub(crate) fn new() -> Self {
        Self {
            durable: ApprovalSet::new(),
            once: HashMap::new(),
        }
    }

    /// Load the durable store from `path`, validating that both `path`
    /// and its parent directory are safe to trust (not a symlink, owned
    /// by this process, not group/other-writable) before ever reading
    /// their contents — the on-disk bytes are evidence to re-validate,
    /// never bare authority (see `eltanin_core::approval`'s module
    /// docs), but this check still keeps an unrelated party from
    /// substituting an entirely different file at this path. A missing
    /// file is not an error — a fresh agent instance starts with an
    /// empty durable store.
    ///
    /// # Errors
    ///
    /// See [`ApprovalStoreError`].
    pub(crate) fn load(path: &Path) -> Result<Self, ApprovalStoreError> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        ensure_directory_is_safe(parent)?;

        match fs::symlink_metadata(path) {
            Ok(meta) => {
                ensure_file_metadata_is_safe(path, &meta)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Self::new());
            }
            Err(e) => {
                return Err(ApprovalStoreError::Io {
                    reason: format!("stat {}: {e}", path.display()),
                })
            }
        }

        let contents = fs::read_to_string(path).map_err(|e| ApprovalStoreError::Io {
            reason: format!("read {}: {e}", path.display()),
        })?;
        let envelope: Versioned<eltanin_core::approval::ApprovalDocument> =
            serde_json::from_str(&contents).map_err(|e| ApprovalStoreError::Json {
                reason: e.to_string(),
            })?;
        let durable = ApprovalSet::from_versioned(envelope)?;
        Ok(Self {
            durable,
            once: HashMap::new(),
        })
    }

    /// Persist the durable store to `path`. `Once` approvals are never
    /// included — see the module docs.
    ///
    /// # Errors
    ///
    /// See [`ApprovalStoreError`].
    pub(crate) fn save(&self, path: &Path) -> Result<(), ApprovalStoreError> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        ensure_directory_is_safe(parent)?;

        let document = self.durable.to_document();
        let json = serde_json::to_string_pretty(&Versioned::current(document)).map_err(|e| {
            ApprovalStoreError::Json {
                reason: e.to_string(),
            }
        })?;
        fs::write(path, json).map_err(|e| ApprovalStoreError::Io {
            reason: format!("write {}: {e}", path.display()),
        })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            ApprovalStoreError::Io {
                reason: format!("chmod {}: {e}", path.display()),
            }
        })
    }

    /// Insert a durable (`Remember`/`Deny`) approval. Callers are
    /// responsible for calling [`Self::save`] afterward — this method
    /// only mutates in-memory state, mirroring `SessionState::insert`'s
    /// own division of responsibility.
    pub(crate) fn insert_durable(&mut self, approval: Approval) {
        debug_assert!(!matches!(approval.disposition(), ApprovalDisposition::Once));
        self.durable.insert(approval);
    }

    /// Insert an ephemeral `Once` approval, valid until `expires_at`.
    /// Never persisted.
    pub(crate) fn insert_once(&mut self, approval: Approval, expires_at: MonotonicTime) {
        debug_assert!(matches!(approval.disposition(), ApprovalDisposition::Once));
        self.once
            .insert(approval.id().clone(), (approval, expires_at));
    }

    /// Drop every `Once` approval whose TTL has elapsed. Called at the
    /// top of every approval-touching operation, mirroring
    /// `SessionState::reap`'s lazy-reaping idiom.
    pub(crate) fn reap_once(&mut self, now: MonotonicTime) {
        self.once.retain(|_, (_, expires_at)| *expires_at > now);
    }

    /// Consume (remove) the `Once` approval identified by `id`, if any —
    /// called after a successful [`eltanin_core::approval::RecallVerdict::Matched`]
    /// use of it.
    pub(crate) fn consume_once(&mut self, id: &ApprovalId) {
        self.once.remove(id);
    }

    /// Every stored approval (durable or still-live `Once`) naming
    /// exactly `resource`/`action`, `Deny` dispositions ordered first —
    /// mirrors [`ApprovalSet::candidates`]'s own ordering contract,
    /// merged across both stores.
    pub(crate) fn candidates(&self, resource: &ResourceIdentity, action: Action) -> Vec<&Approval> {
        let mut matching: Vec<&Approval> = self.durable.candidates(resource, action).collect();
        matching.extend(
            self.once
                .values()
                .map(|(approval, _)| approval)
                .filter(|approval| approval.resource() == resource && approval.action() == action),
        );
        matching.sort_by_key(|a| !matches!(a.disposition(), ApprovalDisposition::Deny));
        matching
    }

    pub(crate) fn get(&self, id: &ApprovalId) -> Option<&Approval> {
        self.durable
            .get(id)
            .or_else(|| self.once.get(id).map(|(approval, _)| approval))
    }

    /// Remove the approval identified by `id` from whichever store holds
    /// it. Returns `true` if an entry was removed. Callers must persist
    /// afterward if the removed entry was durable — this method does
    /// not distinguish the two in its return value, matching
    /// `ForgetOutcome`'s own client-facing coarseness; the caller
    /// already knows which store it came from via [`Self::get`] before
    /// calling this.
    pub(crate) fn remove(&mut self, id: &ApprovalId) -> bool {
        let removed_once = self.once.remove(id).is_some();
        let removed_durable = self.durable.remove(id);
        removed_once || removed_durable
    }

    /// Every approval (durable or still-live `Once`) owned by `uid` —
    /// used by `eltanin approve list`, which must only ever return the
    /// calling peer's own approvals.
    pub(crate) fn owned_by(&self, uid: u32) -> Vec<&Approval> {
        let mut owned: Vec<&Approval> = self.durable.owned_by(uid).collect();
        owned.extend(
            self.once
                .values()
                .map(|(approval, _)| approval)
                .filter(|approval| approval.binding().owner_uid == uid),
        );
        owned
    }
}

fn ensure_directory_is_safe(dir: &Path) -> Result<(), ApprovalStoreError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => ensure_file_metadata_is_safe(dir, &meta),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(dir).map_err(|e| ApprovalStoreError::Io {
                reason: format!("create directory {}: {e}", dir.display()),
            })?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
                ApprovalStoreError::Io {
                    reason: format!("chmod directory {}: {e}", dir.display()),
                }
            })
        }
        Err(e) => Err(ApprovalStoreError::Io {
            reason: format!("stat {}: {e}", dir.display()),
        }),
    }
}

fn ensure_file_metadata_is_safe(
    path: &Path,
    meta: &fs::Metadata,
) -> Result<(), ApprovalStoreError> {
    if meta.file_type().is_symlink() {
        return Err(ApprovalStoreError::Unsafe {
            path: path.to_path_buf(),
            reason: "is a symlink".to_string(),
        });
    }
    if meta.mode() & 0o022 != 0 {
        return Err(ApprovalStoreError::Unsafe {
            path: path.to_path_buf(),
            reason: format!("is group/other-writable (mode {:o})", meta.mode() & 0o777),
        });
    }
    let own_euid = rustix::process::geteuid().as_raw();
    if meta.uid() != own_euid {
        return Err(ApprovalStoreError::Unsafe {
            path: path.to_path_buf(),
            reason: format!(
                "owned by uid {}, not this process's uid {own_euid}",
                meta.uid()
            ),
        });
    }
    Ok(())
}

/// Recover a poisoned lock rather than propagate the poison — identical
/// rationale to `state::lock`/`session_state::lock`.
pub(crate) fn lock(mutex: &Mutex<ApprovalState>) -> std::sync::MutexGuard<'_, ApprovalState> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
