//! macOS adapter for `F-M1-010` (HORO-1013): derives `WorkloadIdentity`
//! and `ExecutionContext` from *observed* kernel process state for a
//! given PID, via `libproc`'s safe wrapper over `proc_pidinfo`/
//! `proc_pidpath` (both public, documented libproc.h APIs — no
//! Endpoint Security entitlement, no private/undocumented hook).
//!
//! Mirrors `crates/eltanin-linux`'s shape exactly: same public function
//! names, same "no caller override" contract, same non-macOS
//! `Unsupported` fallback.
//!
//! # Caller cannot override locally derivable fields
//!
//! Every collection entry point takes only a `pid: u32` — there is no
//! constructor, setter, or `From<CallerClaim>` anywhere in this crate
//! that accepts a caller-supplied `WorkloadIdentity` or
//! `ExecutionContext` value to merge or override. Every field is
//! derived exclusively from what the kernel reports for that PID at
//! collection time. This is not a convention to remember — it is not
//! expressible in this crate's public API.
//!
//! # Non-macOS builds
//!
//! On any `target_os` other than `macos`, every collection function
//! returns `Evidence::Unsupported` for every field rather than failing
//! to compile — so this crate builds and unit-tests on any development
//! machine, while `#[cfg(target_os = "macos")]` real collection code is
//! only compiled (and only exercised) on macOS, including this repo's
//! `macos-latest` CI runner.
//!
//! # Real vs. effective uid/gid
//!
//! [`collect_workload_identity`] reports `pbi_ruid`/`pbi_rgid` (the
//! **real** uid/gid) as `WorkloadIdentity::uid`/`::gid`, matching
//! `eltanin-linux`'s established semantics (its own
//! `read_status_id(pid, "Uid:").0`) — not `pbi_uid`/`pbi_gid` (the
//! **effective** pair), which [`peer::collect_peer_context`] instead
//! reconciles separately against the peer's kernel-reported effective
//! uid (see that module's docs and ADR 0008).
//!
//! # `ProcessStartToken` representation differs from Linux's
//!
//! Linux's `ProcessStartToken` wraps `/proc/<pid>/stat`'s `starttime`
//! field, in clock ticks since boot. This crate's token is derived from
//! `BSDInfo::pbi_start_tvsec`/`pbi_start_tvusec` (seconds and
//! microseconds since the Unix epoch, combined into one microsecond
//! count) — a different unit and a different epoch. `ProcessStartToken`
//! is documented (`eltanin_core::identity`) as an opaque value only
//! ever compared for equality *within one host's one collector*, so
//! this difference is harmless: no code anywhere in this workspace
//! compares a Linux-collected token against a macOS-collected one.

#![forbid(unsafe_code)]

use eltanin_core::identity::{Evidence, ExecutionContext, WorkloadIdentity};

pub mod peer;

/// Collect a [`WorkloadIdentity`] for `pid` from currently observed
/// process state. Never panics: any signal that cannot be read
/// (permission denied, the process has already exited, a malformed
/// kernel response) is reported as [`Evidence::Missing`] on that field,
/// never as a panic and never silently substituted with a default
/// value.
#[must_use]
pub fn collect_workload_identity(pid: u32) -> WorkloadIdentity {
    imp::collect_workload_identity(pid)
}

/// Collect the full [`ExecutionContext`] around `pid`, including its
/// [`WorkloadIdentity`].
#[must_use]
pub fn collect_execution_context(pid: u32) -> ExecutionContext {
    imp::collect_execution_context(pid)
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{Evidence, ExecutionContext, WorkloadIdentity};
    use eltanin_core::identity::{EvidenceSource, ProcessAncestor, ProcessStartToken};
    use libproc::bsd_info::BSDInfo;
    use libproc::proc_pid::{pidinfo, pidpath};

    /// Maximum ancestor hops walked before giving up. Bounds the work
    /// done against a corrupted or adversarially long ancestry chain,
    /// and guards against a cycle (which should never occur in a real
    /// process tree, but must never hang this collector if the kernel
    /// ever reports one) — same bound as `eltanin-linux`'s ancestry
    /// walk.
    const MAX_ANCESTRY_DEPTH: usize = 32;

    fn bsd_info(pid: u32) -> Result<BSDInfo, String> {
        let signed_pid = i32::try_from(pid).map_err(|e| format!("pid {pid} out of range: {e}"))?;
        pidinfo::<BSDInfo>(signed_pid, 0)
    }

    fn process_start(info: &BSDInfo) -> Evidence<ProcessStartToken> {
        // Combine seconds + microseconds since the Unix epoch into one
        // microsecond count. See this crate's module docs on why this
        // representation is not comparable to Linux's clock-tick token
        // — harmless, since nothing compares across collectors.
        let micros = u64::from(info.pbi_start_tvsec)
            .saturating_mul(1_000_000)
            .saturating_add(u64::from(info.pbi_start_tvusec));
        Evidence::Present {
            value: ProcessStartToken(micros),
            source: EvidenceSource::KernelObserved,
        }
    }

    fn executable_path(pid: u32) -> Evidence<String> {
        let signed_pid = match i32::try_from(pid) {
            Ok(p) => p,
            Err(e) => {
                return Evidence::Missing {
                    reason: format!("pid {pid} out of range: {e}"),
                }
            }
        };
        match pidpath(signed_pid) {
            Ok(path) => Evidence::Present {
                value: path,
                source: EvidenceSource::KernelObserved,
            },
            Err(e) => Evidence::Missing {
                reason: format!("proc_pidpath({pid}): {e}"),
            },
        }
    }

    /// Hashing the executable's full contents on every collection is
    /// expensive and, for a large binary, would make identity
    /// collection itself a resource-consumption vector. This collector
    /// deliberately does not implement it yet and reports that
    /// explicitly rather than silently returning an empty or
    /// placeholder hash — exact parity with `eltanin-linux`'s own
    /// stance (see its `executable_hash`).
    fn executable_hash(_pid: u32) -> Evidence<String> {
        Evidence::Missing {
            reason: "executable hashing not implemented by this collector".to_string(),
        }
    }

    /// Walk `start_pid`'s parent chain via repeated `libproc` lookups.
    ///
    /// Known scope gap, identical in shape to `eltanin-linux`'s: a
    /// lookup failure (permission denied on an ancestor owned by
    /// another uid is the realistic case for a non-root collector) is
    /// indistinguishable from genuinely reaching the top of the tree —
    /// both simply stop the walk. Ancestry is a contextual signal only,
    /// never an authorization basis (North Star invariant 4), which
    /// bounds the impact to a less useful audit trail, never a false
    /// authorization.
    fn ancestry(start_pid: u32) -> Vec<ProcessAncestor> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut current = start_pid;
        seen.insert(current);
        for _ in 0..MAX_ANCESTRY_DEPTH {
            let Ok(info) = bsd_info(current) else {
                break;
            };
            let parent = info.pbi_ppid;
            // pid 0 has no real parent; pid 1 is its own conventional
            // root — either terminates the walk, matching
            // eltanin-linux's identical rule.
            if parent == 0 || !seen.insert(parent) {
                break;
            }
            let parent_info = bsd_info(parent);
            out.push(ProcessAncestor {
                pid: parent,
                start: parent_info.as_ref().map_or_else(
                    |_| Evidence::Missing {
                        reason: format!("proc_pidinfo({parent}) failed while walking ancestry"),
                    },
                    process_start,
                ),
                executable_path: executable_path(parent),
            });
            current = parent;
        }
        out
    }

    pub(super) fn collect_workload_identity(pid: u32) -> WorkloadIdentity {
        match bsd_info(pid) {
            Ok(info) => WorkloadIdentity {
                pid,
                process_start: process_start(&info),
                uid: Evidence::Present {
                    value: info.pbi_ruid,
                    source: EvidenceSource::KernelObserved,
                },
                gid: Evidence::Present {
                    value: info.pbi_rgid,
                    source: EvidenceSource::KernelObserved,
                },
                executable_path: executable_path(pid),
                executable_hash: executable_hash(pid),
                ancestry: ancestry(pid),
            },
            Err(reason) => WorkloadIdentity {
                pid,
                process_start: Evidence::Missing {
                    reason: reason.clone(),
                },
                uid: Evidence::Missing {
                    reason: reason.clone(),
                },
                gid: Evidence::Missing {
                    reason: reason.clone(),
                },
                executable_path: executable_path(pid),
                executable_hash: executable_hash(pid),
                ancestry: Vec::new(),
            },
        }
    }

    pub(super) fn collect_execution_context(pid: u32) -> ExecutionContext {
        ExecutionContext {
            workload: collect_workload_identity(pid),
            // Darwin has no cgroups — this is a real "the mechanism
            // does not exist on this platform" case, so `Unsupported`
            // is the correct `Evidence` variant, not `Missing` (which
            // would imply a read was attempted and failed). Same
            // `Evidence`-contract distinction `eltanin-linux` already
            // draws elsewhere.
            cgroup_path: Evidence::Unsupported,
            // Namespace/container/session hints require correlating
            // multiple additional signals this collector does not
            // implement — exact parity with `eltanin-linux`, which
            // reports the same three fields `Unsupported` for the same
            // reason (no partial heuristic reported as if it were
            // complete).
            namespace_hint: Evidence::Unsupported,
            container_hint: Evidence::Unsupported,
            session_origin: Evidence::Unsupported,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn collects_own_workload_identity_with_kernel_observed_evidence() {
            let identity = collect_workload_identity(std::process::id());
            assert!(identity.process_start.is_present());
            assert!(identity.uid.is_present());
            assert!(identity.executable_path.is_present());
            // Deliberately not implemented yet (see `executable_hash`)
            // — must stay explicit `Missing`, never silently `Present`.
            assert!(!identity.executable_hash.is_present());
        }

        #[test]
        fn collects_own_execution_context_with_unsupported_cgroup_path() {
            let ctx = collect_execution_context(std::process::id());
            assert!(matches!(ctx.cgroup_path, Evidence::Unsupported));
            assert!(matches!(ctx.namespace_hint, Evidence::Unsupported));
            assert!(matches!(ctx.container_hint, Evidence::Unsupported));
            assert!(matches!(ctx.session_origin, Evidence::Unsupported));
        }

        #[test]
        fn nonexistent_pid_reports_explicit_missing_not_panic() {
            let identity = collect_workload_identity(u32::MAX);
            assert!(!identity.process_start.is_present());
            assert!(matches!(identity.process_start, Evidence::Missing { .. }));
        }

        #[test]
        fn ancestry_walk_terminates_and_does_not_include_self() {
            let chain = ancestry(std::process::id());
            assert!(chain.len() <= MAX_ANCESTRY_DEPTH);
            assert!(!chain.iter().any(|a| a.pid == std::process::id()));
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::{Evidence, ExecutionContext, WorkloadIdentity};

    pub(super) fn collect_workload_identity(pid: u32) -> WorkloadIdentity {
        WorkloadIdentity {
            pid,
            process_start: Evidence::Unsupported,
            uid: Evidence::Unsupported,
            gid: Evidence::Unsupported,
            executable_path: Evidence::Unsupported,
            executable_hash: Evidence::Unsupported,
            ancestry: Vec::new(),
        }
    }

    pub(super) fn collect_execution_context(pid: u32) -> ExecutionContext {
        ExecutionContext {
            workload: collect_workload_identity(pid),
            cgroup_path: Evidence::Unsupported,
            namespace_hint: Evidence::Unsupported,
            container_hint: Evidence::Unsupported,
            session_origin: Evidence::Unsupported,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn non_macos_build_reports_unsupported_not_a_guess() {
            let identity = collect_workload_identity(std::process::id());
            assert!(matches!(identity.process_start, Evidence::Unsupported));
            assert!(identity.ancestry.is_empty());
            let ctx = collect_execution_context(std::process::id());
            assert!(matches!(ctx.cgroup_path, Evidence::Unsupported));
        }
    }
}
