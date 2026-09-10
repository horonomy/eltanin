//! Linux adapter for `F-M1-003` (HORO-832): derives [`WorkloadIdentity`]
//! and [`ExecutionContext`] from *observed* `/proc` state for a given
//! PID.
//!
//! # Caller cannot override locally derivable fields
//!
//! Every collection entry point takes only a `pid: u32` — there is no
//! constructor, setter, or `From<CallerClaim>` anywhere in this crate
//! that accepts a caller-supplied [`WorkloadIdentity`] or
//! [`ExecutionContext`] value to merge or override. Every field is
//! derived exclusively from what the kernel reports for that PID at
//! collection time. This is not a convention to remember — it is not
//! expressible in this crate's public API.
//!
//! # Non-Linux builds
//!
//! On any `target_os` other than `linux`, every collection function
//! returns [`Evidence::Unsupported`] for every field rather than failing
//! to compile — so this crate builds and unit-tests on any development
//! machine, while `#[cfg(target_os = "linux")]` real collection code is
//! only compiled (and only exercised) on Linux, including this repo's
//! `ubuntu-latest` CI runner.

#![forbid(unsafe_code)]

use eltanin_core::identity::{Evidence, ExecutionContext, WorkloadIdentity};

/// Collect a [`WorkloadIdentity`] for `pid` from currently observed
/// process state. Never panics: any signal that cannot be read (permission
/// denied, the process has already exited, malformed `/proc` content) is
/// reported as [`Evidence::Missing`] on that field, never as a panic and
/// never silently substituted with a default value.
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

#[cfg(target_os = "linux")]
mod imp {
    use super::{Evidence, ExecutionContext, WorkloadIdentity};
    use eltanin_core::identity::{EvidenceSource, ProcessAncestor, ProcessStartToken};
    use std::fs;

    /// Maximum ancestor hops walked before giving up. Bounds the work
    /// done against a corrupted or adversarially long `/proc` parent
    /// chain, and guards against a cycle (which should never occur in a
    /// real process tree, but must never hang this collector if `/proc`
    /// ever reports one).
    const MAX_ANCESTRY_DEPTH: usize = 32;

    /// Parsed fields from `/proc/<pid>/stat` that this collector needs.
    struct StatFields {
        ppid: u32,
        starttime: u64,
    }

    /// Parse `/proc/<pid>/stat`. The `comm` field (2nd field) is
    /// attacker-controlled process-supplied text and may itself contain
    /// spaces and parentheses, so the line is split on the **last**
    /// `')'` rather than tokenized by whitespace from the start — the
    /// classic bug in naive `/proc/stat` parsers. Everything after that
    /// last `)` is fixed-format, whitespace-separated numeric fields
    /// starting at field 3 (`state`).
    fn parse_stat(observed_pid: u32) -> Result<StatFields, String> {
        let raw = fs::read_to_string(format!("/proc/{observed_pid}/stat"))
            .map_err(|e| format!("read /proc/{observed_pid}/stat: {e}"))?;
        let after_comm = raw
            .rsplit_once(')')
            .map(|(_, rest)| rest)
            .ok_or_else(|| format!("/proc/{observed_pid}/stat missing ')': {raw:?}"))?;
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        // `fields[0]` is field 3 (state); field N is therefore `fields[N - 3]`.
        let parent = fields
            .get(4 - 3)
            .ok_or_else(|| "missing ppid field".to_string())?
            .parse::<u32>()
            .map_err(|e| format!("parse ppid: {e}"))?;
        let starttime = fields
            .get(22 - 3)
            .ok_or_else(|| "missing starttime field".to_string())?
            .parse::<u64>()
            .map_err(|e| format!("parse starttime: {e}"))?;
        Ok(StatFields {
            ppid: parent,
            starttime,
        })
    }

    fn process_start(pid: u32) -> Evidence<ProcessStartToken> {
        match parse_stat(pid) {
            Ok(stat) => Evidence::Present {
                value: ProcessStartToken(stat.starttime),
                source: EvidenceSource::KernelObserved,
            },
            Err(reason) => Evidence::Missing { reason },
        }
    }

    fn parent_pid(pid: u32) -> Option<u32> {
        parse_stat(pid).ok().map(|s| s.ppid)
    }

    /// Read the first (`real`) uid/gid from `/proc/<pid>/status`'s `Uid:`
    /// / `Gid:` line (`Uid:\treal\teffective\tsaved\tfs`).
    fn read_status_id(pid: u32, label: &str) -> Evidence<u32> {
        let raw = match fs::read_to_string(format!("/proc/{pid}/status")) {
            Ok(raw) => raw,
            Err(e) => {
                return Evidence::Missing {
                    reason: format!("read /proc/{pid}/status: {e}"),
                }
            }
        };
        let Some(line) = raw.lines().find(|l| l.starts_with(label)) else {
            return Evidence::Missing {
                reason: format!("no {label} line in /proc/{pid}/status"),
            };
        };
        let Some(real) = line.split_whitespace().nth(1) else {
            return Evidence::Missing {
                reason: format!("{label} line has no value: {line:?}"),
            };
        };
        match real.parse::<u32>() {
            Ok(value) => Evidence::Present {
                value,
                source: EvidenceSource::KernelObserved,
            },
            Err(e) => Evidence::Missing {
                reason: format!("parse {label}: {e}"),
            },
        }
    }

    fn executable_path(pid: u32) -> Evidence<String> {
        match fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(path) => Evidence::Present {
                value: path.to_string_lossy().into_owned(),
                source: EvidenceSource::KernelObserved,
            },
            Err(e) => Evidence::Missing {
                reason: format!("readlink /proc/{pid}/exe: {e}"),
            },
        }
    }

    /// Hashing the executable's full contents on every collection is
    /// expensive and, for a large binary, would make identity collection
    /// itself a resource-consumption vector. This collector deliberately
    /// does not implement it yet and reports that explicitly rather than
    /// silently returning an empty or placeholder hash — consistent with
    /// this module's "no default/fallback state" rule (see
    /// `eltanin_core::identity::Evidence`).
    fn executable_hash(_pid: u32) -> Evidence<String> {
        Evidence::Missing {
            reason: "executable hashing not implemented by this collector".to_string(),
        }
    }

    /// Walk `start_pid`'s parent chain via repeated `/proc/<pid>/stat`
    /// reads.
    ///
    /// Known scope gap: `parent_pid` discards *why* a read failed
    /// (permission denied on an ancestor owned by another UID is the
    /// realistic case for a non-root collector walking toward PID 1) and
    /// this loop simply stops there. The returned `Vec<ProcessAncestor>`
    /// therefore cannot be distinguished from "genuinely reached the top
    /// of the tree" by its length alone. `ProcessAncestor`/
    /// `ExecutionContext` (`eltanin_core::identity`) have no field to
    /// carry "ancestry walk stopped early: evidence unavailable" —
    /// closing this gap needs a contract change in `eltanin-core`, out
    /// of scope for this collector-only ticket (HORO-832). Ancestry is a
    /// contextual signal only, never an authorization basis (North Star
    /// invariant 4), which bounds the impact: a short ancestor list can
    /// never be *upgraded* into a false-negative security decision, only
    /// into a less useful audit trail. Tracked for a follow-up rather
    /// than fixed silently here.
    fn ancestry(start_pid: u32) -> Vec<ProcessAncestor> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut current = start_pid;
        seen.insert(current);
        for _ in 0..MAX_ANCESTRY_DEPTH {
            let Some(parent) = parent_pid(current) else {
                break;
            };
            // PID 0 has no real parent; PID 1 (or a namespace's PID 1) is
            // its own conventional root — either terminates the walk.
            if parent == 0 || !seen.insert(parent) {
                break;
            }
            out.push(ProcessAncestor {
                pid: parent,
                start: process_start(parent),
                executable_path: executable_path(parent),
            });
            current = parent;
        }
        out
    }

    /// `/proc/<pid>/cgroup` line format is `hierarchy-id:controllers:path`.
    /// On a cgroup v2 (unified) host, the only line is `0::<path>`; on a
    /// v1 host there are multiple lines. This collector reports the
    /// **last** line's path, which is the cgroup v2 unified path when
    /// present and otherwise the last-listed v1 hierarchy — a reasonable,
    /// documented choice rather than an unstated one.
    fn cgroup_path(pid: u32) -> Evidence<String> {
        let raw = match fs::read_to_string(format!("/proc/{pid}/cgroup")) {
            Ok(raw) => raw,
            Err(e) => {
                return Evidence::Missing {
                    reason: format!("read /proc/{pid}/cgroup: {e}"),
                }
            }
        };
        let Some(last) = raw.lines().last() else {
            return Evidence::Missing {
                reason: format!("/proc/{pid}/cgroup is empty"),
            };
        };
        match last.splitn(3, ':').nth(2) {
            Some(path) => Evidence::Present {
                value: path.to_string(),
                source: EvidenceSource::KernelObserved,
            },
            None => Evidence::Missing {
                reason: format!("malformed /proc/{pid}/cgroup line: {last:?}"),
            },
        }
    }

    pub(super) fn collect_workload_identity(pid: u32) -> WorkloadIdentity {
        WorkloadIdentity {
            pid,
            process_start: process_start(pid),
            uid: read_status_id(pid, "Uid:"),
            gid: read_status_id(pid, "Gid:"),
            executable_path: executable_path(pid),
            executable_hash: executable_hash(pid),
            ancestry: ancestry(pid),
        }
    }

    pub(super) fn collect_execution_context(pid: u32) -> ExecutionContext {
        ExecutionContext {
            workload: collect_workload_identity(pid),
            cgroup_path: cgroup_path(pid),
            // Namespace/container/session hints require correlating
            // multiple additional signals (e.g. `/proc/<pid>/ns/*`
            // inode comparison against this process's own namespace,
            // container-runtime-specific cgroup path heuristics,
            // controlling-terminal/session leader lookups). None of
            // those are implemented by this collector yet; reporting
            // `Unsupported` here is honest about that rather than
            // guessing from a partial heuristic.
            namespace_hint: Evidence::Unsupported,
            container_hint: Evidence::Unsupported,
            session_origin: Evidence::Unsupported,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_own_stat_starttime_and_ppid() {
            let pid = std::process::id();
            let stat = parse_stat(pid).expect("own /proc/self equivalent must be readable");
            // A live test process always has a nonzero starttime and a
            // real (nonzero, since we're not PID 1) parent.
            assert!(stat.starttime > 0);
            assert!(stat.ppid > 0);
        }

        #[test]
        fn comm_field_containing_parens_and_spaces_does_not_desync_fields() {
            // Simulates a process named literally `1 (evil) proc)` —
            // exercises the "split on the *last* `)`" parsing rule
            // rather than the real kernel, since renaming this test
            // binary's own comm is not practical from a unit test.
            let synthetic = "999 (1 (evil) proc)) S 111 222 333 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 123456 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
            let after_comm = synthetic.rsplit_once(')').unwrap().1;
            let fields: Vec<&str> = after_comm.split_whitespace().collect();
            // field3 (state) = "S" at fields[0]; field4 (ppid) = "111" at
            // fields[4-3]; field5 (pgrp) = "222"; field6 (session) =
            // "333" — three distinct values so a field-alignment bug
            // cannot coincidentally pass by comparing equal placeholders.
            assert_eq!(fields[4 - 3], "111", "ppid field misaligned");
            assert_eq!(fields[22 - 3], "123456", "starttime field misaligned");
        }

        #[test]
        fn collects_own_workload_identity_with_kernel_observed_evidence() {
            let identity = collect_workload_identity(std::process::id());
            assert!(identity.process_start.is_present());
            assert!(identity.uid.is_present());
            assert!(identity.executable_path.is_present());
            // Deliberately not implemented yet (see `executable_hash`) —
            // must stay explicit `Missing`, never silently `Present`.
            assert!(!identity.executable_hash.is_present());
        }

        #[test]
        fn collects_own_execution_context_cgroup_path() {
            let ctx = collect_execution_context(std::process::id());
            // Every Linux CI/container host has a `/proc/self/cgroup`
            // for the running test process, so this must be `Present`,
            // not merely "not a panic" — a weaker assertion here would
            // pass even if `cgroup_path()` always returned `Missing`.
            let Evidence::Present { value, .. } = &ctx.cgroup_path else {
                panic!("expected a present cgroup path, got {:?}", ctx.cgroup_path);
            };
            assert!(
                value.starts_with('/'),
                "cgroup path should be absolute: {value:?}"
            );
        }

        #[test]
        fn nonexistent_pid_reports_explicit_missing_not_panic() {
            // PID 1 always exists on Linux; a very large PID almost
            // certainly does not. This must never panic.
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

#[cfg(not(target_os = "linux"))]
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
        fn non_linux_build_reports_unsupported_not_a_guess() {
            let identity = collect_workload_identity(std::process::id());
            assert!(matches!(identity.process_start, Evidence::Unsupported));
            assert!(identity.ancestry.is_empty());
            let ctx = collect_execution_context(std::process::id());
            assert!(matches!(ctx.cgroup_path, Evidence::Unsupported));
        }
    }
}
