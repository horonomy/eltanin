//! Workload identity and execution context (F-M1-003, HORO-831).
//!
//! Every field states its own trust source explicitly — there is no
//! implicit "this identity is trusted" flag anywhere in this module, and
//! no field's mere presence implies authorization. See North Star
//! invariant 4 (contextual signals are not authority) and
//! `docs/product/SECURITY_MODEL.md`.

use serde::{Deserialize, Serialize};

/// How a piece of workload evidence was obtained. Ordered roughly from
/// most to least trustworthy — but **any** of these are signals for
/// policy to weigh, never unconditional proof of authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    /// Read from a kernel mechanism the observed process cannot spoof by
    /// making claims about itself (e.g. Unix-socket peer credentials,
    /// `/proc/<pid>/stat`'s numeric fields).
    KernelObserved,
    /// A best-effort read of process state that the *caller* of this API
    /// cannot forge, but which could reflect a narrow TOCTOU race against
    /// a fast-changing process (e.g. `/proc/<pid>/cmdline` read just
    /// before the process re-execs).
    BestEffort,
    /// Provided by the process/session itself with no independent check.
    /// Never treated as an authorization basis by policy.
    SelfAsserted,
}

/// One piece of evidence: present with provenance, explicitly missing,
/// or explicitly unsupported. There is no default/fallback state — a
/// caller must always handle all three, so missing evidence can never be
/// silently treated as present-and-trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum Evidence<T> {
    Present {
        value: T,
        source: EvidenceSource,
    },
    /// The signal could not be collected this time (e.g. permission
    /// denied reading `/proc`, the process exited mid-read).
    Missing {
        reason: String,
    },
    /// This platform/build does not implement collecting this signal at
    /// all.
    Unsupported,
}

impl<T> Evidence<T> {
    #[must_use]
    pub fn is_present(&self) -> bool {
        matches!(self, Evidence::Present { .. })
    }

    #[must_use]
    pub fn value(&self) -> Option<&T> {
        if let Evidence::Present { value, .. } = self {
            Some(value)
        } else {
            None
        }
    }
}

/// Opaque process-start token used together with a PID to detect PID
/// reuse: two observations of the same PID with different
/// `ProcessStartToken` values are different processes, never the same
/// one restarted. The concrete representation (e.g. Linux's
/// `/proc/<pid>/stat` `starttime` field, in clock ticks since boot) is an
/// implementation detail of the collector (F-M1-003/HORO-832); this
/// crate only needs it to be stable, comparable, and opaque.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessStartToken(pub u64);

/// One ancestor in a process's parent chain. Ancestry is a contextual
/// signal — never used to imply trust by itself (North Star invariant
/// 4: "parent == trusted" is exactly the shortcut this module refuses to
/// take).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessAncestor {
    pub pid: u32,
    pub start: Evidence<ProcessStartToken>,
    pub executable_path: Evidence<String>,
}

/// Result of [`WorkloadIdentity::compare_process`]. Deliberately three
/// states, not a `bool`: "insufficient evidence to tell" must never be
/// representable as, or confusable with, "confirmed different process."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityComparison {
    Same,
    Different,
    /// One or both sides lacked a usable `process_start` token. Callers
    /// must treat this as its own case — never as `Same` and never as
    /// `Different`.
    Indeterminate,
}

/// Stable identity for one observed workload process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadIdentity {
    pub pid: u32,
    /// Paired with `pid` to distinguish a genuinely long-running process
    /// from PID reuse by a later, unrelated process. See
    /// [`WorkloadIdentity::compare_process`] for the defined comparison
    /// semantics.
    pub process_start: Evidence<ProcessStartToken>,
    pub uid: Evidence<u32>,
    pub gid: Evidence<u32>,
    pub executable_path: Evidence<String>,
    pub executable_hash: Evidence<String>,
    pub ancestry: Vec<ProcessAncestor>,
}

impl WorkloadIdentity {
    /// Compare `self` and `other` for whether they observe the same
    /// running process.
    ///
    /// Defined PID-reuse/restart semantics: [`IdentityComparison::Same`]
    /// only when `pid` matches **and** both `process_start` tokens are
    /// [`Evidence::Present`], equal, **and** neither side's token has
    /// `source: EvidenceSource::SelfAsserted`. If either side's start
    /// token is missing, unsupported, or self-asserted, the result is
    /// [`IdentityComparison::Indeterminate`] — **not** `Different` and
    /// **not** `Same`. This is a three-way result rather than a `bool`
    /// on purpose: collapsing "confirmed different process" and
    /// "insufficient evidence to tell" into a single `false` would let a
    /// caller treat `!comparison` as proof of a new process when it
    /// might only mean the evidence was missing — exactly the kind of
    /// implicit-trust shortcut North Star invariant 4 forbids.
    ///
    /// The `SelfAsserted` exclusion closes a real gap (found by
    /// independent review, HORO-833): comparing only `value` would let
    /// an attacker-controlled, self-reported start-token claim that
    /// happens to match a real value be indistinguishable from a
    /// genuine kernel-observed one at the one place that actually
    /// decides identity continuity — this crate's own collectors never
    /// produce `SelfAsserted` process-start evidence today, but the type
    /// is `Deserialize` and must not silently trust it if a future
    /// caller ever does.
    #[must_use]
    pub fn compare_process(&self, other: &WorkloadIdentity) -> IdentityComparison {
        match (&self.process_start, &other.process_start) {
            (
                Evidence::Present {
                    value: a,
                    source: source_a,
                },
                Evidence::Present {
                    value: b,
                    source: source_b,
                },
            ) if *source_a != EvidenceSource::SelfAsserted
                && *source_b != EvidenceSource::SelfAsserted =>
            {
                if self.pid == other.pid && a == b {
                    IdentityComparison::Same
                } else {
                    IdentityComparison::Different
                }
            }
            _ => IdentityComparison::Indeterminate,
        }
    }

    /// Compare `self` and `other` for whether they name the same
    /// executable image, using the strongest evidence [`Evidence::Present`]
    /// on **both** sides (hash first, falling back to path). Neither
    /// `pid` nor [`ProcessStartToken`] changes across an in-place
    /// `execve()` — a process can restart into a completely different
    /// binary while [`WorkloadIdentity::compare_process`] alone still
    /// reports [`IdentityComparison::Same`]. Callers that bind an
    /// authorization to a specific executable (e.g. [`crate::lease`])
    /// must check this in addition to `compare_process`, not instead of
    /// it — the two guard different substitution attacks.
    #[must_use]
    pub fn compare_executable(&self, other: &WorkloadIdentity) -> IdentityComparison {
        if let Some(comparison) =
            Self::compare_evidence(&self.executable_hash, &other.executable_hash)
        {
            return comparison;
        }
        if let Some(comparison) =
            Self::compare_evidence(&self.executable_path, &other.executable_path)
        {
            return comparison;
        }
        IdentityComparison::Indeterminate
    }

    fn compare_evidence<T: PartialEq>(
        a: &Evidence<T>,
        b: &Evidence<T>,
    ) -> Option<IdentityComparison> {
        match (a, b) {
            (
                Evidence::Present {
                    value: x,
                    source: source_x,
                },
                Evidence::Present {
                    value: y,
                    source: source_y,
                },
            ) if *source_x != EvidenceSource::SelfAsserted
                && *source_y != EvidenceSource::SelfAsserted =>
            {
                Some(if x == y {
                    IdentityComparison::Same
                } else {
                    IdentityComparison::Different
                })
            }
            _ => None,
        }
    }
}

/// The execution environment around a [`WorkloadIdentity`] at the moment
/// it requested protected compute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub workload: WorkloadIdentity,
    pub cgroup_path: Evidence<String>,
    pub namespace_hint: Evidence<String>,
    pub container_hint: Evidence<String>,
    pub session_origin: Evidence<String>,
}
