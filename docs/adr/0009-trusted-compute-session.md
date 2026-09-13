# ADR 0009: Trusted Compute Session — POSIX-session-anchored, agent-owned admission gate

## Status

Accepted (MVP 2.0 — F-M2-001, HORO-791).

## Headline trade-off — read this before anything else

**Adopting the caller's existing terminal session as the trust anchor
means intent is proven once per terminal, and thereafter inherited by
everything spawned in that terminal, with no further act of intent.** A
`postinstall` script run in the same shell after `eltanin session start`
is a session member exactly as much as the interactive command the user
actually intended to authorize. This is within this project's stated
L2/L3 threat-level boundary (`docs/product/SECURITY_MODEL.md`), but it
must be stated as a headline design trade-off, not discovered later as a
surprise. `SECURITY_MODEL.md`'s own rule is that a claim exceeding what
is documented is false — this ADR and the accompanying `SECURITY_MODEL.md`
addition are how that claim gets made honestly instead of by omission.

**What this ticket does NOT prove**: a Trusted Compute Session gates
lease *issuance* — who may even ask — never device-level access itself.
Labeled `UNVERIFIED_ON_BARE_METAL` in docs: device-level enforcement
remains F-M1-007/E3, still blocked on unavailable hardware per
`docs/development/campaign-state.md`.

**Cgroup-scoped session membership is a declared, unbuilt seam**,
labeled `BLOCKED_ON_E3` in docs. It is not implemented here.
`SessionAssurance` gets its second variant only when E3 lands.

**macOS support state**: measured, not assumed — see "macOS measurement"
below.

## Context

The ticket's user outcome: a heavy developer proves intent once,
establishes a Trusted Compute Session, and can work for hours without
approving every compute event. The existing MVP 1.0 model requires a
fresh `RequestLease` per protected workload, each independently
policy-evaluated — correct, but with no notion of "the user already
proved they're here" that could let a deployment require an
established session *in addition to* policy, before a lease is even
considered.

The security model this session type must satisfy: session metadata
becomes policy context; possession of an ID string does not grant
compute (AC5's "no long-lived plaintext bearer secret is the trust
root"); another ordinary process cannot join merely by copying session
metadata/ID (AC2).

## Decision — a new, agent-owned Trusted Compute Session layered on top of the existing lease model

`eltanin_core::session::TrustedSession`/`SessionAuthority` is new,
alongside — never inside — `eltanin_core::lease`. No change to
`ComputeLease`, `PolicyDecision`, or `PolicySet`. A Trusted Compute
Session narrows *who may even ask* for a lease; it never itself grants
compute, and `PolicySet::evaluate` still runs, unmodified, on every
`RequestLease`. This is why the North Star invariant ("no protected
compute without authorization") is not weakened: a session narrows the
population that can even reach the policy gate, it does not replace or
bypass it.

## Decision — anchor to the caller's POSIX session, not a token

No syscall on Linux or macOS lets an unprivileged process *join* an
existing POSIX session it did not create — only leave one (`setsid`).
Membership by descent from a session leader is therefore
kernel-unforgeable: nothing lets an unrelated process become a member of
a session it does not already belong to, verifiable in CI today on both
platforms with no GPU/root/eBPF.

**Process groups were considered and rejected**: `setpgid` lets a
same-session process join *another* group within that session —
forgeable by a process already present, which is exactly the gap a
membership primitive must not have.

**A bearer token/ID string was rejected**: this is precisely what AC2
forbids ("possession of an ID string does not grant compute"). No
client-supplied session id is accepted anywhere in this design —
`eltanin_core::session::SessionAuthority::establish` derives everything
from evidence the agent itself collects, `TerminateSession` carries no
id (avoiding an enumeration oracle), and `ListSessions` returns only
sessions the calling peer independently verifies membership of.

**TPM/hardware-backed user-presence was rejected for this ticket**: the
ticket explicitly defers full TPM support. `IntentProof` has exactly one
variant today (`LocalPeerPresence`) so a hardware-backed variant is
additive, never a breaking change to this one.

**Cgroup-scoped membership was rejected for this ticket**: it needs a
privileged, non-delegated cgroup subtree — the same blast radius as
F-M1-007/E3, unavailable without bare-metal access (see
`docs/development/campaign-state.md`'s dependency blockers). Declared as
a seam only: `SessionAssurance` gets a second variant (`CgroupScope`)
when E3 lands, not before.

## Decision — `membership()` is one combined signature, not lookup-then-liveness

`eltanin_core::session::membership(session, peer_key, observed_leader)`
checks evidence freshness (not self-asserted, not missing), session-key
equality, and leader-liveness (`WorkloadIdentity::compare_process`) in
one call. Splitting this into a lookup step followed by a separate
liveness check would reopen the exact bug this design exists to close:
a caller could look a session up once and rely on that lookup
indefinitely without ever re-confirming the leader process is still the
same one — precisely how a bearer token becomes reusable after its
original binding is gone. `compare_process`'s existing PID-reuse
semantics (same pid, matching non-self-asserted `ProcessStartToken`) are
what defeat a dead-leader-pid-reused-by-an-unrelated-process attack.

## Decision — agent-side reaping is a memory-bound cleanup, never the security boundary

`eltanin-agent`'s `SessionState::reap` runs at the top of every
session-touching operation (`RequestLease`, `CreateSession`,
`ListSessions`, `TerminateSession`), re-observing each live session's
anchor leader and administrative validity
(`SessionAuthority::validate`), dropping anything no longer `Valid`.
This is safe specifically because `membership()` independently
re-verifies fresh evidence on every actual admission decision — a
session reaping has not yet noticed is dead can never be *used*, because
`membership()` would reject it the moment anyone tried. There is no
background sweep thread; this bounds memory, it is not what keeps
membership honest.

## Decision — protocol additions are additive, `DOMAIN_SCHEMA_VERSION` bumps to 2

`ClientRequest` gains `CreateSession`/`ListSessions`/`TerminateSession`;
`AgentResponse` gains `SessionEstablished`/`SessionList`/
`SessionTerminated`; `DenialReason` gains `NoTrustedSession`. Per
`envelope.rs`'s own documented bump criterion ("a wrapped type's wire
shape changes in a way that isn't backward compatible"): both enums are
internally tagged (`#[serde(tag = "op"/"result", deny_unknown_fields)]`)
with no `#[serde(other)]` catch-all, so a v2 client's `create_session`
against a v1 agent (or vice versa) does not silently misdecode — it
fails the envelope version check outright. `DOMAIN_SCHEMA_VERSION` is
bumped from 1 to 2 to make that failure explicit rather than a decode
surprise.

`NoTrustedSession` is a new `DenialReason` variant, not a reuse of
`IndeterminateEvidence`/`NoMatchingRule` — the pre-policy session gate
in `eltanin-agent::authz::AuthorizationHandler::handle_request_lease`
denies *before* `PolicySet::evaluate` is ever consulted, and
`docs/product/SECURITY_MODEL.md`'s rule that "no policy backend decided
this" must never be reported as if policy itself denied it applies here
exactly as it already does for a non-`authorizable()` peer.

`TerminateSession` and `ListSessions` are zero-field struct variants
(`{}`), matching the existing `AgentStatus {}` precedent: a unit variant
gives `#[serde(deny_unknown_fields)]` no real field set to check against
sibling JSON, a gap independent review already found and closed for
`AgentStatus`.

## Decision — no new CLI flag on `eltanin run`

`eltanin run --profile <p> -- <cmd>` is byte-for-byte unchanged. Session
membership is always derived server-side by the agent re-observing
kernel state at the moment of use, never presented by the client — this
is what proves AC1: the existing command works inside an active session
with zero new flags. New top-level subcommands `eltanin session
start|list|end` are added instead (`crates/eltanin-cli/src/args.rs`'s
`parse`/`parse_session`), reusing `--profile`'s existing resolution
wholesale: each `--profile` given to `session start` resolves to a
`ProfileDocument`, and their `resource` fields are unioned into the
session's scope. The action component is ignored at session level —
actions stay per-lease, unchanged.

## macOS measurement (HORO-791, 2026-09, this campaign's actual Apple Silicon development host, Darwin 25.4.0)

The ticket asked whether `nix::unistd::getsid` returns `EPERM` for a
foreign (non-child, non-same-session) pid on macOS, and whether a
launchd-started agent would even share a POSIX session with a
CLI-invoked client at all.

**Measured finding**: `getsid` succeeded for *every* pid tried by an
unprivileged, non-root caller, with **no `EPERM` observed in any case**,
including:

- the caller's own pid and its parent (same session, as expected);
- `pid 1` (`launchd`) — succeeded, reporting `launchd`'s own session id;
- a pid deliberately detached into a fresh session via `setsid()`
  (simulating a real foreign-session process) — succeeded, correctly
  reporting the new, different session id;
- a root-owned, completely unrelated system daemon (`WindowServer`)
  queried by an unprivileged caller — succeeded, reporting its session
  id, with **no permission error of any kind**.

This differs from the ticket's cautious framing, in the favorable
direction: macOS's `getsid` is **not** permission-gated by session or
ownership, matching Linux's equivalent `/proc/<pid>/stat` field-6
readability. Reading a session id is not, and was never intended to be,
the security boundary here — anyone can *read* one, same as Linux (see
this ADR's "anchor to the caller's POSIX session" section) — what
matters is that nothing lets an unrelated process *join* one, and that
property holds identically on both platforms regardless of read
permissions on the id itself.

**On whether a launchd-started agent shares a session with a CLI client**:
also measured, separately — `pid 1` (`launchd`) reports session id `1`
(its own), distinct from any interactively-started shell's session.
This confirms the agent process itself is never expected to be *in* the
session it verifies membership for; it only needs to observe (via
`getsid`) whatever session id a connecting peer's pid currently reports,
which the measurement above confirms it can do for any pid without
restriction.

**Conclusion**: macOS support is not `Unsupported`/fail-closed via
`Evidence::Missing` as the ticket allowed for — the measurement found no
obstacle, so `eltanin-macos::collect_session_key` implements real
collection via `nix::unistd::getsid`, exactly mirroring
`eltanin-linux::collect_session_key`'s `/proc/<pid>/stat` field-6 read.
Nothing else in this design depended on macOS succeeding; it did.

Environment caveat, stated honestly: this measurement was taken on one
development host under this campaign's normal (non-sandboxed,
non-hardened) execution conditions. A more restrictive sandbox profile
or an unusual entitlement configuration was not tested and could in
principle behave differently; `Evidence::Missing` on a real `getsid`
failure remains the correct fail-closed fallback for that case, and
`collect_session_key`'s implementation already produces it whenever the
syscall itself returns an error.

## Consequences

- `DOMAIN_SCHEMA_VERSION` bumps to 2 — every fixture/golden test
  asserting the old literal needed updating (mechanical, isolated to its
  own commit).
- `AuthorizationConfig` gains `session_requirement` (default
  `NotRequired`, set via `with_session_requirement`) — every existing
  test harness and deployment keeps its current MVP 1.0 behavior
  unchanged; only a deployment that opts in via `SessionRequirement::Required`
  sees the new pre-policy gate at all.
- `ExecutionContext.session_origin` (`eltanin_core::identity`) is now
  populated by both platform collectors, tagged `KernelObserved`. It
  remains deliberately unmatchable by `eltanin_core::policy::Condition`:
  a per-boot kernel session id is not a value a static, authored policy
  document can usefully pin in advance — it is a live signal for
  `membership()`'s freshly-observed comparison only.
- New crates/modules: `eltanin_core::session`,
  `eltanin_agent::authz::session`/`session_state`. No new workspace
  members.

## North Star unchanged

"No protected compute without authorization" is not weakened: a
Trusted Compute Session narrows *who may even ask* for a lease; it
grants nothing by itself, and `PolicySet::evaluate` still runs on every
`RequestLease`, session or no session. This is Evidence class E1 (unit/
integration, no privileged enforcement claim) — no device-level
enforcement claim is made or implied by this ticket; that remains E3,
still gated on bare-metal hardware access.

This ADR builds on ADR 0003 (scoped, expiring `ComputeLease` — the model
this session type is layered on top of, unmodified) and ADR 0008
(macOS platform adapter — this ADR's `eltanin-macos::collect_session_key`
extends that adapter's existing collector, following its established
`Evidence`/non-macOS-fallback idioms exactly).
