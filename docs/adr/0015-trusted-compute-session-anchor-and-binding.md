# ADR 0015: Trusted Compute Session Anchor and Binding — POSIX-Session-Leader Redesign

## Status

Accepted (MVP 2.0 — HORO-1278, founder-reviewed).

## Headline disclosure — read this before anything else

**F-M2-001, the flagship feature MVP 2.0 is named for, did not survive
real multi-invocation CLI usage.** `ELTANIN_AGENT_SESSION_REQUIRED=1`
behaved as a deny-all switch for any real deployment, not the "prove
intent once per terminal" gate ADR 0009 describes. This was found by
HORO-797's Track B scenario (`docs/qa/e2e/B-M2-DEVFLOW.md`), not by
F-M2-001's own Track A suite, and confirmed live against real binaries
on macOS: `eltanin session start` reports `SessionEstablished`; the very
next `eltanin session list` — a separate real process in the same POSIX
session — reported no active session at all.

This ADR records the redesign that closes that defect, and a second,
independent bug closed in the same pass: `TrustedSession::owner_uid` was
stored at establishment time but never actually compared by
`membership()`. Both are real, disclosed, and fixed — this document does
not soften either.

## The defect

`eltanin-agent`'s `session_establish_inputs` set a newly established
session's anchor `leader` to the `CreateSession` request's own connecting
peer — i.e. `eltanin session start`'s own process identity (pid + start
token). That process is short-lived *by design*: `session start`
establishes the session and exits immediately, printing its result.
Every later session-touching operation re-collected that same pid's
*current* identity and required `WorkloadIdentity::compare_process` to
report `Same` against the recorded leader — a comparison that can never
succeed once the anchor process has exited, which for `session start` is
always, and near-immediately.

Track A's `authz_session.rs` did not catch this because its
`self_peer_context()` helper is the same live test-process object for
the whole test — the anchor leader never actually died mid-test there,
which is exactly the condition every real separate CLI invocation
produces. The bug was found only because HORO-797's Track B scenario
(`B-M2-DEVFLOW-v1`, PR #67) drove the real `eltanin` binary across two
separate process invocations.

A second, independent defect was closed in the same pass:
`TrustedSession` stored `owner_uid` from the moment `SessionAuthority::establish`
was first written, but `membership()` never compared it against anything
— a different uid in the same POSIX session was silently admitted. This
was not the ticket's headline defect but was found and fixed during the
same design/implementation pass (see `membership_requires_matching_owner_uid`
and `horo1278_a_different_uid_in_the_same_posix_session_is_refused`).

## The founder-approved trust model (verbatim constraints, HORO-1278)

The founder's ruling, restated here for the permanent record:

> The trusted session MUST NOT be anchored to the lifetime/PID of one
> CLI process. Use a host-local daemon/authoritative-agent managed
> session lease instead. Session identity bound to, at minimum: host
> identity, local OS user/security principal, opaque generated session
> ID, relevant policy/context, explicit TTL/expiry.
>
> Requirements:
> - session material must not be forgeable by an untrusted client
> - authoritative session state belongs to the local trusted agent/daemon
> - expiry, revocation/session-stop, and tampering must all fail closed
> - stale, cross-user, and (where host identity is available) cross-host
>   session reuse must be rejected
> - PID/process lifetime must NOT be the primary session identity;
>   parent-shell/process lineage may be additional evidence only
> - preserve a path for future Secure Enclave/TPM-backed strengthening

Every decision below exists to satisfy one or more of these bullets
directly, and the AC-mapping table at the end of this ADR maps each one
to the real test that proves it (or states plainly that none exists,
where the requirement is structural rather than testable).

## Decision — anchor to the resolved POSIX session leader, never the connecting peer

The session's anchor leader is now resolved from the POSIX session id
(`sid`) itself, not from whichever peer happened to be connected when
`CreateSession` was handled. Concretely: at establishment time, the
agent resolves the *current* leader of the caller's `sid` independently
of which process asked, and records that leader's `WorkloadIdentity` (or
records `Unobserved` if no leader could be collected) as the anchor.
Because `eltanin session start`'s own process is a member of the same
`sid` as every later CLI invocation launched from the same terminal,
this closes the defect at its root: nothing about the anchor's validity
depends on `session start`'s own process staying alive.

This required extending `membership()`'s combined signature — the one
security-critical entry point ADR 0009 already established should never
be split into a lookup-then-liveness pair — from `(session, peer_key,
observed_leader)` to:

```rust
pub fn membership(
    session: &TrustedSession,
    peer_uid: &Evidence<u32>,
    peer_key: &Evidence<SessionKey>,
    observed_host: &Evidence<HostId>,
    observed_leader: &WorkloadIdentity,
    now: MonotonicTime,
) -> MembershipVerdict
```

(`crates/eltanin-core/src/session.rs`). Two evidence checks (`peer_uid`,
`observed_host`) and an explicit `now` for expiry were added to the same
single combined call — see the "Decision — expiry is now structural
inside `membership`" section below for why `now` moved here.

## Decision — no client-held session credential; the CLI is unchanged

The design alternative the original ticket framing implied — a
host-local daemon issuing a durable session lease the client then holds
and presents — was considered and rejected in favor of something
stronger: **no session credential exists on the client side at all.**
`eltanin session start|list|end` remain byte-for-byte unchanged at the
CLI layer; no new flag, no persisted file, token, or environment
variable is written anywhere. The agent resolves session membership
entirely from kernel-observed facts it re-derives on every use — uid,
sid, host — never from a value a client presents as "my session is X."
This is machine-asserted, not merely claimed:
`crates/eltanin-cli/tests/session_argv_contract.rs::session_start_persists_no_client_side_credential`
snapshots a private scratch `HOME`/`XDG_*`/`TMPDIR` tree before and
after `eltanin session start` runs and asserts it is byte-identical,
and that stdout carries no token/credential-shaped value.

This is stronger than a bearer token/session-lease file, not merely an
alternative to one: there is no forgeable artifact of any kind for an
attacker to steal, copy, or replay, because none is ever created. This
directly satisfies NORTH_STAR invariant 8 — **"No permanent plaintext
bearer credential for convenience. Authorization artifacts are
short-lived and scoped; long-lived ambient credentials that grant
protected compute are explicitly against this North Star."** — and is
the reason a client-held bearer token/session-lease file was rejected
outright rather than merely hardened (see "Rejected alternatives"
below).

## Decision — `LeaderCorroboration` is reject-only; absence must never deny

The single load-bearing invariant of this redesign:

```rust
pub enum LeaderCorroboration {
    Recorded(WorkloadIdentity),
    Unobserved,
}
```

An absent or unobservable leader (`Unobserved`, or a `Recorded` leader
that a later re-observation cannot confirm — `IdentityComparison::Indeterminate`)
**must never** cause `membership()` or `SessionAuthority::validate` to
deny. Only an actual contradiction — a different, live process now
observably occupying the same sid (`IdentityComparison::Different`) —
may deny. This deliberately inverts this crate's usual fail-closed
`Evidence` discipline (where missing evidence is normally treated as
indeterminate/denied): the entire point of this redesign is that a
Trusted Compute Session's establishing CLI process is *expected* to exit
almost immediately, so treating "the original leader is no longer
observable" as a denial reason would silently reintroduce the exact bug
this ADR exists to fix.

**Warning to future maintainers, stated as plainly as the code itself
states it**: a future attempt to "harden" this by failing closed on
absence is not hardening — it is reintroducing the HORO-1278 defect.
`crates/eltanin-core/src/session.rs::absent_leader_observation_does_not_deny`
pins this verbatim: "If this test is ever changed to expect denial, that
is a regression of the founder's explicit requirement, not a
hardening."

## Decision — `owner_uid`, `HostId`, cross-host and cross-user rejection

`membership()` now compares the peer's freshly collected uid against
`TrustedSession::owner_uid` (`NotMemberReason::OwnerUidMismatch`) and a
freshly observed `HostId` against the session's recorded host
(`NotMemberReason::HostMismatch`), closing both the second defect above
and the founder's "cross-user, and (where host identity is available)
cross-host session reuse must be rejected" requirement in one pass. Both
checks follow the same reject-only-on-confirmed-mismatch discipline as
leader corroboration: missing/unsupported uid or host evidence is
`Indeterminate` (never silently treated as a match), and only a
confirmed different value denies.

`HostId` is honestly disclosed as **currently inert**: session state is
agent-in-memory and single-host today, so cross-host reuse is not a
scenario that can currently arise. Its only job is rejecting reuse in a
future deployment where session state might be shared or persisted
across hosts — it does real comparison work today (`validate_reports_host_mismatch`,
`membership_requires_matching_host`), but the scenario it defends
against does not yet exist in this deployment shape.

## Decision — expiry is now structural inside `membership` itself

Before this redesign, `membership()` took no `now` parameter and never
checked `expires_at` on its own — the safety property depended entirely
on `SessionState::reap` having already run under the same lock before
any lookup (a dependency ADR 0013 itself flagged as an inaccurate module
doc-comment claim at the time). This redesign closes that dependency
structurally: `membership()` now takes `now` directly and checks expiry
itself (`NotMemberReason::Expired`), proven independent of any reaping
sweep by `horo1278_an_expired_session_is_refused_by_membership_itself`,
which calls `membership()` directly with no `AuthorizationHandler` or
`SessionState` involved at all. This satisfies the founder's "expiry...
must fail closed" requirement without relying on a caller ordering
discipline to hold.

## Decision — `SessionNonce`, an inert extension seam for future hardware binding

```rust
pub struct SessionNonce(#[serde(skip)] [u8; 32]);
```

A 32-byte value read from the OS CSPRNG at establishment time,
agent-held only (`#[serde(skip)]` — never serialized to the wire or an
audit log), never compared, never validated. **It does no security work
today.** It exists solely so a future hardware-backed (Secure
Enclave/TPM) challenge/response mechanism has a per-session value to
bind a challenge to, without a breaking change to `TrustedSession`'s
shape when that lands. This satisfies the founder's "preserve a path for
future Secure Enclave/TPM-backed strengthening" requirement as a
structural seam, not as tested behavior — there is nothing to test yet,
by design, and this document does not claim otherwise.

## Decision — `NotMemberReason` gains `KeyMismatch`, `OwnerUidMismatch`, `HostMismatch`, `Expired`, `AnchorRecycled`

`SessionValidity::AnchorGone` is renamed `AnchorRecycled` (HORO-1278) to
make the reject-only distinction unambiguous in the type itself: the
anchor is not merely "gone" (that would be the common, non-denying
case), it is *recycled* by a confirmed different live process. The audit
mirror in `crates/eltanin-audit/src/record.rs`'s `RecordedSessionRefusal`
carries the same five-variant shape faithfully, including
`KeyMismatch`, which is honestly disclosed there as structurally
unreachable through `AuthorizationHandler` today (its `SessionState`
looks a session up by exactly this key, so any candidate `membership()`
is called against already matches by construction) — kept complete
anyway, since `membership()` is a public `eltanin-core` function another
caller could reach differently.

## Decision — `DOMAIN_SCHEMA_VERSION` bumps 6 → 7

This is the sixth MVP 2.0 schema bump (1→2 ADR 0009, →3 ADR 0010, →4 ADR
0011, →5 ADR 0012 — no bump for ADR 0013, →6 ADR 0014, now →7). Same
cost as every prior bump: every pre-existing durable `Approval` embeds
the old schema version and now fails `recall()`'s schema check —
re-approval is required after this ships. No other wire-shape change is
folded into this bump; it exists solely to make the `NotMemberReason`
variant-set change (and `AnchorGone` → `AnchorRecycled` rename) an
explicit decode failure rather than a silent misread by an old client
against a new agent or vice versa, per `envelope.rs`'s own documented
bump criterion.

## Decision — the residual false-negative, disclosed honestly

After the establishing leader exits and its pid is later reused by the
kernel, an unrelated process in a *different* session could in principle
land on `pid == sid` for some other session's leader field. No test
pins this scenario directly — it is disclosed here as reasoning about
the design, not as machine-verified behavior. The reasoning: because
`compare_process`'s existing `ProcessStartToken` comparison (pre-dating
this ticket, unchanged) would very likely observe a different start
token for the coincidentally-reused pid, the analysis is that this
scenario is far more likely to surface as an `AnchorRecycled` denial
(a false negative — a legitimate member incorrectly refused) than as a
silent `Same` match (a false positive — an unrelated process admitted).
This is not proven by a test and should not be read as one. Separately,
and this part *is* tested: the uid check added by this ADR covers the
cross-user variant of the same class of concern regardless of what
leader corroboration concludes
(`horo1278_a_different_uid_in_the_same_posix_session_is_refused`).

## Rejected alternatives

- **A client-held bearer token or session-lease file**, as the original
  ticket framing's "host-local daemon/authoritative-agent managed
  session lease" phrasing could be read to imply. Rejected per NORTH_STAR
  invariant 8 ("no permanent plaintext bearer credential for
  convenience") and because it is unnecessary once reject-only leader
  corroboration works: a client-held artifact only earns its complexity
  if the agent cannot otherwise re-derive membership from kernel state
  alone, and it can. Every one of the founder's own requirements (not
  forgeable, authoritative state held by the agent, fail-closed expiry/
  revocation, stale/cross-user/cross-host rejection) is satisfied without
  ever creating a client-side artifact at all — see `session_start_persists_no_client_side_credential`.
- **A MAC or signature over agent-held session state.** Rejected as
  authenticating nothing when the agent already holds the value in its
  own address space and never accepts it back from a client — a
  signature only does real work once *something crosses the trust
  boundary back into the agent as a claim*, which this design never
  does. This would only become necessary if a client-held credential
  path were ever taken instead (see the point above), which it was not.
- **Failing closed on an unobservable leader** (the "obvious hardening"
  a future maintainer might reach for). Rejected explicitly and
  permanently — this is not a stricter version of the design, it is the
  HORO-1278 defect itself, reintroduced. See "Decision —
  `LeaderCorroboration` is reject-only" above.

## Known disclosed trade-off — S8c, not a regression

A same-session process that avoids `setsid()` (a double-fork-shaped
detached daemon that keeps the leader's sid) is now admitted for the
full session TTL once the leader dies, bounded only by expiry, never by
the establishing leader's own process lifetime —
`crates/eltanin-agent/tests/authz_session.rs::s8c_a_same_session_detached_process_is_bounded_by_ttl_not_by_terminal_lifetime`.
This is disclosed and deliberate: `SessionAuthority::validate`'s own doc
comment states plainly that what now bounds a `TrustedSession`'s
lifetime is TTL/expiry alone, not leader liveness — "this is not a
regression; it is exactly the founder's 'explicit TTL/expiry'
requirement, made structural rather than incidental." Before this
redesign, *any* same-session detached process was killed the moment the
session leader exited — that was the defect's own accidental
"protection," not a real security boundary, and S1's adversarial-matrix
coverage was standing in on top of the very bug this ADR fixes (see
`docs/qa/test-plans/mvp-2.0.md`'s S1 row). The distinguishing fact this
ADR asks a reader to hold onto: TTL-*bounded* admission (correct) versus
permanent/indefinite admission with no expiry (which would be wrong and
is not what this design does).

## AC mapping (HORO-1278 founder-stated requirements)

| Founder requirement | Status | Evidence |
|---|---|---|
| Session material must not be forgeable by an untrusted client | Met | No client-held session credential exists at all — `crates/eltanin-cli/tests/session_argv_contract.rs::session_start_persists_no_client_side_credential` (byte-identical filesystem before/after, no token in stdout) |
| Authoritative session state belongs to the local trusted agent/daemon | Met | `SessionAuthority`/`SessionState` remain wholly agent-internal, in-memory, `Serialize`-only (never `Deserialize`) — unchanged discipline from ADR 0009, re-confirmed by this redesign touching only the anchor-resolution and comparison logic, not this storage model |
| Expiry must fail closed | Met | `crates/eltanin-core/src/session.rs::horo1278_an_expired_session_is_refused_by_membership_itself` — expiry checked structurally inside `membership()` itself, independent of any reaping sweep |
| Revocation/session-stop must fail closed | Met (unchanged from ADR 0009) | `authz_session.rs::ac3_terminating_a_session_prevents_new_lease_issuance_under_required`, `::ac3_terminating_a_session_revokes_leases_issued_under_it` |
| Tampering must fail closed | No test — structural by construction | There is no client-held artifact to tamper with (see the no-credential design above); "tampering" as a threat class does not apply to a value the client never possesses. The closest analogous case — a confirmed sid-recycle contradiction — denies via `AnchorRecycled` (`crates/eltanin-core/src/session.rs::validate_reports_anchor_recycled_when_leader_is_confirmed_different`) |
| Stale session reuse must be rejected | Met | `horo1278_an_expired_session_is_refused_by_membership_itself` (time-based staleness); `validate_reports_foreign_issuer_after_restart` (an agent-restart-stale session is unconditionally `ForeignIssuer`, unchanged from ADR 0009) |
| Cross-user session reuse must be rejected | Met | `crates/eltanin-core/src/session.rs::membership_requires_matching_owner_uid` (unit-level), `crates/eltanin-agent/tests/authz_session.rs::horo1278_a_different_uid_in_the_same_posix_session_is_refused` (integration-level, real kernel-observed evidence with an overridden uid) |
| Cross-host session reuse must be rejected, where host identity is available | Met (currently inert scenario) | `session.rs::validate_reports_host_mismatch`, `::membership_requires_matching_host` — real comparison logic; the scenario itself does not yet arise since session state is single-host in-memory (see "Decision — `owner_uid`, `HostId`" above) |
| PID/process lifetime must NOT be the primary session identity | Met | `session.rs::absent_leader_observation_does_not_deny`, `::unobserved_leader_at_establishment_does_not_deny` — pin the reject-only property directly; `authz_session.rs::horo1278_a_session_survives_the_establishing_peer_process_exiting` proves the actual regression scenario end-to-end against a real killed child process |
| Parent-shell/process lineage may be additional evidence only | Met | `LeaderCorroboration` is reject-only by construction — it can deny (on a confirmed contradiction) but can never itself grant membership; see `LeaderCorroboration`'s own doc comment |
| Preserve a path for future Secure Enclave/TPM-backed strengthening | Met (structural seam, not tested) | `SessionNonce` — write-only, agent-held, never compared; `IntentProof` retains exactly one variant (`LocalPeerPresence`), additive when hardware-backed presence lands (see ADR 0009's original "Extensible seams" framing, unchanged in spirit) |

## Amendment to prior ADRs

This ADR amends [ADR 0009](0009-trusted-compute-session.md) — see the
in-place amendment section added to that document. It also supersedes
ADR 0013's own correction of ADR 0009's session-reaping module-doc claim
(ADR 0013 "Decision — a doc-comment correction, not a behavior change"):
that correction described `membership_for_peer` calling `reap`
immediately before lookup as the load-bearing safety property for
expiry. This ADR changes that property again — expiry is now checked
structurally inside `membership()` itself, independent of `reap` running
first at all. A reader following ADR 0013's correction back to ADR 0009
would land on now-stale guidance without this note.

## North Star unchanged

"No protected compute without authorization" is untouched by this ADR.
A Trusted Compute Session still narrows only *who may even ask* for a
lease; `PolicySet::evaluate` still runs, unmodified, on every
`RequestLease`. Every change in this ADR either closes a real
security-relevant defect (the anchor-to-peer bug; the uncompared
`owner_uid`) or strengthens an already-correct design's binding (host,
structural expiry) — none of it creates a new allow source or loosens an
existing check. This ADR builds on ADR 0009 (which it amends in place),
ADR 0013 (whose own session-reaping correction it supersedes, disclosed
above), and ADR 0014 (`DOMAIN_SCHEMA_VERSION` 6, which this ADR bumps to
7); it does not supersede any of them wholesale, and none is renumbered.
