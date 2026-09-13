# ADR 0010: Remembered Authorization Intent — a second, independent pre-policy admission gate

## Status

Accepted (MVP 2.0 — F-M2-002, HORO-792).

## Headline trade-off — read this before anything else

**A remembered authorization records that this user approved this
resource/action through this launcher. It cannot distinguish which
workload is launched through it, and a compromised-but-unchanged binary
re-fires its old approval silently.**

Unpacked:

1. **Does this protect against a compromised-but-unchanged binary
   reusing its old approval? No — state this plainly.** Digest binding
   (`ApprovalBinding::launcher_digest`) only detects on-disk file
   *replacement*. It detects nothing about in-memory compromise (a
   process exploited after launch) or a malicious-but-unmodified
   program a user was tricked into approving in the first place. The
   digest changing is the only signal this mechanism can ever act on.
2. **Not a boundary against the same user's other processes.** Any
   same-uid process that reproduces the exact binding facts (same
   launcher path/digest, same cgroup-or-none) satisfies `recall`
   identically — a direct analogue of ADR 0009's `postinstall`-script
   disclosure for Trusted Compute Session membership. "Remembered
   authorization intent" narrows *which launcher* was approved, never
   *which process instance* is currently running it.
3. **The actual workload/script/argv is invisible to this mechanism
   entirely** — this is topology (see "Do NOT build in this ticket"
   below), not a shortcut this ticket took. A `python` interpreter
   approved once admits every script later run through that same
   `python` binary, identically to how ADR 0005 already documents this
   limitation for `eltanin run` generally.
4. **macOS's launcher digest is `BestEffort`, not `KernelObserved`** —
   weaker than Linux's. See "Executable-digest implementation" below.
5. **`UNVERIFIED_ON_BARE_METAL`** (this gates lease *issuance*, never
   device access itself — same label ADR 0009 established) and
   **`BLOCKED_ON_E3`** (the cgroup/container dimension is observed and
   compared only, never enforced at the device/cgroup layer — same
   label, same reason: F-M1-007/E3 is still blocked on unavailable
   bare-metal hardware per `docs/development/campaign-state.md`).

`docs/product/SECURITY_MODEL.md`'s rule that a claim exceeding what is
documented is false is why this is the ADR's opening section, not a
footnote.

## AC4 is PARTIALLY met, not fully met — stated here, not softened anywhere else

The ticket's AC4 ("interpreter/container cases are context-scoped") is
only half achievable today:

- **The container/cgroup half is real and built now**: `ApprovalBinding::cgroup_path`
  is compared at `recall` time — a workload that has moved into a
  different cgroup/container (or out of one) is a material change,
  reported as `ChangedDimension::CgroupPath`.
- **The interpreter half is NOT built, and cannot be with what this
  workspace has today.** Binding authorization to *which
  interpreter-invoked script* is running (`python script_a.py` vs.
  `python script_b.py`) is structurally impossible in this ticket for
  three independently sufficient reasons, verified against actual
  current source:
  1. `crates/eltanin-cli/src/sequence.rs` fixes stage S4
     (`RequestLease`) strictly before stage S6 (`SpawnWorkload`) — no
     stage exists between them for a workload identity to be attached
     to the lease request at all. This is the documented structural
     guarantee behind "no globally-permissive access window ever
     opens," and it means there is no point in the sequence where an
     interpreter's *argv* could even be observed before the lease
     decision is made.
  2. `eltanin-protocol`'s wire types carry no client-declared identity
     field anywhere (`crates/eltanin-protocol/src/request.rs`'s own
     module docs: "no producer of `Evidence`/`WorkloadIdentity`/
     `ExecutionContext`") — the zero-identity-field invariant bars a
     client from ever declaring "I am running script X" even if a
     protocol field existed to carry it.
  3. `crates/eltanin-audit/tests/redaction.rs` mechanically forbids any
     collector from reading `/proc/<pid>/cmdline` — the one kernel
     source that could in principle reveal an interpreter's argv. This
     is a deliberate, tested boundary (a workload's own argv can carry
     sensitive material), not an oversight this ticket could work
     around.

  Closing this gap requires a future ADR-0005 amendment (workload
  attestation — binding authorization to the actually-launched
  workload/interpreter-script identity) and a new ticket. It is out of
  scope here, disclosed honestly rather than silently narrowed. **Do
  not globally trust an interpreter (Python/Node/bash/Docker) merely
  because the executable is trusted** is therefore enforced only at the
  launcher-binary level today — the same interpreter approved once
  admits every script run through it, which is exactly the gap the
  follow-up ticket must close.

## Context

The ticket's user outcome: after approving a stable workload/context
once, the user is not prompted again on every restart; Eltanin silently
issues a new short-lived lease only when the current workload still
matches the remembered authorization policy. Core principle: "remember
authorization intent, never remember possession of privilege."

## Decision — a second, independent pre-policy admission gate, structurally identical to ADR 0009's session gate

`eltanin_core::approval::{Approval, ApprovalSet, recall}` is new,
alongside — never inside — `eltanin_core::policy`/`eltanin_core::lease`.
No change to `PolicySet::evaluate`, `Condition`, or `ComputeLease`. An
`Approval` narrows *who may even ask* for a lease; it never itself
grants compute. `AuthorizationHandler::handle_request_lease` runs the
approval gate after the existing session gate (ADR 0009) and before
policy is ever consulted — same structural placement, same reasoning:
a gate refusal here is reported as `DenialReason::ApprovalRequired`/
`ApprovalDenied`, never as if `PolicySet::evaluate` had spoken, exactly
as `NoTrustedSession` already does for the session gate.

Default off: `ApprovalRequirement::NotRequired` (`AuthorizationConfig`'s
default). Every existing MVP 1.0/HORO-791 test harness and deployment
keeps its current behavior unchanged, byte-identically — proven by a
regression test (`authz_approval.rs`'s
`not_required_grants_an_authorized_request_with_zero_approvals_ever_recorded`),
not merely asserted in a comment.

## Decision — `Approval` is the deliberate exception to the "Serialize-only" rule ADR 0009 established

ADR 0009 explains why `TrustedSession` (and, from an earlier ticket,
`ComputeLease`) derive `Serialize` but never `Deserialize`: both types
*are* the bearer authority a session/lease grants, so nothing should be
able to reconstruct one from bytes and treat it as authoritative.

A durable `Approval` is different in kind, not just in degree: it must
survive an agent restart (that is the entire point — "remember
authorization intent," not "remember it until the next reboot"), so it
needs *some* path back from disk. This is safe for exactly the reason
`eltanin_core::policy::PolicySet::from_document` is already safe: the
raw on-disk shape (`ApprovalEntry`/`ApprovalDocument`) is a plain,
`Deserialize`-safe row, and `ApprovalSet::from_document`/`from_versioned`
is the *only* path from that row to a validated `Approval` — mirroring
`PolicySet`'s own document/validated-set split exactly, not a new
pattern. `Approval` itself does not derive `Deserialize`; only the raw
row type does.

**The core safety argument**: even an attacker who somehow writes a
forged entry into the on-disk store only buys the right to *reach*
`PolicySet::evaluate` — policy must still independently allow, and
every `ApprovalBinding` dimension (`recall`'s comparison, not the
stored bytes) is re-observed fresh from the kernel at admission time,
which a static file cannot supply or fake. The bytes are evidence to
re-validate, never bare authority. This is the load-bearing reason
`Approval` can be the deliberate exception without reopening the gap
ADR 0009 closed.

## Decision — `recall()` is one combined signature, not lookup-then-check

`eltanin_core::approval::recall(approval, observed, observed_capabilities,
current_policy, request)` checks every material dimension together in
one call, mirroring `eltanin_core::session::membership`'s own
discipline exactly, and for the same reason: splitting it into a lookup
step followed by a separate check would let a caller look an approval
up once and reuse that lookup's result without ever re-confirming the
launcher context still matches — precisely how a bearer credential
becomes reusable after its original binding is gone.

Candidate lookup (`ApprovalSet::candidates`) is keyed on
`(resource, action)` **only**. Every other dimension — owner uid,
launcher path, launcher digest, cgroup path, resource capability state,
security posture (policy id/revision/schema version) — is a *compared*
dimension inside `recall`, never a lookup key, so a uid or digest change
surfaces as a named `ChangedDimension` for audit rather than a silent
lookup miss with no explanation.

Fail-closed discipline, matching `MembershipVerdict::Indeterminate`:
any dimension where the binding recorded an expectation but the fresh
evidence is `Missing`/`Unsupported`/`SelfAsserted` is
`RecallVerdict::Indeterminate`, and callers must treat this identically
to `NotMatched` — never `Matched`.

## Decision — executable-digest implementation reverses an earlier documented decision

`eltanin-linux`/`eltanin-macos` previously documented a deliberate
decision not to hash an executable's contents ("would make identity
collection itself a resource-consumption vector"). This ticket reverses
that decision, with a bounded size cap (256 MiB) closing the exact
concern that motivated the original decision: above the cap,
`executable_hash` reports `Evidence::Missing` rather than hashing (or
blocking) an arbitrarily large binary.

`sha2`, not `blake3`, was chosen deliberately: `blake3`'s default
features pull in unsafe SIMD code, which this workspace's
`#![forbid(unsafe_code)]` invariant would reject or require an
exception for — `sha2`'s pure-Rust implementation avoids the question
entirely.

**Linux** hashes via `/proc/<pid>/exe`, opened as a file — the
kernel-resolved symlink to the actual exec'd inode, immune to a later
on-disk path replacement (a same-uid attacker who swaps the file after
this process already exec'd it cannot change what this fd reads).
Reported as `EvidenceSource::KernelObserved`.

**macOS is weaker, disclosed plainly**: this crate's pinned `libproc`
(`0.14.11`) has no `/proc/<pid>/exe`-equivalent fd — `pidcwd` and
similar mechanisms that could name the exec'd image directly are
unimplemented for macOS in this pinned version (verified against the
actual pinned dependency source, not assumed). The only path available
is `pidpath`'s currently-reported executable path, re-read by name.
This proves "the file at that path right now," not "the image that was
actually exec'd" — a same-uid attacker who replaces the on-disk file
*after* the process has already exec'd it defeats this check on macOS
in a way Linux's fd-based approach does not. Reported as
`EvidenceSource::BestEffort`, never `KernelObserved`, so `recall`'s own
trust-floor comparison (which already excludes only `SelfAsserted`,
matching `WorkloadIdentity::compare_evidence`'s existing rule) treats it
accordingly.

Both collectors' own tests, which previously asserted the hash was
never present, are updated. No policy fixture in this repository names
`Condition::ExecutableHash` today (verified by grep, not assumed), so
this is a safe behavior change requiring no fixture rewrite beyond the
collector tests themselves.

## Decision — `ApproveRequest` carries `(resource, action)` directly, not a `--profile` name

The originating design sketch proposed `{ profile, disposition }` on
the wire. Verified against actual current source, this is wrong:
`crates/eltanin-cli/src/profile.rs`'s own module docs state a profile
is a "client-side intent alias only" that "never reaches the wire
itself," and no existing protocol type has ever carried one —
`CreateSessionRequest` already takes resolved `Vec<ResourceIdentity>`,
not profile names. `ApproveRequest` follows that same, already-
established precedent: `eltanin approve --profile <name>` resolves
`--profile` to `(resource, action)` client-side via the existing
`crate::profile::load_profile`, exactly as `eltanin run --profile <p>`
and `eltanin session start --profile <p>` already do, and sends the
resolved pair. There is no wire-level `--profile` concept anywhere in
this protocol, before or after this ticket.

## Decision — approval and Trusted Compute Session requirements are independent, conjunctive gates

When both `SessionRequirement::Required` (ADR 0009) and
`ApprovalRequirement::Required` (this ADR) are configured, **both**
gates must independently pass — implemented as two sequential checks
inside `handle_request_lease`, neither subsuming the other. A
remembered approval does not require an active Trusted Compute Session
to re-fire: durable approvals must survive things sessions don't (a
session's own anchor-leader liveness, `SessionValidity::AnchorGone`,
expires far sooner than a `Remember` approval is meant to). Nesting one
gate inside the other would either let an approval alone satisfy a
session requirement (wrong — a session and an approval prove different
things: "this terminal is trusted" vs. "this launcher was approved") or
require re-approving on every new terminal even when the launcher never
changed (defeats this ticket's entire user outcome). Verified with a
dedicated test (`authz_approval.rs`'s
`approval_and_session_requirements_are_independent_both_must_pass`).

The act of running `eltanin approve` proves intent the same way
`eltanin session start` does: `IntentProof::LocalPeerPresence` (ADR
0009) is reused as-is — the authorizable local peer of the `Approve`
request itself is the proof. No second intent-proof mechanism was
introduced.

## Decision — `allow once` / `remember` / `deny` semantics, deny-overrides

`ApprovalDisposition::{Once, Remember, Deny}`. `Once` lives entirely in
agent memory with a short TTL (`AuthorizationConfig::once_approval_ttl`,
default 120s) and is consumed on first successful `Matched` use — safe
to keep in memory-only because `MonotonicTime` is only ever compared
within one `IssuerInstanceId`'s lifetime, exactly like every other
in-memory-only clock reading in this codebase (`ComputeLease`,
`TrustedSession`). `Remember`/`Deny` are durable, with **no TTL at
all** — `eltanin_core` never reads a wall clock (`WallClockTime` lives
in `eltanin-audit`, which depends on `eltanin-core`, never the reverse
— verified by the actual dependency direction in `Cargo.toml`, not
assumed), so a durable approval cannot expire on a schedule even if a
future ticket wanted it to; it is invalidated only by material-change
detection (`recall`) or explicit `eltanin approve forget <id>`.

`Deny` dispositions are evaluated first / always win regardless of
insertion order relative to a `Remember` entry for the same
`(resource, action)` — mirroring `PolicySet`'s own established
deny-overrides convention (`DecisionReason::ExplicitDeny`'s
`overridden_allow_rules`), applied at this gate for the same reason: a
user's explicit refusal must never be silently shadowed by an earlier
approval. In practice this rarely produces two coexisting entries for
one launcher, since `ApprovalId` is a deterministic digest of the
launcher's own identity-anchoring dimensions (uid, launcher path,
launcher digest, cgroup) — re-approving the *same* launcher with a new
disposition replaces the prior entry (`ApprovalSet::insert`) rather
than creating a second one. The deny-overrides ordering is defensive
depth for a store that somehow ends up with more than one matching
candidate (e.g. an admin-edited or restored file), not the everyday
path.

## Decision — no runtime-mintable `PolicySet`/`Condition` extension

Extending `PolicySet`/`Condition` directly (a runtime-authored allow
rule minted by `eltanin approve`) was rejected: it would let a user
grant, via an ordinary client-facing operation, something admin policy
denies — breaking default-deny being structural, the same reasoning
that already keeps a Trusted Compute Session (ADR 0009) from being a
second allow source. An `Approval` narrows admission; `PolicySet` alone
still decides whether a request is ever allowed.

## Decision — rejected alternatives

- **Post-spawn attestation** (attaching identity after
  `SpawnWorkload`): violates the S4→S6 stage adjacency `sequence.rs`
  documents as the structural guarantee against a globally-permissive
  access window — see the AC4 section above.
- **cwd-based "developer context"**: this workspace's pinned `libproc`
  (`0.14.11`) has `pidcwd` literally unimplemented for macOS (verified
  against the actual pinned dependency source, not assumed to be true
  from memory) — and even where implementable, a process's current
  working directory is not a real L2/L3 trust boundary: any same-uid
  process can `chdir()` freely, making it exactly the kind of
  self-asserted, forgeable context North Star invariant 4 already
  forbids treating as authority.
- **A TTL on the durable (`Remember`/`Deny`) approval**: rejected — see
  the "allow once / remember / deny semantics" decision above for why
  `eltanin_core` structurally cannot read a wall clock, and why
  material-change detection is the correct invalidation mechanism
  instead of an arbitrary expiry.
- **Extending `PolicySet`/`Condition` directly**: see the dedicated
  decision above.

## Consequences

- `DOMAIN_SCHEMA_VERSION` bumps to 3 — every fixture/golden test
  asserting the old literal needed updating (mechanical, isolated to
  its own commit), following exactly the precedent ADR 0009 already
  set for the 1→2 bump.
- **This bump alone invalidates every pre-existing durable approval.**
  `PolicySet::provenance()` embeds `schema_version: DOMAIN_SCHEMA_VERSION`
  in the `PolicyProvenance` every `Approval` records as its own security
  posture, and `recall`'s security-posture dimension compares this
  value fresh at every use. A deliberate consequence, not a bug to work
  around: the schema version is part of what "security posture" means
  here, and a security-relevant schema change should require
  re-approval, the same way a policy revision change already does.
- `AuthorizationConfig` gains `approval_requirement` (default
  `NotRequired`, set only via `with_approval_store(path)` — there is no
  way to set `Required` without also supplying a store path,
  correct-by-construction rather than a runtime check for "no default
  value for a security-relevant choice," this repo's own established
  convention for `lease_ttl`) and `once_approval_ttl` (default 120s).
  Every existing test harness and deployment keeps its current MVP 1.0/
  HORO-791 behavior unchanged; only a deployment that opts in via
  `ApprovalRequirement::Required` sees the new pre-policy gate at all —
  proven by a regression test, not merely asserted.
- New crate module: `eltanin_core::approval`. New agent modules:
  `eltanin_agent::authz::approval`/`approval_state`. New CLI module:
  `eltanin_cli::approve`. No new workspace members.
- **AC4 is PARTIALLY met.** The container/cgroup half is real; the
  interpreter half requires a future ADR-0005 amendment (workload
  attestation) and a new ticket — see the dedicated section above. This
  is stated here, in the PR, and in the CLI's own failure messaging
  honestly; it is not claimed as fully met anywhere.

## North Star unchanged

"No protected compute without authorization" is not weakened: a
remembered approval only narrows *who may even reach* policy
evaluation; it grants nothing by itself, and `PolicySet::evaluate`
still runs, unmodified, on every `RequestLease`, approval or no
approval. This is Evidence class E1 (unit/integration, no privileged
enforcement claim) — no device-level enforcement claim is made or
implied by this ticket; that remains E3, still gated on bare-metal
hardware access.

This ADR builds on ADR 0003 (scoped, expiring `ComputeLease` —
unmodified), ADR 0009 (Trusted Compute Session — this ADR's admission
gate is structurally identical and independent, per the "conjunctive
gates" decision above), and ADR 0005 (`eltanin run` process topology —
this ADR's AC4 gap is the same interpreter-topology limitation ADR 0005
already documents for policy evaluation generally, now also documented
for remembered approvals).
