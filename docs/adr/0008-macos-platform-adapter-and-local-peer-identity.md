# ADR 0008: macOS platform adapter — crate boundary, peer-credential binding, and honest limits

## Status

Accepted (MVP 1.0 — Apple Silicon scope amendment).

## Context

[ADR 0007](0007-apple-silicon-metal-backend.md) discovers a physical
Apple Silicon Metal device, but never claims to authorize or launch
anything on macOS — `AppleBackend::discover`/`observe` report a Metal
device; `ControlledLaunch` is explicitly `NotEvaluated` there. F-M1-010's
remaining subtask, HORO-1013, ports the *platform-dependent* portion of
F-M1-003 (workload/process identity), F-M1-006 (local IPC peer
credential), and F-M1-008 (`eltanin run` controlled launch) to macOS far
enough for the existing canonical identity/policy/lease/protocol/CLI/audit
flow to run unmodified on physical Apple Silicon hardware. This ADR
records the crate-boundary, binding, and peer-credential-semantics
decisions that implementation made.

Three decisions needed to be made before writing any macOS-calling code:
where the new code lives relative to `crates/eltanin-apple`, what Rust
bindings to use for process inspection and peer credentials, and — the
one with real security content — how strong a peer-credential guarantee
macOS's socket options actually provide compared to Linux's
`SO_PEERCRED`.

## Decision — crate boundary: a new `crates/eltanin-macos`, not an extension of `crates/eltanin-apple`

`crates/eltanin-macos` is a new workspace member, holding macOS
process-identity collection (`crate::collect_workload_identity`/
`collect_execution_context`) and local IPC peer-credential collection
(`crate::peer::collect_peer_context`). It is **not** added to
`crates/eltanin-apple`.

ADR 0007's crate-boundary decision named `crates/eltanin-apple` "the
Apple vendor adapter," not "a Metal wrapper library," specifically so a
*future non-Metal accelerator API* could live there without forcing a
rename. Read in place, that reasoning is scoped to the accelerator
backend `eltanin-apple` implements (`ComputeBackend`) — it says nothing
about OS-level process/IPC code, and using it to justify folding
HORO-1013's scope into `eltanin-apple` would over-read it. This ADR
narrows that reading explicitly (see "Amendment" below).

The decisive constraint is `docs/product/PRODUCT_CONSTITUTION.md`'s
vendor-neutral-core rule, extended to `crates/eltanin-agent` by ADR
0007's own language: `eltanin-agent` depends on a *platform* adapter for
process/peer-credential collection, never on a *vendor* backend.
`eltanin-agent` must consume the real peer-context source
(`src/peer.rs`) and the real workload-identity collector
(`src/runtime.rs::issuer_instance_id`). Putting either in
`eltanin-apple` would put `eltanin-apple` — and therefore `objc2`/
`objc2-foundation`/`objc2-metal` — in `eltanin-agent`'s dependency graph
purely to read `LOCAL_PEERCRED`, a literal violation of that rule, not a
smell a cfg gate could hide.

This also matches the repository's existing OS/vendor split for the
other platform: `crates/eltanin-linux` (the OS platform adapter) is a
separate crate from the not-yet-built `crates/eltanin-nvidia` (the
vendor accelerator adapter) — Apple Silicon collapses vendor and OS into
one physical platform, but that does not collapse the two *concerns*.
The Jira Component table (ADR 0002's naming/layout authority) already
tracks them separately: `Eltanin :: Apple Silicon` (10163, backing
`eltanin-apple`) and `Eltanin :: macOS Platform` (10164, backing
`eltanin-macos`), both created alongside F-M1-010's subtasks.

`crates/eltanin-macos` keeps `#![forbid(unsafe_code)]` — see the binding
decision below — a property `crates/eltanin-apple` cannot have (its
Metal compute-buffer readback needs one scoped `unsafe` fn, per ADR
0007). Merging the two crates would have lost that property for code
that does not need to give it up.

## Decision — file layout and binding choice

```
crates/eltanin-macos/
  Cargo.toml
  src/lib.rs   # collect_workload_identity / collect_execution_context,
               #  mirroring crates/eltanin-linux/src/lib.rs's shape:
               #  a cfg(target_os = "macos") `imp` module with the real
               #  collector, a cfg(not(...)) `imp` reporting Unsupported
               #  on every field.
  src/peer.rs  # collect_peer_context, same cfg-split shape, mirroring
               #  crates/eltanin-linux/src/peer.rs.
  tests/peer_credential.rs      # mirrors eltanin-linux's own test file
  tests/macos_integration.rs    # mirrors eltanin-linux's own test file
```

Two source files, not four — `eltanin-linux` keeps its whole real
collector inline in `lib.rs`; this crate matches that so the two
collectors diff cleanly against each other.

Dependencies, both target-gated to `cfg(target_os = "macos")` exactly
like `eltanin-linux` gates `rustix` and `eltanin-apple` gates
`objc2*`, so neither ever enters a non-macOS build's dependency graph:

- **`nix`** (`sockopt::LocalPeerCred`, `sockopt::LocalPeerPid`) — a safe
  wrapper over `getsockopt(SOL_LOCAL, LOCAL_PEERCRED/LOCAL_PEERPID)`.
  `rustix::net::sockopt::socket_peercred` (the wrapper `eltanin-linux`
  uses) is Linux-only — verified against its own `cfg` gate — so it has
  no macOS equivalent to reuse; `nix`'s Apple-gated sockopts are the
  narrowest safe alternative.
- **`libproc`** (`proc_pid::pidinfo::<BSDInfo>`, `proc_pid::pidpath`) — a
  safe wrapper over `proc_pidinfo`/`proc_pidpath` (public, documented
  `libproc.h` functions — not Endpoint Security, not a private/
  undocumented hook, satisfying this ticket's AC #8 by construction, not
  by omission).

This is the same "safe wrapper crate over hand-written unsafe libc FFI"
trade-off this workspace already made twice — `rustix` for
`SO_PEERCRED`/`geteuid` (ADR 0004, `eltanin-linux`/`eltanin-agent`) and
`signal-hook` for `SIGTERM`/`SIGINT` (HORO-840) — applied to the one
remaining OS boundary that needed it. Both `nix` and `libproc` are
`MIT`-licensed, already covered by `deny.toml`'s allow-list; the exact
API surfaces used (`XuCred::version()`/`uid()`/`groups()`,
`sockopt::LocalPeerCred`/`LocalPeerPid`, `libproc::proc_pid::{pidinfo,
pidpath}`, `bsd_info::BSDInfo`'s field names) were verified by reading
the real downloaded crate sources (`nix` 0.30.1, `libproc` 0.14.11).
`cargo deny check` was run for real against the resolved dependency
graph — including `nix`/`libproc` — using a private `CARGO_TARGET_DIR`
to bypass this session's shared dev machine's contended
`~/.cargo/shared-target` lock (see the PR description's verification
notes); it reported `advisories ok, bans ok, licenses ok, sources ok`.

**Consequence**: `crates/eltanin-macos` keeps `#![forbid(unsafe_code)]`
— unlike `crates/eltanin-apple` (ADR 0007) and the not-yet-built
`crates/eltanin-nvidia` (ADR 0004), this platform adapter needed no
`unsafe` escape hatch at all.

## Decision — field mapping (mirrors `eltanin-linux` field-for-field)

| `WorkloadIdentity` field | macOS source | Note |
|---|---|---|
| `process_start` | `BSDInfo::pbi_start_tvsec`/`pbi_start_tvusec`, combined into one microsecond-since-epoch `ProcessStartToken` | **Different unit and epoch from Linux's clock-tick token.** Harmless: `ProcessStartToken` is documented (`eltanin_core::identity`) as opaque, compared only for equality within one host's one collector — nothing in this workspace compares a Linux-collected token against a macOS-collected one. |
| `uid` / `gid` | `pbi_ruid` / `pbi_rgid` (**real**) | Matches `eltanin-linux`'s established real-uid-first semantics exactly — not `pbi_uid`/`pbi_gid` (effective), which `crate::peer` instead reconciles separately against the peer's kernel-reported effective uid. |
| `executable_path` | `proc_pidpath` | `Missing` on failure, never a panic. Requires root to resolve a foreign-uid process's path on macOS — same privilege caveat `eltanin-agent`'s docs already state for Linux's `CAP_SYS_PTRACE`. |
| `executable_hash` | not implemented | `Evidence::Missing{"executable hashing not implemented by this collector"}` — exact parity with `eltanin-linux`. Explicitly out of scope for this ticket (see Non-goals). |
| `ancestry` | `pbi_ppid` chain | Same `MAX_ANCESTRY_DEPTH = 32` bound and cycle guard as `eltanin-linux`; same documented "early stop indistinguishable from reaching the top" limitation. |

`ExecutionContext::{cgroup_path, namespace_hint, container_hint,
session_origin}` are all `Evidence::Unsupported` on macOS.
`cgroup_path` is `Unsupported` (not `Missing`) because Darwin genuinely
has no cgroups — the mechanism does not exist, as opposed to existing
and failing to read. The other three are `Unsupported` for exact parity
with `eltanin-linux`, which reports the same three fields `Unsupported`
today: macOS reporting *more* context than Linux for no ticket-driven
reason (e.g. a controlling-tty-derived `session_origin` via `sysctl`)
would create an unjustified platform asymmetry, not a genuine
capability gain — deferred, not implemented here.

## Decision — peer credential binding, and its honest limit

This is the security-material decision. macOS has two relevant
`SOL_LOCAL` socket options, and they do not provide equal guarantees:

- **`LOCAL_PEERCRED`** returns an `xucred`: the connecting process's
  **effective** uid/gid, captured **once, at `connect()` time** (XNU's
  `unp_connect` copies the connecting process's credential into
  `unp_peercred` under `UNP_HAVEPC`) — the same connect-time-fixed
  strength as Linux `SO_PEERCRED`'s uid/gid. It carries **no pid** and no
  start-time field.
- **`LOCAL_PEERPID`** returns the peer's pid — but reads XNU's `last_pid`
  socket field, which is updated on subsequent socket operations
  (`so_update_last_owner_locked`), **not connect-time-fixed**. Handing a
  connected file descriptor to a different process and having that
  process operate on the socket changes what this option reports.

**Consequence**: on macOS, the peer-consistency cross-check
(`eltanin_core::peer::classify_consistency`, reconciling `xucred`'s
connect-time effective uid against the real/effective uid a fresh
`libproc` lookup reports for the `LOCAL_PEERPID` pid) carries *more*
security weight than the equivalent Linux cross-check — it is the only
thing binding the one strong, connect-time-fixed credential
(`LOCAL_PEERCRED`'s uid) to the pid every downstream `WorkloadIdentity`
field is keyed on. A cross-uid file-descriptor hand-off between
`connect()` and this collector's read produces
`PeerConsistency::CredentialDivergence` (or `Indeterminate` if the new
pid cannot be inspected), so `PeerContext::authorizable()` returns
`None` and the request fails closed — the same fail-closed contract
Linux already has. **A same-uid hand-off is not caught** by this
cross-check, exactly mirroring the same-uid PID-reuse gap
`crates/eltanin-linux/src/peer.rs`'s own module docs already name and
leave open. Neither gap is closed by this ADR; both are named,
honestly-scoped limitations, not unstated assumptions.

`crate::peer::collect_peer_context` runs immediately after `accept()`,
before the first request frame is read (`eltanin-agent::connection::serve_connection`'s
existing ordering, unchanged by this ticket) — this narrows, but does
not eliminate, the window in which such a hand-off could occur.

**Rejected alternative — `LOCAL_PEERTOKEN`** (`audit_token_t`, pid +
pidversion): would add PID-reuse detection in principle, but XNU derives
it from the same `last_pid` field `LOCAL_PEERPID` uses, so it does not
close the gap above — it would only move the same weak link one layer
deeper. `BSDInfo::pbi_start_tvsec`/`pbi_start_tvusec` already gives this
crate's `ProcessStartToken` equivalent to Linux's, so nothing is lost by
not adopting it. Not implemented now; named here as a candidate for a
future ticket if this gap is ever prioritized for closure (the same
status `eltanin-linux`'s own residual gap already has — no mechanism
pre-selected).

**No new `PeerConsistency` variant** was added for the "pid is live, not
connect-time-fixed" asymmetry. `PeerConsistency` is mirrored into
persisted `eltanin-audit` NDJSON records (`RecordedPeerConsistency`); a
new variant is an audit-schema change with blast radius far beyond this
narrow platform distinction. The existing `Indeterminate`/
`CredentialDivergence` variants already cover every observable outcome;
the asymmetry itself is documented in `crate::peer`'s module docs and
above, not encoded as a new type.

**Malformed-response handling**: `XuCred::version()` (nix's safe wrapper
over the kernel's `xucred` struct) is checked against `XUCRED_VERSION`,
and an empty group list from `XuCred::groups()` is treated as a
`PeerCredentialError::Io` (no fabricated gid) — refusing to guess at an
unexpected kernel ABI shape rather than silently proceeding with
undefined field contents. `nix`'s `XuCred` does not expose the kernel's
`cr_ngroups` count separately; this collector relies on the documented
kernel convention that `cr_groups`'s first entry is always the effective
gid, the same convention `nix`'s own `groups()` doc comment states.

## Decision — non-macOS fallback

`crate::collect_workload_identity`/`collect_execution_context` and
`crate::peer::collect_peer_context` are `cfg`-gated: on `macos` they
call the real `libproc`/`nix`-backed collectors; on every other
`target_os` they report `Evidence::Unsupported` (identity/context) or
`PeerCredentialError::UnsupportedPlatform` (peer), with zero macOS API
calls attempted — no `nix`/`libproc` dependency exists in a non-macOS
build's dependency graph at all. This is what lets `crates/eltanin-macos`
build and unit-test on this repository's `ubuntu-latest` CI runner (the
`Unsupported`-fallback path), while the real collector is only compiled
*and only exercised* on a `macos-latest` runner — see "CI" below.

## Decision — peer contract relocation to `eltanin-core::peer`

`PeerCredential`, `PeerConsistency`, `PeerContext`, `PeerCredentialError`,
and the consistency classifier (renamed `classify_consistency`, kept
pure and platform-neutral) move from `crates/eltanin-linux/src/peer.rs`
to a new `crates/eltanin-core/src/peer.rs`. Two platform adapters
(`eltanin-linux`, `eltanin-macos`) must produce the same contract for
`eltanin-agent` to consume through one seam; neither may depend on the
other, and `eltanin-core` is the one crate both already depend on.

**Construction is deliberately narrower after the move than a literal
relocation would produce.** `PeerCredential`'s and `PeerContext`'s
fields are private; in `eltanin-linux`, only same-crate code could ever
construct a real one by struct literal, which is what made "production
code has exactly one way to construct a real `PeerContext`"
(`eltanin-linux`'s own module docs) true without any enforcement code —
a naive move to a shared crate would have needed a public constructor,
and then **any** downstream crate could mint
`PeerConsistency::Consistent` directly and pass `authorizable()`. To
preserve the invariant instead of quietly weakening it, the only
non-test constructors are:

- `PeerCredential::from_kernel(pid, effective_uid, effective_gid)`
- `PeerContext::from_kernel_observation(credential, observed, &real_uid, &effective_uid)`
  — runs `classify_consistency` internally; the caller supplies
  observations, never a `PeerConsistency` verdict.
- `PeerContext::peer_unmapped(credential, observed)` — the "kernel
  credential mechanism reported no resolvable pid" case (Linux's pid-0
  `SO_PEERCRED` report; macOS's non-positive `LOCAL_PEERPID` report).
- `PeerContext::for_test(...)`/`PeerCredential::new`/`PeerContext::new`
  (the last two are `test-support`-gated aliases preserved for the
  existing call sites) — gated behind the `test-support` Cargo feature
  (relocated from `eltanin-linux` to `eltanin-core`), never available in
  a normal build.

No production code path in this workspace can hand-assert
`PeerConsistency::Consistent`. `crates/eltanin-agent/tests/agent_architecture_guard.rs`
gained a third test asserting `eltanin-agent`'s own `src/` never names
the `test-support`-gated constructors, compensating for the fact that
the old crate-local privacy boundary no longer exists.

`eltanin-audit`'s `Recorded*` mirrors and their golden tests are
unaffected by this move — they already depend only on plain data shapes
that did not change.

## CI

Unlike ADR 0007's Apple Silicon *Metal* backend — which deliberately
added no `macos-latest` CI job, because its device-discovery and
capability-mapping logic (`DeviceSnapshot`, `snapshot_to_resource`) was
kept unconditional specifically so it is testable on `ubuntu-latest`,
leaving only a thin, real-hardware-tagged compute probe behind
`cfg(target_os = "macos")` — HORO-1013 inverts that ratio: nearly all of
its real logic (peer-credential derivation, `libproc`-based process
inspection) lives behind `cfg(target_os = "macos")` and is otherwise
invisible to `ubuntu-latest` CI, which does not even type-check it. This
ADR therefore adds `macos-latest` jobs (`clippy-macos`, `test-macos`) to
`.github/workflows/ci.yml`, mirroring the existing `clippy`/`test`
jobs. This is free on this public repository — GitHub does not bill
macOS runner minutes on public repos — so there is no cost trade-off
analogous to what a private repository would face.

`test-macos` deliberately runs with `--exclude eltanin-apple`. That
crate's `crates/eltanin-apple/tests/metal_compute_probe.rs` dispatches a
real Metal kernel unconditionally (no hardware-availability skip) and
was written for local developer verification on a real Apple Silicon
host per ADR 0007's own Consequences section, which explicitly declined
a macOS CI runner for it — a GitHub-hosted `macos-latest` runner is
virtualized and is not the evidence class that probe exists to
establish. Producing a Feature Verification Record from that probe
remains HORO-1015's scope, unchanged by this ADR. `clippy-macos` still
lints `eltanin-apple` (linting is static and carries no hardware
dependency).

## Consequences

- `crates/eltanin-core/tests/architecture_no_vendor_leak.rs`'s existing
  `apple`/`darwin`/`metal`/`mtl`/`objc` ban (added by ADR 0007) already
  covers `crates/eltanin-core/src/peer.rs`'s new content — it names none
  of those terms in code (only in doc comments, which the test's
  comment-stripping already exempts).
- `crates/eltanin-linux/src/peer.rs` shrinks to a thin
  `collect_peer_context` plus its `#[cfg(target_os = "linux")]` `imp`
  module, importing the shared contract from `eltanin_core::peer`
  instead of defining it.
- `crates/eltanin-agent/src/peer.rs`'s `LinuxPeerContextSource` is
  renamed `OsPeerContextSource`, cfg-dispatching to
  `eltanin_linux::peer`/`eltanin_macos::peer` internally — no
  deprecated alias, since this workspace's convention (`CONTRIBUTING.md`)
  is atomic in-place renames within one ticket's PR, not compatibility
  shims for code with no external callers.
- `crates/eltanin-agent/src/config.rs`'s and `crates/eltanin-cli/src/client.rs`'s
  `DEFAULT_SOCKET_PATH` each gain a `cfg(target_os = "macos")` arm
  (`/var/run/eltanin/agent.sock`, since `/run` does not exist on macOS),
  pinned together by a new `crates/eltanin-cli/tests/docs_sync.rs` test.
- `crates/eltanin-agent/tests/authz_end_to_end.rs` and
  `crates/eltanin-cli/tests/canonical_e2e.rs` widen their file-level
  `#![cfg(target_os = "linux")]` gates to `any(target_os = "linux",
  target_os = "macos")` — both now run for real on this repository's
  `macos-latest` CI runner, not merely compile-checked.
- `docs/product/PRODUCT_CONSTITUTION.md` and
  `docs/architecture/domain-model.md` are updated in this same PR to
  reflect `crates/eltanin-macos`'s existence and its place in the
  platform-adapter list alongside `crates/eltanin-linux`.

## Amendment (2026-09, ADR 0008) to ADR 0007

[ADR 0007](0007-apple-silicon-metal-backend.md)'s "Decision — crate
boundary" section states the `eltanin-apple` naming choice "matters if a
future Apple-Silicon-specific capability needs a non-Metal API." This
ADR clarifies that statement was scoped to a future *accelerator* API
(e.g. a non-Metal compute API Apple might expose later), not to OS-level
process/IPC/launch code — HORO-1013's scope is deliberately kept in a
separate crate (`crates/eltanin-macos`) for the reasons stated above.
ADR 0007 itself is not rewritten beyond this note.

## North Star unchanged

**"No protected compute without authorization"** is untouched by this
ADR. `crates/eltanin-macos` adds process-identity and peer-credential
*evidence collection* only — it adds zero authorization, enforcement, or
revoke capability, and it does not touch `AppleBackend::enforce`/
`revoke`, which (per ADR 0006/0007) remain `Unsupported` on every
target unconditionally. This ticket's `eltanin run` controlled-launch
path on macOS represents exactly what ADR 0007 already stated: **managed
controlled-launch authorization**, never system-wide GPU isolation or a
claim that arbitrary already-running/unmanaged processes are blocked
from Metal. No Endpoint Security entitlement and no private/undocumented
kernel hook is used anywhere in this crate — `LOCAL_PEERCRED`,
`LOCAL_PEERPID`, `proc_pidinfo`, and `proc_pidpath` are all public,
documented APIs.

This ADR does not change ADR 0006's evidence-class framing: **E2**
(Apple Silicon functional evidence, including this ticket's real
controlled-launch authorization flow) **remains additive functional
proof, explicitly not a device-level protection claim. E3** (Linux/NVIDIA
physical device-level enforcement, F-M1-007) **remains the sole,
mandatory basis for any device-level protection claim this project
makes.** An Apple-only PASS — including this ticket's — is insufficient
for MVP 1.0 READY and remains **BLOCKED ON E3**.

This ADR amends [ADR 0007](0007-apple-silicon-metal-backend.md) (see
above) and builds on [ADR 0002](0002-vendor-neutral-domain-backend-trait-boundary.md)
and [ADR 0004](0004-local-ipc-and-nvml-ffi-boundary.md); it does not
supersede any of them, and none is renumbered or rewritten beyond the
amendment note above.
