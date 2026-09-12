# ADR 0006: Cross-accelerator capability support states and memory model

## Status

Accepted (MVP 1.0 — Apple Silicon scope amendment).

## Context

[ADR 0001](0001-linux-nvidia-cgroup-ebpf-enforcement.md) scoped MVP 1.0 to
bare-metal Linux + NVIDIA, and [`Capability`](../../crates/eltanin-core/src/resource.rs)
(HORO-784) was a single `BTreeSet<Capability>` — each capability either
"supported" or not — with variants DISCOVER/OBSERVE/ATTRIBUTE/AUTHORIZE/
ENFORCE/REVOKE/ATTEST. That model was correct for a single enforcement
substrate where "the backend can launch/observe a workload" and "the
backend can deny/kill it at the device level" were, in practice, the
same claim.

A product/architecture scope amendment (2026-09-12) adds Apple Silicon
(physical MacBook Pro M3 Max) as a second real-hardware evidence class
for MVP 1.0, alongside the existing Fake Backend (CI) and Linux/NVIDIA
classes. Apple Silicon has no validated kernel-level mechanism this
project can use to enforce or revoke device-level GPU access — it can
prove real Metal-accelerator compute, ALLOW/DENY application-level
flow, discovery, observation, and attribution, but not device
enforcement. The old boolean `Capability` set cannot represent this: a
backend either "supports enforce" or doesn't, with no way to say
"functionally works, device-enforcement not proven" without either
lying (claiming `Enforce` supported) or hiding a real capability
(reporting the whole backend as unsupported).

## The three evidence classes

MVP 1.0 READY now requires evidence from three distinct classes, not
conflated with each other:

- **E1 — Fake/simulated (CI).** Deterministic, no real accelerator.
- **E2 — Apple Silicon real-accelerator functional evidence.** Real
  Metal GPU compute, full ALLOW/DENY flow, on physical hardware.
  `DeviceEnforce`/`DeviceRevoke` are `Unsupported`/`NotEvaluated` here
  by definition — this class never claims system-wide or kernel-level
  GPU protection.
- **E3 — Linux/NVIDIA physical device-level enforcement.** The
  mandatory hard security gate (HORO-841/844, F-M1-007). Unreplaceable
  by E2 evidence.

**Compatibility is not protection.** A backend being functionally
compatible with a platform (it can discover, observe, launch) must
never be represented, in code, docs, or evidence records, as that
backend providing device-level protection. This ADR's capability model
exists specifically to make that distinction a type-level guarantee
rather than a documentation convention someone can forget.

## Decision — capability model

`Capability` becomes nine independently-evaluated semantic dimensions:

```
DiscoverResource, ObserveResource, ObserveWorkload, AttributeWorkload,
Authorize, ControlledLaunch, DeviceEnforce, DeviceRevoke, Attest
```

Renamed from the original five (`Discover`→`DiscoverResource`,
`Observe`→`ObserveResource`, `Attribute`→`AttributeWorkload`,
`Enforce`→`DeviceEnforce`, `Revoke`→`DeviceRevoke`); `Authorize` and
`Attest` are unchanged; `ObserveWorkload` and `ControlledLaunch` are
new. `ControlledLaunch` supported must never be read as implying
`DeviceEnforce`/`DeviceRevoke` supported — that conflation is exactly
what this amendment removes.

Each dimension carries an independent `SupportState`:

```
Supported | Partial | Unsupported | NotEvaluated
```

`ResourceCapabilities` changes from `{ supported: BTreeSet<Capability> }`
to `{ support: BTreeMap<Capability, SupportState> }`. `supports()` keeps
its exact signature and meaning — it returns `true` iff the state is
exactly `Supported`; `Partial`, `Unsupported`, and an absent key
(`NotEvaluated`) all return `false`. This is the type-level guarantee
that partial or unproven support can never be read as full protection
by existing call sites, none of which needed to change.

### Rejected alternatives

- **A nine-field struct** (one `Option<SupportState>` field per
  dimension). Rejected: a tenth dimension becomes a struct change at
  every construction site, and expressing "not evaluated" needs an
  awkward `Option`-in-effect-`Option`.
- **Three parallel `BTreeSet`s** (`supported`/`partial`/`unsupported`).
  Rejected: permits contradictory states (the same capability present
  in two sets) that then need validation, instead of being
  unrepresentable by construction.
- **Keeping bare `Observe`/`Enforce` alongside new `ObserveWorkload`/
  `ControlledLaunch`.** Rejected: this manufactures exactly the
  ambiguity/conflation this ADR exists to remove.
- **Renaming the type to `CapabilityDimension`.** Rejected: no
  behavioral reason to also break `EnforcementResult::Unsupported { capability }`
  and `BackendError::Unsupported { capability }` field names.

## Decision — memory model

A backend's accelerator memory topology is now representable
truthfully via a new `AcceleratorMemory` enum on `ProtectedResource`:

```
Dedicated { total_bytes: u64 } | Unified | NotReportable
```

`Unified` deliberately carries no byte count — this amendment does not
require a backend to report a fictitious VRAM size for a unified-memory
architecture (e.g. Apple Silicon's shared CPU/GPU memory pool). Default
is `NotReportable`, so a backend that has nothing to say about memory
topology is truthful by construction rather than defaulting to a wrong
guess.

**Security implication of unified memory:** a shared memory pool means
the accelerator's memory is not, by itself, an isolation boundary
against the host process. This is a statement about what the memory
model *is*, not a change to what this project claims to enforce —
device-level protection claims continue to rest entirely on the E3
(Linux/NVIDIA) evidence class, never on the memory model.

`AcceleratorMemory` lives on `ProtectedResource`, not `ResourceIdentity`
— identity is a stable key (used as a `HashMap` key in the Fake
backend), while memory topology is a mutable observation about that
identity.

## Decision — compatibility and versioning

`ProtectedResource`/`ResourceCapabilities`/`Capability` have zero
persisted or IPC-exposed instances anywhere in this repository today:
they appear in no `eltanin-protocol` message type, no audit-record
field (except `EnforcementResult`'s `capability` tag, addressed below),
and the only serialized `ProtectedResource` in the repo is the inline
golden fixture in `crates/eltanin-core/tests/resource_golden.rs`.

`DOMAIN_SCHEMA_VERSION` (`crates/eltanin-core/src/envelope.rs`) is
**deliberately not bumped** by this change. That single constant is
shared by three formats, only one of which this ADR touches:

- the `Versioned<T>` domain-payload envelope (this ADR's concern),
- the IPC framing version (`eltanin-protocol`), unaffected,
- the user-published policy-document format (`docs/product/QUICKSTART.md`,
  `docs/product/POLICY_EXAMPLES.md`), unaffected.

Bumping the shared constant to reflect a resource-shape change with no
persisted instances would break every user's already-documented policy
JSON for a change they never touch. Not bumping it is the correct
choice for *this* change, precisely because nothing that constant
actually versions today has any real bytes affected by it.

**The one real casualty:** `EnforcementResult`'s `capability` field
(e.g. `{"outcome":"unsupported","capability":"enforce"}`) is embedded
in persisted audit JSONL records (`eltanin-audit/src/record.rs`,
`eltanin-agent/src/authz/event.rs`) and read back by `explain`. The
rename (`"enforce"` → `"device_enforce"`) means a developer's
pre-existing local audit file becomes undecodable. This is a real,
named change — not a silent one — and it is acceptable because no
release has shipped and no such file is a canonical fixture in this
repository.

**Named follow-up, explicitly out of scope here:** splitting
`DOMAIN_SCHEMA_VERSION` into separate domain / protocol /
policy-document version constants, so a future change to one format
cannot again force a decision about the other two. Tracked for a
future ticket, not blocking this amendment.

## Consequences

- One golden fixture (`resource_golden.rs`) reshaped deliberately.
- ~60 mechanical `Capability::*` rename call sites across
  `eltanin-core`, `eltanin-backend`, and `eltanin-agent` tests/binaries
  — verified compiling and passing in the same delivery cycle, per the
  global "update every in-repo consumer, no compatibility shim with no
  callers" rule.
- A pre-existing local audit JSONL file (if any) becomes undecodable;
  no committed fixture or released binary is affected.
- `docs/architecture/domain-model.md`, `docs/product/SECURITY_MODEL.md`,
  and `docs/product/PRODUCT_CONSTITUTION.md` are updated to reflect the
  nine-dimension model and the compatibility-vs-protection distinction.

## North Star unchanged

**"No protected compute without authorization"** is untouched by this
ADR, and no locked invariant in `docs/product/NORTH_STAR.md` is
altered. This ADR amends how support is *described* — the vocabulary
for saying what a backend can and cannot do — never what is *enforced*.
The E3 (Linux/NVIDIA) evidence class remains the sole basis for any
device-level protection claim this project makes; Apple Silicon
evidence is additive functional proof, never a substitute for it.

This ADR amends the capability model introduced by
[ADR 0001](0001-linux-nvidia-cgroup-ebpf-enforcement.md) and referenced
by [ADR 0002](0002-vendor-neutral-domain-backend-trait-boundary.md); it
does not supersede either, and neither is renumbered or edited.
