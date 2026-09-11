# Authorization Policy — Worked Example

This is a user-facing example of an Eltanin authorization policy
document (F-M1-004). It is **kept byte-identical** to
`crates/eltanin-core/tests/fixtures/example_policy.json`, which
`policy_replay.rs::example_policy_from_the_docs_matches_the_committed_fixture`
loads and validates on every CI run — if this example and the fixture
ever drift apart, that test fails. Don't edit one without the other.

> **Scope note (F-M1-008, HORO-845): this example is not valid for
> `eltanin run`.** The `executable_path` condition below can only be
> satisfied by a workload that connects to the agent *directly* (e.g. an
> SDK-integrated program) — the kernel-observed evidence the agent uses
> is the *connecting peer's* executable path. `eltanin run` stays alive
> as the lease-holding supervisor for the workload's entire run (see
> [ADR 0005](../adr/0005-eltanin-run-process-topology.md)), so the
> connecting peer through `eltanin run` is always `eltanin` itself, never
> the workload it launches. A policy that expects to gate `eltanin
> run`-launched workloads on `executable_path` will deny every such
> workload, unconditionally, in MVP 1.0 — this is a named limitation, not
> a bug. See "Worked example: `eltanin run`" below for what MVP 1.0
> *can* actually express for that launch path, and
> `docs/product/CLI_CONTRACT.md` for the full limitation statement.

## Scenario

A single developer workstation with one GPU. Alice (uid `1000`) is
allowed to run exactly one trusted tool at `/usr/bin/trusted-tool`
against it. Any workload observed running as `root` (uid `0`) is denied
outright, regardless of what else matches.

```json
{
  "version": 1,
  "payload": {
    "id": "dev-workstation-gpu",
    "revision": 1,
    "rules": [
      {
        "id": "allow-alice-trusted-tool",
        "effect": "allow",
        "resource": {
          "vendor": "fake",
          "kind": "gpu",
          "local_id": "gpu-0"
        },
        "action": "compute",
        "conditions": [
          {
            "field": "uid",
            "expected": 1000,
            "min_trust": "kernel_observed"
          },
          {
            "field": "executable_path",
            "expected": "/usr/bin/trusted-tool",
            "min_trust": "kernel_observed"
          }
        ]
      },
      {
        "id": "deny-root",
        "effect": "deny",
        "resource": {
          "vendor": "fake",
          "kind": "gpu",
          "local_id": "gpu-0"
        },
        "action": "compute",
        "conditions": [
          {
            "field": "uid",
            "expected": 0,
            "min_trust": "kernel_observed"
          }
        ]
      }
    ]
  }
}
```

## What supported matching semantics this example demonstrates

- **AND-only conditions**: `allow-alice-trusted-tool` requires *both* the
  uid and executable path conditions to hold — a request from uid 1000
  running a different binary does not match this rule.
- **`min_trust: "kernel_observed"`**: both rules only trust evidence read
  directly from the kernel (e.g. `/proc/<pid>/status`, not a caller's own
  claim about itself). A workload that could forge its own uid/path
  claim (`EvidenceSource::SelfAsserted`) can never satisfy either
  condition, regardless of what value it claims.
- **Deny-overrides**: if a workload somehow matched *both* rules (not
  possible here since the uid values differ, but the semantics apply
  generally), `deny-root` would win — any matching `Deny` rule always
  overrides any matching `Allow` rule.
- **Default deny**: a request for a different resource, a different
  action, or from any uid other than `1000`/`0` matches neither rule and
  is denied — there is no third "otherwise allow" branch.
- **Fail-closed on missing evidence**: if this workload's uid genuinely
  could not be read (e.g. permission denied), `deny-root`'s condition
  becomes indeterminate rather than simply not matching — the decision
  still denies rather than falling through to `allow-alice-trusted-tool`
  on the strength of the (also unverifiable) executable path alone. See
  `docs/architecture/domain-model.md`'s policy section for the full
  precedence rule.

This is a worked example, not a template to copy verbatim into
production — real policies should express the actual authorized
users/tools for a given host.

## Worked example: `eltanin run`

This example is what MVP 1.0 can actually express for workloads launched
through `eltanin run` — kept byte-identical to
`crates/eltanin-cli/tests/fixtures/eltanin_run_example_policy.json`,
validated by `crates/eltanin-cli/tests/docs_sync.rs`.

### Scenario

Same workstation, same GPU. Alice (uid `1000`) may run any workload
through `eltanin run`; anyone else, including `root`, is denied. Unlike
the SDK-integration example above, this policy **cannot** and does
**not** attempt to name a specific trusted binary — see the scope note
above for why `executable_path` is not a usable condition for this
launch path in MVP 1.0.

```json
{
  "version": 1,
  "payload": {
    "id": "dev-workstation-gpu-eltanin-run",
    "revision": 1,
    "rules": [
      {
        "id": "allow-alice-via-eltanin-run",
        "effect": "allow",
        "resource": {
          "vendor": "fake",
          "kind": "gpu",
          "local_id": "gpu-0"
        },
        "action": "compute",
        "conditions": [
          {
            "field": "uid",
            "expected": 1000,
            "min_trust": "kernel_observed"
          }
        ]
      },
      {
        "id": "deny-root",
        "effect": "deny",
        "resource": {
          "vendor": "fake",
          "kind": "gpu",
          "local_id": "gpu-0"
        },
        "action": "compute",
        "conditions": [
          {
            "field": "uid",
            "expected": 0,
            "min_trust": "kernel_observed"
          }
        ]
      }
    ]
  }
}
```

### What this example demonstrates, and what it deliberately does not

- **Enforceable identity dimensions through `eltanin run` in MVP
  1.0**: uid, gid, process ancestry, and cgroup/governed-execution-context
  membership (once F-M1-007 lands) — all describe the *connecting peer*
  (`eltanin run` itself), which is exactly what this launch path can
  honestly attest to.
- **Deliberately absent**: no rule here conditions on `executable_path`
  or a future `executable_hash`. Adding one would not raise an error
  today (the policy engine has no `eltanin run`-awareness — see
  `docs/architecture/domain-model.md`'s F-M1-008 section for the forward
  obligation to make an executable-identity condition explicitly
  rejected or flagged as unsupported for this launch path), but it would
  silently and unconditionally deny every `eltanin run` invocation,
  since `executable_path` would always observe `eltanin`'s own binary.
  Don't write one.
- Everything else — AND-only conditions, `min_trust: "kernel_observed"`,
  deny-overrides, default-deny, fail-closed-on-missing-evidence — applies
  identically to the SDK-integration example above; see that section for
  the full explanation of each.
