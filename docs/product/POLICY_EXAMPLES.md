# Authorization Policy — Worked Example

This is a user-facing example of an Eltanin authorization policy
document (F-M1-004). It is **kept byte-identical** to
`crates/eltanin-core/tests/fixtures/example_policy.json`, which
`policy_replay.rs::example_policy_from_the_docs_matches_the_committed_fixture`
loads and validates on every CI run — if this example and the fixture
ever drift apart, that test fails. Don't edit one without the other.

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
