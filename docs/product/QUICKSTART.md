# Quickstart — `eltanin run`

This walks through the exact ALLOW and DENY journeys MVP 1.0 supports for
`eltanin run`, on bare-metal Linux or macOS. Every command below is
exercised, byte-for-byte, by the canonical Product E2E scenario
`E2E-F-M1-008-controlled-launch-v1`
(`crates/eltanin-cli/tests/canonical_e2e.rs`, `tests/docs_sync.rs` pins
this page to it), on both platforms — if a command here ever drifted
from what that test actually runs, CI would fail. See
[`docs/qa/e2e/F-M1-008-controlled-launch.md`](../qa/e2e/F-M1-008-controlled-launch.md)
for the full evidence record this scenario produces.

**Platform**: bare-metal Linux, or Apple Silicon macOS (F-M1-010,
HORO-1013 — see `README.md`). **Backend**: `FakeBackend` — this
Quickstart proves the *authorization* path end to end; it is not GPU
hardware enforcement evidence (that is F-M1-002/F-M1-007's, gated on
bare-metal NVIDIA hardware, and remains the sole device-level
enforcement basis — see `docs/product/SECURITY_MODEL.md`'s E2/E3
distinction). On macOS specifically, this proves **managed
controlled-launch authorization**, never device-level Metal enforcement
— no Metal/GPU guard exists or is claimed here. **Do not run as root** —
the policy below denies uid `0` outright (see step 2), so a root shell
will always get the DENY journey, never ALLOW.

## What this proves, and what it does not

MVP 1.0 can authorize `eltanin run` based on the connecting caller's
uid/gid, launcher path, process ancestry, and cgroup — the identity
dimensions `SO_PEERCRED` and `/proc` let the agent observe directly and
independently of what the caller claims. It **cannot**, in MVP 1.0,
authorize based on the identity of the workload binary you pass after
`--`: by the time that binary exists as a process, authorization has
already happened. See
[`CLI_CONTRACT.md`](CLI_CONTRACT.md#mvp-10-limitation-stated-up-front)
for the full statement of this limitation and
[`POLICY_EXAMPLES.md`](POLICY_EXAMPLES.md#worked-example-eltanin-run) for
why the policy below only ever conditions on uid, never on
`executable_path`.

## 1. Write a profile

`eltanin run --profile <name>` resolves `<name>` to a
`(resource, action)` pair via a JSON document under
`$ELTANIN_PROFILE_DIR` (or `$XDG_CONFIG_HOME/eltanin/profiles`, or
`$HOME/.config/eltanin/profiles`). Create the directory, then
`~/.config/eltanin/profiles/gpu.json`:

```sh
mkdir -p ~/.config/eltanin/profiles
```

```json
{
  "version": 3,
  "payload": {
    "resource": {
      "vendor": "fake",
      "kind": "gpu",
      "local_id": "gpu-0"
    },
    "action": "compute"
  }
}
```

A profile is a client-side convenience alias only — it never reaches the
agent as a distinct concept; the agent sees the same `(resource, action)`
any client could send directly.

## 2. Write a policy and start the agent

Take the [`eltanin run` policy example](POLICY_EXAMPLES.md#worked-example-eltanin-run)
and replace `1000` in the `allow-alice-via-eltanin-run` rule with your
own uid (`id -u`). Save it as `policy.json`.

`eltanin-agentd` refuses to bind its socket directly into a
world-writable directory like a bare `/tmp`, so create a private
subdirectory for it first:

```sh
mkdir -m 0700 -p /tmp/eltanin
```

Then start the agent in one terminal:

```sh
ELTANIN_AGENT_SOCKET=/tmp/eltanin/agent.sock \
ELTANIN_AGENT_SOCKET_MODE=0600 \
ELTANIN_AGENT_POLICY=policy.json \
ELTANIN_AGENT_LEASE_TTL_SECS=60 \
eltanin-agentd
```

Optionally, add `ELTANIN_AUDIT_LOG=/tmp/eltanin/audit.ndjson` to get a
real audit trail you can query with `eltanin-explain` (step 4) — without
it, the agent logs to stderr only.

## 3. Run a workload

In another terminal, with the agent from step 2 still running:

```sh
ELTANIN_AGENT_SOCKET=/tmp/eltanin/agent.sock \
ELTANIN_PROFILE_DIR=~/.config/eltanin/profiles \
eltanin run --profile gpu -- echo authorized-compute-ok
```

If your uid matches the policy's `allow-alice-via-eltanin-run` rule
(step 2), this prints `authorized-compute-ok` and exits `0` — the
workload's own exit status, passed through verbatim. `eltanin run`
requested a lease, the agent observed your uid via `SO_PEERCRED`,
matched the allow rule, and only then spawned `echo`.

## 4. The DENY journey

Run the exact same command as a caller the policy doesn't name (a
different uid, or edit `policy.json` to allow a uid that isn't yours) and
it instead:

- exits **77** ("denied by policy");
- never runs the workload at all — there is no point in the launch
  sequence between requesting the lease (S4) and spawning the workload
  (S6) for anything else to happen, so a denied request cannot leave any
  trace of the workload having run;
- prints a message on stderr naming the denial and the next action:
  `eltanin-explain --pid <the eltanin process's own pid>`.

That `eltanin-explain` invocation reads whatever `ELTANIN_AUDIT_LOG` you
set in step 2:

```sh
eltanin-explain --log /tmp/eltanin/audit.ndjson --pid <pid from the stderr message above>
```

and prints the full decision record for that denial — the same evidence
[`docs/qa/e2e/F-M1-008-controlled-launch.md`](../qa/e2e/F-M1-008-controlled-launch.md)
cites as Track B evidence for F-M1-009 (local audit & explain).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| exit `69` | `eltanin-agentd` isn't running, or `ELTANIN_AGENT_SOCKET` doesn't match between the two commands. |
| exit `78` | the profile name doesn't resolve — check `ELTANIN_PROFILE_DIR` and that `<name>.json` exists there. |
| exit `74` | the governed execution context could not be established (MVP 1.0's context is a no-op today, so this is unexpected — check the error message). |
| `eltanin-agentd` refuses to start, naming its socket's parent directory | that directory is world/group-writable; create a private one (`mkdir -m 0700 ...`) and point `ELTANIN_AGENT_SOCKET` inside it. |

## Running a real GPU workload on Apple Silicon

Step 3 above uses `echo` so this journey runs on any platform. To run
the exact same ALLOW/DENY journey against a real Metal GPU compute
workload on physical Apple Silicon hardware instead of `echo`, see
[`APPLE_SILICON_FIXTURE.md`](APPLE_SILICON_FIXTURE.md) (F-M1-010,
HORO-1014) — including what that evidence proves and does not prove.
