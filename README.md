# Eltanin — Compute Zero Trust

**No protected compute without authorization.**

Eltanin is a local-first authorization and enforcement layer for protected
compute (starting with NVIDIA GPUs on bare-metal Linux). It proves that
protected compute is unavailable without explicit authorization, and
available only through a scoped, expiring authorization path — with no
cloud dependency in the per-compute hot path.

## Status

**MVP 1.0 — Authorization Happy Path** (in progress). This is an
intentionally narrow security vertical slice, not a general product:

- bare-metal Linux only (no Windows/macOS)
- NVIDIA only (no AMD/Intel)
- Rust-first implementation (C only at unavoidable FFI boundaries)
- local authorization and enforcement (no cloud control plane)
- a controlled protected workload launch path (`eltanin run`)
- physical hardware enforcement evidence
- local audit/explain evidence

See [`docs/product/NORTH_STAR.md`](docs/product/NORTH_STAR.md) for the
locked security principle this project is held to, and
[`docs/product/SECURITY_MODEL.md`](docs/product/SECURITY_MODEL.md) for the
current supported threat boundary.

## Explicit non-goals (MVP 1.0)

Windows/macOS, AMD/Intel, SaaS control plane, enterprise SSO/RBAC,
Kubernetes/Slurm/Run:ai integration, ML anomaly detection, a polished
installer. See the Epic (HORO-772) for the full non-goal list.

## Repository layout

```text
crates/eltanin-core/       Vendor-neutral domain: resource, identity, policy, lease, provenance
crates/eltanin-backend/    Backend trait contract + deterministic fake backend
crates/eltanin-protocol/   Versioned local IPC protocol
crates/eltanin-agent/      Privileged local authorization agent
crates/eltanin-cli/        `eltanin` CLI
crates/eltanin-nvidia/     NVIDIA backend adapter (added by F-M1-002)
crates/eltanin-linux/      Linux platform integration (added by F-M1-003/007)
ebpf/eltanin-device-guard/ cgroup v2 device-BPF guard (added by F-M1-007)
docs/                      Product constitution, architecture, ADRs, QA
```

## Quickstart

See [`docs/product/QUICKSTART.md`](docs/product/QUICKSTART.md) for the
ALLOW/DENY `eltanin run` walkthrough.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`docs/development/`](docs/development/) for the engineering workflow.

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability reporting process.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
Founder decision, [HORO-781](https://lightning-dust-mite.atlassian.net/browse/HORO-781).
