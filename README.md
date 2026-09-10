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
crates/          Rust workspace: domain, backend, agent, protocol, CLI
platform/linux/  Linux-specific integration (agent, eBPF)
docs/            Product constitution, architecture, ADRs, QA
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`docs/development/`](docs/development/) for the engineering workflow.

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability reporting process.

## License

See [`LICENSE`](LICENSE) — **pending founder decision**, tracked in
[HORO-781](https://lightning-dust-mite.atlassian.net/browse/HORO-781).
