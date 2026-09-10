# Architecture Decision Records

Each ADR records one architecture decision: the context, the decision,
and its consequences. ADRs are numbered sequentially and are not deleted
or renumbered when superseded — a superseding ADR says so explicitly and
links back.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-linux-nvidia-cgroup-ebpf-enforcement.md) | Linux/NVIDIA-first scope, cgroup v2 device-BPF as the enforcement substrate | Accepted |
| [0002](0002-vendor-neutral-domain-backend-trait-boundary.md) | Vendor-neutral domain model behind a backend trait boundary | Accepted |
| [0003](0003-scoped-expiring-compute-lease.md) | Scoped, short-lived Compute Lease as the sole authorization artifact | Accepted |
| [0004](0004-local-ipc-and-nvml-ffi-boundary.md) | Local IPC over versioned Unix Domain Sockets; NVML behind a single FFI boundary | Accepted |

See [`docs/product/NORTH_STAR.md`](../product/NORTH_STAR.md) for the
locked invariants these decisions implement, and
[`docs/product/PRODUCT_CONSTITUTION.md`](../product/PRODUCT_CONSTITUTION.md)
for how they translate into engineering constraints.
