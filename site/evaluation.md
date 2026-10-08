# Evaluate Eltanin

Eltanin's North Star is **no protected compute without authorization**.
The current MVP is experimental and in progress. This guide distinguishes
a functioning authorization journey from a validated device-protection claim.

## Build from source

Install a Rust stable toolchain, then clone the public repository:

```sh
git clone https://github.com/horonomy/eltanin.git
cd eltanin
cargo build --workspace
```

Run the walkthrough with the binaries in `target/debug` on your PATH.
Do not run the quickstart as root. It uses the fake backend and a disposable
`echo` workload, not privileged device enforcement.

## Read before evaluating

- [Authorization quickstart](quickstart.md)
- [Supported security model](security-model.md)
- [Policy examples](policy-examples.md)
- [CLI contract and current limitations](cli-contract.md)
- [Apple Silicon fixture and functional evidence boundary](apple-fixture.md)
- [North Star](north-star.md)

[Product source and release history](https://github.com/horonomy/eltanin) remain
canonical. A preview tag does not establish MVP READY or production protection.
No hosted runtime is provided. Site analytics are disabled; local product audit
records can contain process identity and paths, and should be treated as sensitive.

Use [GitHub issues](https://github.com/horonomy/eltanin/issues) for sanitized
questions and [SECURITY.md](https://github.com/horonomy/eltanin/blob/main/SECURITY.md)
for private vulnerability reporting. Never attach credentials or raw workload payloads.
