# Contributing to Eltanin

## Ground rules

- North Star: **no protected compute without authorization.** A change that
  weakens this must not be merged silently — see
  [`docs/product/NORTH_STAR.md`](docs/product/NORTH_STAR.md).
- Rust is the default implementation language. C is allowed only at
  unavoidable FFI boundaries. C++ requires a compelling vendor SDK
  requirement.
- Unsafe Rust must be isolated, documented, and reviewed.

## Workflow

1. Branch from latest `main`: `<phase>/<ticket>/<short_summary>`
   (e.g. `mvp-1.0/HORO-825/define_resource_domain`).
2. Small, atomic, Gitmoji-prefixed commits: `<emoji> (<scope>): <summary>`.
   One semantic change per commit (one model, one function, one test).
3. Open a PR against `main` using the PR template. `main` is PR-only —
   direct pushes are rejected once branch protection is enabled.
4. One implementation ticket maps to at most one PR unless the ticket
   explicitly documents a justified exception.
5. All required CI checks must be green before merge. Merge via **merge
   commit** — never squash, never rebase-merge.

## Testing

- New features require tests. Bug fixes require a regression test.
- Normal CI runs with no GPU, against the Fake/Virtual Compute Backend.
  Real-hardware jobs are separate release/integration gates.

## Documentation

Every change must classify Docs Impact: User Docs | Contributor Docs |
Both | None (with an explicit reason). See
[`docs/development/`](docs/development/).
