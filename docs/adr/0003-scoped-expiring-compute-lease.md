# ADR 0003: Scoped, short-lived Compute Lease as the sole authorization artifact

## Status

Accepted (MVP 1.0).

## Context

The authorization decision (F-M1-004) needs to produce *something* the
agent (F-M1-006) and enforcement layer (F-M1-007) can check before
granting/continuing protected compute access. The candidates:

1. A long-lived credential/token issued once, checked by presence.
2. A scoped, short-lived **Compute Lease** bound to
   workload/resource/context, checked by validity + expiry on every
   enforcement-relevant event.
3. Implicit trust based on process ancestry (e.g. "child of the
   authorized launcher process").

## Decision

Use option 2: a **Compute Lease** that is:

- **scoped** — bound to a specific `WorkloadIdentity` and protected
  `ResourceIdentity`; a caller cannot present a lease issued for one
  workload/resource pair and use it for another;
- **short-lived** — carries an explicit expiry; there is no "renew
  forever" default;
- **non-broadenable** — nothing in the lease's own lifecycle can widen
  its original scope; a broader grant requires a new authorization
  decision, not a mutation of the existing lease.

Option 1 is rejected — it violates North Star invariant 8 ("no permanent
plaintext bearer credential for convenience"). Option 3 is rejected as
the *sole* basis — it violates North Star invariant 4 (process ancestry
is a signal, not authority) — though process context still feeds into
`WorkloadIdentity`/`ExecutionContext` (F-M1-003) as one input to the
authorization decision that produces the lease.

## Consequences

- F-M1-005 (HORO-822) implements `Lease` with binding, validation, and
  expiry as its core contract — see HORO-836/837 subtasks.
- F-M1-006's agent must re-check lease validity at enforcement-relevant
  moments, not just at initial grant time — a lease that has expired must
  stop protecting compute even if the underlying device handle is still
  technically open (see `docs/product/SECURITY_MODEL.md`'s L3 caveat,
  pending HORO-841 hardware evidence on that exact boundary).
- "Remember authorization intent, never remember possession of
  privilege" (North Star invariant 5) is implemented by: the agent may
  remember *that a particular workload/resource pair was approved under
  policy P*, to streamline re-issuing a fresh lease, but never treats an
  expired lease's prior existence as continuing authority.
