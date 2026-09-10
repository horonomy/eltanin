# North Star

> **No protected compute without authorization.**

This is the one sentence Eltanin exists to make true. Every design
decision, PR, and release claim is measured against it. A change that
weakens it must never merge silently — cite this document to reject it.

## Locked invariants

These are not hypotheses. They do not change without a MAJOR DECISION
(see the campaign's escalation rules) and a new ADR:

1. **Authorization before consumption.** Default deny for protected
   compute. Compute happens only after an explicit, evaluated
   authorization decision — never implicitly, never by default.
2. **Allocation != Authorization.** A scheduler, orchestrator, or
   entitlement system (Kubernetes, Slurm, Run:ai, ...) may decide *who is
   allowed to ask*. It never decides *who is authorized to compute*. Those
   systems are future entitlement inputs, not security roots.
3. **Monitoring != Security.** Telemetry, utilization metrics, and
   observability are evidence for audit/explain — never the authorization
   root. A system that only detects unauthorized compute after the fact
   does not satisfy this North Star.
4. **Contextual signals are not authority.** Process owner, PID, path,
   and parent process are useful *signals* for building workload identity
   and provenance. They are never, by themselves, unconditional proof of
   authorization. They can be spoofed, reused, or inherited.
5. **Remember authorization intent, never remember possession of
   privilege.** A system that "remembers" a workload was previously
   authorized and grants renewed access purely on that memory is
   vulnerable to privilege retention. Intent (what was actually approved,
   under what scope) may be remembered and used to *streamline*
   re-authorization; raw possession of a previously-granted capability
   must never itself be treated as continuing authority once its scope
   has expired.
6. **A lease is scoped and expiring.** Every grant of protected compute
   is bound to a specific workload/resource/context, and expires. A
   caller cannot broaden a lease's scope after it is issued.
7. **Locally observable caller identity is not overridable by untrusted
   caller claims.** The agent's authorization decision is grounded in
   what it can independently verify about the caller, not what the
   caller asserts about itself.
8. **No permanent plaintext bearer credential for convenience.**
   Authorization artifacts are short-lived and scoped; long-lived
   ambient credentials that grant protected compute are explicitly
   against this North Star.
9. **Cloud is absent from the per-compute authorization/enforcement hot
   path.** Local authorization and local enforcement must work with zero
   cloud dependency for every individual compute decision. Cloud/SaaS
   components (when they exist, in later stages) may observe, aggregate,
   or manage fleets — they never sit on the critical path of "can this
   workload compute right now."

## What "MVP 1.0" is allowed to be, and is not allowed to become

MVP 1.0 (HORO-772) is a **Happy Path**: the smallest complete vertical
slice of this North Star on one narrow platform (bare-metal Linux +
NVIDIA + Rust). It is explicitly **not allowed to become**:

- GPU monitoring or utilization dashboards;
- scheduler/orchestrator governance;
- cryptomining/anomaly detection;
- a UI demo that fakes enforcement;
- a system whose "enforcement" is actually just logging or advisory.

See [`SECURITY_MODEL.md`](SECURITY_MODEL.md) for the exact supported
threat boundary this claim is held to, and
[`PRODUCT_CONSTITUTION.md`](PRODUCT_CONSTITUTION.md) for the full set of
product/architecture invariants this North Star implies.
