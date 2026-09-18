//! `eltanin-agentd` — the local authorization agent daemon binary
//! (F-M1-006, HORO-840).
//!
//! Environment-variable configuration only; F-M1-008 owns the real
//! `eltanin` CLI, this binary is a thin, directly-runnable composition
//! of `eltanin-agent`'s library modules for that ticket (and for manual
//! testing) to depend on.
//!
//! A binary crate root is a separate crate from `eltanin-agent`'s
//! library target — `lib.rs`'s `#![forbid(unsafe_code)]` does not reach
//! here, so it is restated explicitly.
#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use eltanin_agent::authz::audit::AuditEventSink;
use eltanin_agent::authz::event::{EventSink, StderrSink};
use eltanin_agent::authz::session::SessionRequirement;
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler, RevocationRequirement};
use eltanin_agent::config::{AgentConfig, DEFAULT_SOCKET_PATH};
use eltanin_agent::peer::OsPeerContextSource;
use eltanin_agent::runtime::{issuer_instance_id, AgentClock};
use eltanin_agent::{authz, daemon};
use eltanin_backend::fake::FakeBackend;
use eltanin_core::resource::{
    AcceleratorMemory, Capability, ProtectedResource, ResourceCapabilities,
};
use eltanin_protocol::response::EnforcementMode;

/// Required environment variables have no default: each names a
/// security-relevant choice (socket mode, lease ttl) or a value this
/// binary cannot safely guess (which policy to load) — same "no silent
/// default" stance as [`AgentConfig::new`]'s `socket_mode` parameter.
fn required_var(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("required environment variable {name} is not set"))
}

/// Parse a boolean-shaped gate-enablement env var. Absent means disabled
/// (the same "no gate active unless a deployment opts in" default every
/// `AuthorizationConfig` requirement already has — HORO-797 prep). Unlike
/// `ELTANIN_AGENT_MODE`'s enum-shaped values, `"1"`/`"true"` is this
/// binary's first boolean-shaped env var, so there is no existing
/// convention to mirror; any other set value is a startup-time
/// configuration error, exactly like `ELTANIN_AGENT_MODE`'s own handling
/// of an unrecognized value, rather than silently treated as false.
fn required_flag(name: &str) -> Result<bool, String> {
    match env::var(name) {
        Ok(value) => match value.as_str() {
            "1" | "true" => Ok(true),
            other => Err(format!(
                "{name} {other:?} is not valid — expected \"1\" or \"true\" to enable, or leave \
                 unset to disable"
            )),
        },
        Err(_) => Ok(false),
    }
}

/// Apply the session/approval/revocation gate env vars (HORO-797 prep)
/// on top of `config`'s already-set lease ttl and enforcement mode. Split
/// out of `run` purely to keep that function under `clippy::too_many_lines`
/// — every one of these gates is operator-opt-in, `NotRequired`/disabled
/// by default, mirroring `AuthorizationConfig::new`'s own blast-radius
/// discipline for every requirement it defaults, so none of this changes
/// behavior for a deployment that never sets these env vars.
fn configure_gates(mut config: AuthorizationConfig) -> Result<AuthorizationConfig, String> {
    let session_required = required_flag("ELTANIN_AGENT_SESSION_REQUIRED")?;
    let revocation_required = required_flag("ELTANIN_AGENT_REVOCATION_REQUIRED")?;
    let approval_required = required_flag("ELTANIN_AGENT_APPROVAL_REQUIRED")?;
    let approval_store = env::var_os("ELTANIN_AGENT_APPROVAL_STORE");
    let gate_config_path = env::var_os("ELTANIN_AGENT_GATE_CONFIG");

    if session_required {
        config = config.with_session_requirement(SessionRequirement::Required);
    }

    if revocation_required {
        config = config.with_revocation_requirement(RevocationRequirement::Required);
    }

    // `AuthorizationConfig::with_approval_store` is the only way to set
    // `ApprovalRequirement::Required` — there is deliberately no way to
    // require approvals without also naming a durable store path (see
    // that method's own doc), so this binary enforces the same pairing
    // at the env-var boundary rather than silently ignoring one half of
    // a half-specified configuration. `resolved_approval_store` is kept
    // (rather than discarded once `with_approval_store` is called) so
    // the delegation/step-up gate-config wiring below can reuse the
    // operator's own store path — never a store path from the
    // gate-config file itself, which deliberately has no such field.
    let resolved_approval_store: Option<PathBuf> =
        match (approval_required, approval_store) {
            (true, None) => return Err(
                "ELTANIN_AGENT_APPROVAL_REQUIRED is set but ELTANIN_AGENT_APPROVAL_STORE is not \
                 — a durable approval store path is required to enable this gate"
                    .to_string(),
            ),
            (false, Some(_)) => return Err(
                "ELTANIN_AGENT_APPROVAL_STORE is set but ELTANIN_AGENT_APPROVAL_REQUIRED is not \
                 — approvals cannot be enabled without requiring them"
                    .to_string(),
            ),
            (true, Some(path)) => {
                let path = path.into_string().map_err(|raw| {
                    format!(
                        "ELTANIN_AGENT_APPROVAL_STORE is set but not valid UTF-8: {}",
                        raw.to_string_lossy()
                    )
                })?;
                let path = PathBuf::from(path);
                config = config.with_approval_store(path.clone());
                Some(path)
            }
            (false, None) => None,
        };

    // `ELTANIN_AGENT_GATE_CONFIG` (HORO-1278) exposes the bounded
    // compute delegation (F-M2-003) and risk-based step-up (F-M2-004)
    // gates, both fully implemented and Track-A-tested but previously
    // reachable only by a caller embedding `eltanin-agent` as a
    // library. Both `AuthorizationConfig::with_delegation`/
    // `with_step_up` also flip `approval_requirement`/
    // `approval_store_path` as a side effect — resolved here from the
    // operator's own `ELTANIN_AGENT_APPROVAL_REQUIRED`/
    // `ELTANIN_AGENT_APPROVAL_STORE` pair, never from the gate-config
    // file — so an operator who names a gate-config file without also
    // requiring approvals must be refused, not silently opted into an
    // approval gate they never asked for.
    if let Some(gate_config_path) = gate_config_path {
        let Some(approval_store) = resolved_approval_store else {
            return Err(
                "ELTANIN_AGENT_GATE_CONFIG is set but ELTANIN_AGENT_APPROVAL_REQUIRED and \
                 ELTANIN_AGENT_APPROVAL_STORE are not — delegation/step-up cannot be enabled \
                 without also requiring approvals with a durable store path"
                    .to_string(),
            );
        };
        let gate_config_path = gate_config_path.into_string().map_err(|raw| {
            format!(
                "ELTANIN_AGENT_GATE_CONFIG is set but not valid UTF-8: {}",
                raw.to_string_lossy()
            )
        })?;
        let gate_config_path = PathBuf::from(gate_config_path);
        let gate_config = authz::gate_config::load_gate_config(&gate_config_path).map_err(|e| {
            format!(
                "failed to load gate config {}: {e}",
                gate_config_path.display()
            )
        })?;
        if let Some(delegation) = gate_config.delegation {
            config = config.with_delegation(approval_store.clone(), delegation);
        }
        if let Some(step_up) = gate_config.step_up {
            config = config.with_step_up(approval_store.clone(), step_up);
        }
    }

    Ok(config)
}

fn run() -> Result<(), String> {
    let socket_path = env::var("ELTANIN_AGENT_SOCKET")
        .map_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH), PathBuf::from);

    let mode_str = required_var("ELTANIN_AGENT_SOCKET_MODE")?;
    let socket_mode = u32::from_str_radix(mode_str.trim_start_matches("0o"), 8)
        .map_err(|e| format!("ELTANIN_AGENT_SOCKET_MODE {mode_str:?} is not valid octal: {e}"))?;

    let policy_path = PathBuf::from(required_var("ELTANIN_AGENT_POLICY")?);
    let policy = authz::load_policy(&policy_path)
        .map_err(|e| format!("failed to load policy {}: {e}", policy_path.display()))?;

    let ttl_str = required_var("ELTANIN_AGENT_LEASE_TTL_SECS")?;
    let ttl_secs: u64 = ttl_str
        .parse()
        .map_err(|e| format!("ELTANIN_AGENT_LEASE_TTL_SECS {ttl_str:?} is not a valid u64: {e}"))?;
    // ELTANIN_AGENT_MODE is optional — its absence is not a startup
    // error, unlike the required vars above, since `Enforce` is a safe,
    // fully-backward-compatible default (F-M2-006, HORO-796 subtask 3).
    // Case-sensitive, mirroring this binary's other enum-shaped env vars
    // (there are none yet to actually mirror the casing convention of,
    // so lowercase is chosen to match the wire's own `snake_case`
    // rendering of `EnforcementMode`).
    let enforcement_mode = match env::var("ELTANIN_AGENT_MODE") {
        Ok(value) => match value.as_str() {
            "enforce" => EnforcementMode::Enforce,
            "shadow" => EnforcementMode::Shadow,
            other => {
                return Err(format!(
                    "ELTANIN_AGENT_MODE {other:?} is not valid — expected \"enforce\" or \"shadow\""
                ))
            }
        },
        Err(_) => EnforcementMode::Enforce,
    };

    let authz_config = AuthorizationConfig::new(Duration::from_secs(ttl_secs))
        .map_err(|e| format!("invalid lease ttl: {e}"))?
        .with_enforcement_mode(enforcement_mode);
    let authz_config = configure_gates(authz_config)?;

    // Fails closed by design (runtime.rs's own docs) rather than
    // degrading to a weaker instance id when this process's own start
    // token isn't kernel-observed — propagated here, never papered over.
    let instance = issuer_instance_id().map_err(|e| format!("cannot start agent: {e}"))?;

    // ELTANIN_AUDIT_LOG is optional — its absence is not a startup
    // error, unlike the required vars above, since a real audit trail
    // is additive (F-M1-009/HORO-824) over the StderrSink stopgap that
    // shipped with F-M1-006. A *set-but-non-UTF-8* value is a distinct
    // case from "unset" and must not silently fall through to the
    // stopgap sink — that would mask a real misconfiguration in the
    // switch between "real audit trail" and "no persistent audit trail
    // at all."
    let sink: Arc<dyn EventSink> = match env::var_os("ELTANIN_AUDIT_LOG") {
        None => Arc::new(StderrSink),
        Some(path) => {
            let path = path.into_string().map_err(|raw| {
                format!(
                    "ELTANIN_AUDIT_LOG is set but not valid UTF-8: {}",
                    raw.to_string_lossy()
                )
            })?;
            Arc::new(
                AuditEventSink::open(&PathBuf::from(path), instance.clone())
                    .map_err(|e| format!("failed to open audit log: {e}"))?,
            )
        }
    };

    // `FakeBackend` has no independent resource-discovery mechanism of
    // its own (unlike a real vendor backend's `discover()`), so it has
    // nothing to `enforce` on unless something seeds it — every resource
    // this policy names is seeded here, with the capabilities a real
    // backend would need for the authorization path to actually work
    // end to end (`Capability::DeviceEnforce`/`Revoke`; `discover`/`observe`
    // are always supported by `FakeBackend` regardless).
    let backend = Arc::new(FakeBackend::new());
    for resource in policy.resources() {
        backend.insert(ProtectedResource {
            identity: resource,
            capabilities: ResourceCapabilities::new([
                Capability::DeviceEnforce,
                Capability::DeviceRevoke,
            ]),
            memory: AcceleratorMemory::NotReportable,
        });
    }

    let handler = Arc::new(AuthorizationHandler::new(
        instance,
        policy,
        backend,
        Arc::new(AgentClock::new()),
        sink,
        &authz_config,
    ));

    let config = AgentConfig::new(socket_path, socket_mode);
    let report = daemon::run(config, handler, Arc::new(OsPeerContextSource))
        .map_err(|e| format!("agent startup failed: {e}"))?;
    eprintln!(
        "eltanin-agentd: shut down (drained {}, abandoned {})",
        report.drained, report.abandoned
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("eltanin-agentd: {message}");
            ExitCode::FAILURE
        }
    }
}
