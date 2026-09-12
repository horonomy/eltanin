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
use eltanin_agent::authz::{AuthorizationConfig, AuthorizationHandler};
use eltanin_agent::config::{AgentConfig, DEFAULT_SOCKET_PATH};
use eltanin_agent::peer::LinuxPeerContextSource;
use eltanin_agent::runtime::{issuer_instance_id, AgentClock};
use eltanin_agent::{authz, daemon};
use eltanin_backend::fake::FakeBackend;
use eltanin_core::resource::{AcceleratorMemory, Capability, ProtectedResource, ResourceCapabilities};

/// Required environment variables have no default: each names a
/// security-relevant choice (socket mode, lease ttl) or a value this
/// binary cannot safely guess (which policy to load) — same "no silent
/// default" stance as [`AgentConfig::new`]'s `socket_mode` parameter.
fn required_var(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("required environment variable {name} is not set"))
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
    let authz_config = AuthorizationConfig::new(Duration::from_secs(ttl_secs))
        .map_err(|e| format!("invalid lease ttl: {e}"))?;

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
            capabilities: ResourceCapabilities::new([Capability::DeviceEnforce, Capability::DeviceRevoke]),
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
    let report = daemon::run(config, handler, Arc::new(LinuxPeerContextSource))
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
