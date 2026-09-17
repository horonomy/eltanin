//! Real-binary coverage for the session/approval/revocation gate env
//! vars `eltanin-agentd` reads at startup (HORO-797 prep — see the
//! Critical defect this ticket's prep work fixes: these gates were
//! library-reachable via `AuthorizationConfig::with_session_requirement`/
//! `with_approval_store`/`with_revocation_requirement` but had no
//! operator-facing way to enable them).
//!
//! Mirrors `canonical_e2e.rs`'s "drive the real binaries over a real
//! Unix Domain Socket" approach (a minimal, purpose-built subset of the
//! same scaffolding — this file does not touch or depend on that file),
//! since the env vars are parsed inside `eltanin-agentd`'s own
//! `fn main`/`fn run`, which is not a `pub` library function this crate
//! could otherwise call directly. `eltanin status`'s
//! `session_required`/`approval_required`/`revocation_required`
//! disclosure (also added by this ticket) is the observable proof that
//! each env var actually reached the constructed
//! `eltanin_agent::authz::AuthorizationConfig` — the same wire path a
//! real operator would use to check this.
//!
//! Linux and macOS only, mirroring `canonical_e2e.rs`'s own gate — both
//! spawn real Unix Domain Socket agent processes.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;
use std::time::{Duration, Instant};

use rustix::process::{kill_process, Pid, Signal};

const POLICY_FIXTURE: &str = include_str!("fixtures/eltanin_run_example_policy.json");

static INIT: Once = Once::new();

fn private_base_dir() -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let real_tmp = std::env::temp_dir();
    // Short prefix deliberately: this path's full length (base dir +
    // scenario tag + "/agent.sock") must clear `sun_path`'s ~100-byte
    // platform limit — see `Agentd::start`'s own length assertion below.
    let base = real_tmp.join(format!("elt-agtd-gate-{}", std::process::id()));
    INIT.call_once(|| {
        fs::create_dir_all(&base).expect("create private test base dir");
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700))
            .expect("chmod private test base dir");
    });
    base
}

fn scenario_dir(tag: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = private_base_dir().join(format!("{tag}-{n}"));
    fs::create_dir_all(&dir).expect("create scenario dir");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod scenario dir");
    dir
}

/// Resolve `name`'s binary path as a build sibling of the `eltanin`
/// binary this test binary already gets via `CARGO_BIN_EXE_eltanin` —
/// see `canonical_e2e.rs::sibling_bin`'s identical rationale.
fn sibling_bin(name: &str) -> PathBuf {
    let eltanin = PathBuf::from(env!("CARGO_BIN_EXE_eltanin"));
    let dir = eltanin.parent().expect("eltanin binary has a parent dir");
    let path = dir.join(name);
    assert!(
        path.exists(),
        "expected {name} to already be built next to {}; build the whole workspace first: \
         `cargo build --workspace`",
        eltanin.display(),
    );
    path
}

fn write_policy(dir: &Path) -> PathBuf {
    let path = dir.join("policy.json");
    fs::write(&path, POLICY_FIXTURE).expect("write policy fixture");
    path
}

/// A running `eltanin-agentd` process, killed on drop.
struct Agentd {
    child: Child,
    socket_path: PathBuf,
}

/// Optional gate env vars for one [`Agentd::start`] call — every field
/// `None` reproduces this ticket's own "no gate active unless a
/// deployment opts in" default.
#[derive(Default)]
struct GateEnv<'a> {
    session_required: Option<&'a str>,
    approval_required: Option<&'a str>,
    approval_store: Option<&'a Path>,
    revocation_required: Option<&'a str>,
}

impl Agentd {
    fn start(dir: &Path, gates: &GateEnv<'_>) -> Self {
        let policy_path = write_policy(dir);
        let socket_path = dir.join("agent.sock");
        assert!(
            socket_path.as_os_str().len() < 100,
            "socket path too long for sun_path: {}",
            socket_path.display(),
        );

        let mut command = Command::new(sibling_bin("eltanin-agentd"));
        command
            .env("ELTANIN_AGENT_SOCKET", &socket_path)
            .env("ELTANIN_AGENT_SOCKET_MODE", "0600")
            .env("ELTANIN_AGENT_POLICY", &policy_path)
            .env("ELTANIN_AGENT_LEASE_TTL_SECS", "60")
            .env_remove("ELTANIN_AUDIT_LOG")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(value) = gates.session_required {
            command.env("ELTANIN_AGENT_SESSION_REQUIRED", value);
        }
        if let Some(value) = gates.approval_required {
            command.env("ELTANIN_AGENT_APPROVAL_REQUIRED", value);
        }
        if let Some(path) = gates.approval_store {
            command.env("ELTANIN_AGENT_APPROVAL_STORE", path);
        }
        if let Some(value) = gates.revocation_required {
            command.env("ELTANIN_AGENT_REVOCATION_REQUIRED", value);
        }

        let child = command.spawn().expect("spawn eltanin-agentd");
        Self { child, socket_path }.wait_for_socket()
    }

    fn wait_for_socket(mut self) -> Self {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if self.socket_path.exists() {
                return self;
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                let mut stderr = String::new();
                if let Some(mut s) = self.child.stderr.take() {
                    let _ = s.read_to_string(&mut stderr);
                }
                panic!(
                    "eltanin-agentd exited early ({status}) before creating its socket at {} — \
                     stderr: {stderr}",
                    self.socket_path.display(),
                );
            }
            assert!(
                Instant::now() < deadline,
                "eltanin-agentd did not create its socket within 5s at {}",
                self.socket_path.display(),
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Spawn `eltanin-agentd` and assert it refuses to start, returning
    /// its stderr — for the misconfiguration cases this ticket's env-var
    /// pairing validation rejects at startup.
    fn expect_startup_failure(dir: &Path, gates: &GateEnv<'_>) -> String {
        let policy_path = write_policy(dir);
        let socket_path = dir.join("agent.sock");

        let mut command = Command::new(sibling_bin("eltanin-agentd"));
        command
            .env("ELTANIN_AGENT_SOCKET", &socket_path)
            .env("ELTANIN_AGENT_SOCKET_MODE", "0600")
            .env("ELTANIN_AGENT_POLICY", &policy_path)
            .env("ELTANIN_AGENT_LEASE_TTL_SECS", "60")
            .env_remove("ELTANIN_AUDIT_LOG")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(value) = gates.session_required {
            command.env("ELTANIN_AGENT_SESSION_REQUIRED", value);
        }
        if let Some(value) = gates.approval_required {
            command.env("ELTANIN_AGENT_APPROVAL_REQUIRED", value);
        }
        if let Some(path) = gates.approval_store {
            command.env("ELTANIN_AGENT_APPROVAL_STORE", path);
        }
        if let Some(value) = gates.revocation_required {
            command.env("ELTANIN_AGENT_REVOCATION_REQUIRED", value);
        }

        let output = command.output().expect("run eltanin-agentd");
        assert!(
            !output.status.success(),
            "expected eltanin-agentd to refuse to start with this misconfiguration, got: {:?}",
            output.status
        );
        String::from_utf8_lossy(&output.stderr).into_owned()
    }
}

impl Drop for Agentd {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return;
        }
        if let Some(pid) = i32::try_from(self.child.id()).ok().and_then(Pid::from_raw) {
            let _ = kill_process(pid, Signal::TERM);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return;
                }
            }
        }
    }
}

fn eltanin_status(agent: &Agentd) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_eltanin"))
        .env("ELTANIN_AGENT_SOCKET", &agent.socket_path)
        .arg("status")
        .output()
        .expect("run eltanin binary");
    assert_eq!(output.status.code(), Some(0), "stderr: {:?}", output.stderr);
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn no_gate_env_vars_set_reports_every_gate_not_required() {
    let dir = scenario_dir("none");
    let agent = Agentd::start(&dir, &GateEnv::default());
    let stdout = eltanin_status(&agent);
    assert!(stdout.contains("session required: NO"), "got: {stdout}");
    assert!(stdout.contains("approval required: NO"), "got: {stdout}");
    assert!(stdout.contains("revocation required: NO"), "got: {stdout}");
}

#[test]
fn eltanin_agent_session_required_reaches_authorization_config() {
    let dir = scenario_dir("session");
    let agent = Agentd::start(
        &dir,
        &GateEnv {
            session_required: Some("true"),
            ..GateEnv::default()
        },
    );
    let stdout = eltanin_status(&agent);
    assert!(stdout.contains("session required: yes"), "got: {stdout}");
}

#[test]
fn eltanin_agent_revocation_required_reaches_authorization_config() {
    let dir = scenario_dir("revocation");
    let agent = Agentd::start(
        &dir,
        &GateEnv {
            revocation_required: Some("1"),
            ..GateEnv::default()
        },
    );
    let stdout = eltanin_status(&agent);
    assert!(stdout.contains("revocation required: yes"), "got: {stdout}");
}

#[test]
fn eltanin_agent_approval_required_and_store_reach_authorization_config() {
    let dir = scenario_dir("approval");
    let store_path = dir.join("approvals.json");
    let agent = Agentd::start(
        &dir,
        &GateEnv {
            approval_required: Some("true"),
            approval_store: Some(&store_path),
            ..GateEnv::default()
        },
    );
    let stdout = eltanin_status(&agent);
    assert!(stdout.contains("approval required: yes"), "got: {stdout}");
}

#[test]
fn approval_required_without_a_store_path_refuses_to_start() {
    let dir = scenario_dir("approval-no-store");
    let stderr = Agentd::expect_startup_failure(
        &dir,
        &GateEnv {
            approval_required: Some("true"),
            ..GateEnv::default()
        },
    );
    assert!(
        stderr.contains("ELTANIN_AGENT_APPROVAL_STORE"),
        "got: {stderr}"
    );
}

#[test]
fn an_approval_store_without_requiring_approval_refuses_to_start() {
    let dir = scenario_dir("store-no-required");
    let store_path = dir.join("approvals.json");
    let stderr = Agentd::expect_startup_failure(
        &dir,
        &GateEnv {
            approval_store: Some(&store_path),
            ..GateEnv::default()
        },
    );
    assert!(
        stderr.contains("ELTANIN_AGENT_APPROVAL_REQUIRED"),
        "got: {stderr}"
    );
}

#[test]
fn an_unrecognized_boolean_flag_value_refuses_to_start() {
    let dir = scenario_dir("bad-bool");
    let stderr = Agentd::expect_startup_failure(
        &dir,
        &GateEnv {
            revocation_required: Some("yes-please"),
            ..GateEnv::default()
        },
    );
    assert!(
        stderr.contains("ELTANIN_AGENT_REVOCATION_REQUIRED"),
        "got: {stderr}"
    );
}
