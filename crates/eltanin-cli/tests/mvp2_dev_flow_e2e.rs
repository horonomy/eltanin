//! The canonical MVP 2.0 Product/Business E2E scenario (HORO-797/HORO-811):
//! the low-friction "developer flow" a real operator now gets once
//! `eltanin-agentd`'s remembered approval (F-M2-002), lease-lifecycle
//! hardening (F-M2-005), and audit/status (F-M2-006) gates are actually
//! turned on via their real `ELTANIN_AGENT_*` environment configuration
//! — not called as library functions directly
//! (`crates/eltanin-agent/tests/authz_approval.rs` etc. already do that
//! at the Track A level).
//!
//! Like `canonical_e2e.rs`, this drives the two real binaries
//! (`eltanin-agentd`, `eltanin`) against each other over a real Unix
//! Domain Socket, with a real on-disk policy file, a real on-disk
//! approval store, and a real on-disk audit log.
//!
//! # F-M2-001 (Trusted Compute Session) is deliberately NOT covered here
//!
//! A design pass for this scenario assumed `eltanin session start` (run
//! as its own short-lived process) followed by a *later*, separate
//! `eltanin run`/`eltanin session list` invocation would see the
//! established session. Empirically, it does not:
//! `eltanin-agentd`'s `session::membership_for_peer` re-collects the
//! *session-establishing peer's own pid*'s identity
//! (`candidate.anchor().leader.pid`, set from `observed.workload.pid` at
//! `CreateSession` time — see `crates/eltanin-agent/src/authz/mod.rs`'s
//! `session_establish_inputs`) on every later session-touching
//! operation, and compares it via `WorkloadIdentity::compare_process`,
//! which requires the *exact same pid* to still be alive
//! (`crates/eltanin-core/src/identity.rs::compare_process`). Since
//! `eltanin session start` is a real, distinct process that exits the
//! moment it prints its result (`crate::session::run`'s own doc: "establishes
//! it and exits"), that pid is already dead by the time any subsequent
//! `eltanin` invocation connects — confirmed live: `eltanin session
//! start` reports `SessionEstablished`, and the very next `eltanin
//! session list` (a separate process, same shell, same real POSIX
//! session) reports "no active Trusted Compute Session," not the
//! session just established. `docs/adr/0009-trusted-compute-session.md`'s
//! own "the caller's existing terminal session is the trust anchor...
//! inherited by everything spawned in that terminal" is not what the
//! shipped code does across two real CLI invocations — Track A's
//! `authz_session.rs` never catches this because its `self_peer_context()`
//! is the *same* live test-process object for the whole test, so the
//! leader never actually dies mid-test.
//!
//! This is a real product gap, not a test-authoring mistake — see
//! `docs/qa/e2e/B-M2-DEVFLOW.md`'s "Named limitations" for the full
//! writeup and the escalation this scenario's discovery triggered.
//! Changing which identity dimension a session is anchored to is a
//! product/security design decision (`.claude/CLAUDE.md` §5), not
//! something this Track B scenario (or its author) may silently work
//! around or paper over — so `COVERS` below does **not** include
//! F-M2-001, and `docs/qa/e2e/README.md`'s per-Feature table marks it
//! `BLOCKED`, not `N/A`.
//!
//! Linux and macOS (mirrors `canonical_e2e.rs`'s own file-level gate;
//! this repo's `ubuntu-latest` and `macos-latest` CI runners). Requires
//! the workspace to already be built (`cargo build --workspace`, which
//! CI always runs before `cargo test --workspace`) so `eltanin-agentd`'s
//! binary exists next to `eltanin`'s.
//!
//! **Named limitation** (see `docs/qa/e2e/B-M2-DEVFLOW.md` for the full
//! record): runs against `FakeBackend`, same as `canonical_e2e.rs` — this
//! proves the *authorization* path, not real GPU hardware enforcement.
//! F-M2-003 (delegation) and F-M2-004 (step-up) are deliberately not
//! exercised here — see that record's "Named limitations."

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;
use std::time::{Duration, Instant};

use rustix::process::{kill_process, Pid, Signal};

/// Stable Track B scenario identifier. Cited by
/// `docs/qa/e2e/B-M2-DEVFLOW.md` and `docs/qa/e2e/README.md`'s manifest
/// — see `tests/qa_governance_sync.rs` for the mechanical checks tying
/// this literal, `COVERS` below, and those two documents together. Bump
/// the trailing version if this scenario's *observable behavior*
/// changes (exit codes, commands, fixture shape) — not for a
/// wording-only edit.
pub const SCENARIO_ID: &str = "B-M2-DEVFLOW-v1";

/// Every Feature this scenario provides Track B (Product/Business E2E)
/// evidence for, per `docs/qa/e2e/B-M2-DEVFLOW.md`'s coverage table.
///
/// F-M2-001 (Trusted Compute Session) is deliberately excluded — see
/// this file's module docs above for the real product gap found while
/// building this scenario. F-M2-003 (bounded delegation) and F-M2-004
/// (risk-based step-up) are excluded because `eltanin-agentd`'s
/// `configure_gates` (as of HORO-797 prep) has no environment-variable
/// surface for either — delegation/step-up configuration remains
/// library-only, not operator-reachable from the real binary.
pub const COVERS: &[&str] = &["F-M2-002", "F-M2-005", "F-M2-006"];

/// The name `--profile` resolves in this scenario — reuses the same
/// published "gpu" profile/policy fixtures `canonical_e2e.rs` already
/// established, so this scenario and MVP 1.0's Quickstart docs can never
/// silently disagree about what a "gpu-like profile" looks like.
const PROFILE_NAME: &str = "gpu";

const POLICY_FIXTURE: &str = include_str!("fixtures/eltanin_run_example_policy.json");
const PROFILE_FIXTURE: &str = include_str!("fixtures/example_profile.json");

/// A private (`0o700`) per-test-process base directory — mirrors
/// `canonical_e2e.rs::private_base_dir` exactly and for the same reason
/// (`eltanin-agentd`'s `BoundSocket::bind` refuses to bind under a
/// world/group-writable directory like `/tmp` itself).
fn private_base_dir() -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    static INIT: Once = Once::new();
    let real_tmp = fs::canonicalize("/tmp").unwrap_or_else(|_| PathBuf::from("/tmp"));
    let base = real_tmp.join(format!(
        "eltanin-cli-mvp2-dev-flow-e2e-{}",
        std::process::id()
    ));
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
        "[{SCENARIO_ID}] expected {name} to already be built next to {}; build the whole \
         workspace first: `cargo build --workspace`",
        eltanin.display(),
    );
    path
}

fn real_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn assert_non_root_precondition(uid: u32) {
    assert_ne!(
        uid, 0,
        "[{SCENARIO_ID}] this scenario's fixture denies uid 0 outright (see \
         docs/product/POLICY_EXAMPLES.md's \"deny-root\" rule) — this scenario cannot run as \
         root; re-run as a non-root user"
    );
}

fn write_policy(dir: &Path, allow_uid: u32) -> PathBuf {
    let original = "\"expected\": 1000";
    let text = POLICY_FIXTURE.replacen(original, &format!("\"expected\": {allow_uid}"), 1);
    let path = dir.join("policy.json");
    fs::write(&path, text).expect("write policy fixture");
    path
}

fn write_profile_dir(dir: &Path) -> PathBuf {
    fs::write(dir.join(format!("{PROFILE_NAME}.json")), PROFILE_FIXTURE)
        .expect("write profile fixture");
    dir.to_path_buf()
}

/// A private, distinctly-named on-disk copy of the `eltanin` binary this
/// scenario's `eltanin` invocations run as — never the shared build
/// artifact `CARGO_BIN_EXE_eltanin` points at directly, and never the
/// same path twice within one test. `name` becomes part of this
/// launcher's absolute path, which is exactly the identity dimension
/// [`ApprovalBinding::launcher_path`](eltanin_core::approval::ApprovalBinding)
/// binds to — two different `name`s are, to the approval gate, two
/// different launchers connecting from the same real binary content.
fn copy_launcher(dir: &Path, name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let source = PathBuf::from(env!("CARGO_BIN_EXE_eltanin"));
    let dest = dir.join(name);
    fs::copy(&source, &dest).expect("copy eltanin binary into a private, named launcher path");
    let mut perms = fs::metadata(&dest)
        .expect("stat copied launcher")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&dest, perms).expect("chmod copied launcher executable");
    dest
}

/// A running `eltanin-agentd` process configured with F-M2-002's
/// approval gate and F-M2-005's revocation-capability gate required —
/// exactly the `ELTANIN_AGENT_APPROVAL_REQUIRED`+`ELTANIN_AGENT_APPROVAL_STORE`
/// / `ELTANIN_AGENT_REVOCATION_REQUIRED` environment configuration
/// `eltanin-agentd::configure_gates` (HORO-797 prep) exposes — the thing
/// that makes these two Features operator-reachable from the real
/// binary at all, not just from `AuthorizationConfig` calls in a Track A
/// test. Deliberately does **not** set `ELTANIN_AGENT_SESSION_REQUIRED`
/// — see this file's module docs for why F-M2-001 cannot be honestly
/// exercised here.
struct Agentd {
    child: Child,
    socket_path: PathBuf,
}

impl Agentd {
    /// Common setup shared by every `Agentd` constructor: a fresh policy
    /// fixture, a socket path short enough for `sun_path`, and the
    /// baseline env every configuration needs. Returns the not-yet-spawned
    /// `Command` and the socket path it will bind.
    fn base_command(dir: &Path, allow_uid: u32) -> (Command, PathBuf) {
        let policy_path = write_policy(dir, allow_uid);
        let socket_path = dir.join("agent.sock");
        assert!(
            socket_path.as_os_str().len() < 100,
            "[{SCENARIO_ID}] socket path too long for sun_path: {}",
            socket_path.display(),
        );

        let mut command = Command::new(sibling_bin("eltanin-agentd"));
        command
            .env("ELTANIN_AGENT_SOCKET", &socket_path)
            .env("ELTANIN_AGENT_SOCKET_MODE", "0600")
            .env("ELTANIN_AGENT_POLICY", &policy_path)
            .env("ELTANIN_AGENT_LEASE_TTL_SECS", "60")
            .env_remove("ELTANIN_AGENT_SESSION_REQUIRED")
            .env_remove("ELTANIN_AGENT_APPROVAL_REQUIRED")
            .env_remove("ELTANIN_AGENT_APPROVAL_STORE")
            .env_remove("ELTANIN_AGENT_REVOCATION_REQUIRED")
            .env_remove("ELTANIN_AUDIT_LOG")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        (command, socket_path)
    }

    fn start(dir: &Path, allow_uid: u32, approval_store: &Path, audit_log: Option<&Path>) -> Self {
        let (mut command, socket_path) = Self::base_command(dir, allow_uid);
        command
            .env("ELTANIN_AGENT_APPROVAL_REQUIRED", "1")
            .env("ELTANIN_AGENT_APPROVAL_STORE", approval_store)
            .env("ELTANIN_AGENT_REVOCATION_REQUIRED", "1");
        if let Some(log) = audit_log {
            command.env("ELTANIN_AUDIT_LOG", log);
        }

        let child = command.spawn().expect("spawn eltanin-agentd");
        Self { child, socket_path }.wait_for_socket()
    }

    /// A running `eltanin-agentd` configured with **only** F-M2-001's
    /// session gate required (`ELTANIN_AGENT_SESSION_REQUIRED=1`) —
    /// deliberately no approval/revocation gate, so a denial in the
    /// ground-truth regression tests below can only mean the session
    /// gate itself, never a different, unrelated gate this scenario
    /// isn't testing. This is the constructor that actually exercises
    /// the real product bug HORO-1278 fixes — see this file's module
    /// docs for why the plain `start` above never sets this env var.
    fn start_session_required(dir: &Path, allow_uid: u32) -> Self {
        let (mut command, socket_path) = Self::base_command(dir, allow_uid);
        command.env("ELTANIN_AGENT_SESSION_REQUIRED", "1");
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
                    "[{SCENARIO_ID}] eltanin-agentd exited early ({status}) before creating its \
                     socket at {} — stderr: {stderr}",
                    self.socket_path.display(),
                );
            }
            assert!(
                Instant::now() < deadline,
                "[{SCENARIO_ID}] eltanin-agentd did not create its socket within 5s at {}",
                self.socket_path.display(),
            );
            std::thread::sleep(Duration::from_millis(20));
        }
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

/// Build (but do not run) an `eltanin <args...>` command through
/// `launcher`.
fn eltanin_command(launcher: &Path, agent: &Agentd, profile_dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(launcher);
    command
        .env("ELTANIN_AGENT_SOCKET", &agent.socket_path)
        .env("ELTANIN_PROFILE_DIR", profile_dir)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn approve_remember(launcher: &Path, agent: &Agentd, profile_dir: &Path) -> std::process::Output {
    eltanin_command(
        launcher,
        agent,
        profile_dir,
        &["approve", "--profile", PROFILE_NAME, "--remember"],
    )
    .output()
    .expect("run `eltanin approve --remember`")
}

fn run_workload(
    launcher: &Path,
    agent: &Agentd,
    profile_dir: &Path,
    sentinel: &str,
) -> std::process::Output {
    eltanin_command(
        launcher,
        agent,
        profile_dir,
        &["run", "--profile", PROFILE_NAME, "--", "echo", sentinel],
    )
    .output()
    .expect("run `eltanin run`")
}

fn eltanin_status(launcher: &Path, agent: &Agentd) -> std::process::Output {
    Command::new(launcher)
        .env("ELTANIN_AGENT_SOCKET", &agent.socket_path)
        .arg("status")
        .output()
        .expect("run `eltanin status`")
}

/// #1: once an intent is remembered for a launcher, every subsequent
/// `eltanin run` for the same profile *through that same launcher* is
/// granted with no further prompt — the low-friction claim this
/// scenario exists to machine-assert, not just document. `eltanin
/// status` also discloses the real enforcement posture this journey ran
/// under, including that the session gate is (honestly) not active
/// here.
#[test]
fn low_friction_repeated_runs_grant_every_request_with_zero_additional_prompts() {
    let uid = real_euid();
    assert_non_root_precondition(uid);

    let dir = scenario_dir("low-friction");
    let approval_store = dir.join("approvals.json");
    let agent = Agentd::start(&dir, uid, &approval_store, None);
    let profile_dir = write_profile_dir(&dir);
    let launcher = copy_launcher(&dir, "eltanin-launcher");

    let status = eltanin_status(&launcher, &agent);
    assert!(status.status.success(), "eltanin status must succeed");
    let status_stdout = String::from_utf8_lossy(&status.stdout);
    assert!(status_stdout.contains("enforce"), "got: {status_stdout}");
    assert!(
        status_stdout.contains("session required: NO")
            && status_stdout.contains("approval required: yes")
            && status_stdout.contains("revocation required: yes"),
        "[{SCENARIO_ID}] `eltanin status` must disclose the real posture this journey runs \
         under: no session gate (F-M2-001 is not exercised here — see this file's module docs), \
         approval required, revocation required — got: {status_stdout}",
    );

    let approve = approve_remember(&launcher, &agent, &profile_dir);
    assert!(
        approve.status.success(),
        "[{SCENARIO_ID}] `eltanin approve --remember` must succeed (F-M2-002) — stderr={:?}",
        String::from_utf8_lossy(&approve.stderr),
    );

    // Three independent `eltanin run` invocations, none of which may
    // hit any pre-policy gate a second time — the actual "zero
    // additional prompts" claim, machine-asserted by scanning every
    // run's stderr for the exact denial-reason phrases
    // `describe_denial_reason` would print for ApprovalRequired.
    for (n, sentinel) in ["run-one", "run-two", "run-three"].iter().enumerate() {
        let output = run_workload(&launcher, &agent, &profile_dir, sentinel);
        assert!(
            output.status.success(),
            "[{SCENARIO_ID}] run #{n} ({sentinel}) must be granted with zero additional \
             prompts — got exit {:?}, stderr={:?}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(sentinel),
            "[{SCENARIO_ID}] the authorized workload's own stdout must pass through `eltanin \
             run` verbatim, got: {:?}",
            String::from_utf8_lossy(&output.stdout),
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("no remembered approval matches"),
            "[{SCENARIO_ID}] run #{n} ({sentinel}) must not re-trigger the approval gate — this \
             is the scenario's core low-friction claim, violated: {stderr:?}",
        );
    }
}

/// #2 (Quickstart's trust-transition step): a launcher whose identity
/// changes after being remembered is re-evaluated, never trusted from
/// stored bytes (F-M2-002's core safety argument) — denied until
/// re-approved, and the denial is explainable via real `eltanin
/// audit`/`eltanin explain` output correlated to the real pid that was
/// denied (F-M2-006).
///
/// The identity change exercised here is the launcher's *path*, not its
/// content: a copy of the exact same `eltanin` binary at a second,
/// distinct absolute path is — to `ApprovalBinding::launcher_path` — a
/// different launcher, exactly the way a stale symlink retarget or a
/// binary reinstalled to a new location would be in real use. This
/// scenario does not attempt to mutate the launcher's on-disk bytes and
/// re-execute it (portable, digest-specific detection of *that* case
/// remains Track-A-only:
/// `authz_approval.rs::a_changed_executable_digest_is_reevaluated_and_denied`)
/// — see `docs/qa/e2e/B-M2-DEVFLOW.md`'s "Named limitations."
#[test]
fn a_changed_launcher_identity_is_denied_then_recovers_and_is_explainable() {
    let uid = real_euid();
    assert_non_root_precondition(uid);

    let dir = scenario_dir("trust-transition");
    let approval_store = dir.join("approvals.json");
    let audit_log = dir.join("audit.ndjson");
    let agent = Agentd::start(&dir, uid, &approval_store, Some(&audit_log));
    let profile_dir = write_profile_dir(&dir);
    let launcher_a = copy_launcher(&dir, "eltanin-launcher-a");
    let launcher_b = copy_launcher(&dir, "eltanin-launcher-b");

    let approve = approve_remember(&launcher_a, &agent, &profile_dir);
    assert!(approve.status.success(), "initial approve must succeed");

    let before = run_workload(&launcher_a, &agent, &profile_dir, "before-identity-change");
    assert!(
        before.status.success(),
        "[{SCENARIO_ID}] the first run, through the approved launcher, must be granted — \
         stderr={:?}",
        String::from_utf8_lossy(&before.stderr),
    );

    // The trust transition: the exact same binary content, a different
    // launcher path.
    let denied_child = eltanin_command(
        &launcher_b,
        &agent,
        &profile_dir,
        &["run", "--profile", PROFILE_NAME, "--", "true"],
    )
    .spawn()
    .expect("spawn eltanin run for the denied leg");
    let denied_pid = denied_child.id();
    let denied = denied_child
        .wait_with_output()
        .expect("wait for denied eltanin run");

    assert_eq!(
        denied.status.code(),
        Some(77),
        "[{SCENARIO_ID}] a run through a launcher whose path differs from the one approved must \
         be denied (F-M2-002) — got exit {:?}, stderr={:?}",
        denied.status.code(),
        String::from_utf8_lossy(&denied.stderr),
    );
    let denied_stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(
        denied_stderr.contains("no remembered approval matches this launcher/context")
            && denied_stderr.contains("eltanin approve --profile <name> --remember"),
        "[{SCENARIO_ID}] the denial must name ApprovalRequired's own message/next action, not a \
         generic failure — got: {denied_stderr:?}",
    );

    // Recovery: approving the new launcher path lifts the denial.
    let reapprove = approve_remember(&launcher_b, &agent, &profile_dir);
    assert!(
        reapprove.status.success(),
        "[{SCENARIO_ID}] approving the new launcher path must succeed — stderr={:?}",
        String::from_utf8_lossy(&reapprove.stderr),
    );

    let after = run_workload(&launcher_b, &agent, &profile_dir, "after-reapproval");
    assert!(
        after.status.success(),
        "[{SCENARIO_ID}] a run through the newly-approved launcher must be granted again — \
         stderr={:?}",
        String::from_utf8_lossy(&after.stderr),
    );

    // Correlate the denial via the real `eltanin explain`/`eltanin
    // audit` subcommands (F-M2-006) against the real audit log
    // `eltanin-agentd` wrote — not a scripted fixture.
    assert_denial_is_explainable_via_audit_and_explain(
        &launcher_a,
        &agent,
        &profile_dir,
        &audit_log,
        denied_pid,
    );
}

/// The audit/explain correlation half of
/// [`a_changed_launcher_identity_is_denied_then_recovers_and_is_explainable`]
/// — split out only to stay under this crate's line-count lint, not a
/// reusable seam.
fn assert_denial_is_explainable_via_audit_and_explain(
    launcher: &Path,
    agent: &Agentd,
    profile_dir: &Path,
    audit_log: &Path,
    denied_pid: u32,
) {
    let explain = eltanin_command(
        launcher,
        agent,
        profile_dir,
        &[
            "explain",
            "--pid",
            &denied_pid.to_string(),
            "--log",
            audit_log.to_str().expect("utf-8 audit log path"),
        ],
    )
    .output()
    .expect("run `eltanin explain`");
    assert!(
        explain.status.success(),
        "[{SCENARIO_ID}] `eltanin explain --pid {denied_pid}` must succeed — stderr={:?}",
        String::from_utf8_lossy(&explain.stderr),
    );
    let explain_stdout = String::from_utf8_lossy(&explain.stdout);
    assert!(
        explain_stdout.contains(&format!("pid={denied_pid}"))
            && explain_stdout.contains("ApprovalRequired"),
        "[{SCENARIO_ID}] `eltanin explain --pid {denied_pid}` must produce a real decision \
         record naming this denial's actual pid and reason — got: {explain_stdout:?}",
    );

    let audit = eltanin_command(
        launcher,
        agent,
        profile_dir,
        &[
            "audit",
            "--log",
            audit_log.to_str().expect("utf-8 audit log path"),
        ],
    )
    .output()
    .expect("run `eltanin audit`");
    assert!(audit.status.success(), "eltanin audit must succeed");
    let audit_stdout = String::from_utf8_lossy(&audit.stdout);
    assert!(
        audit_stdout.contains("RequestLease") && audit_stdout.contains("Approve"),
        "[{SCENARIO_ID}] `eltanin audit` must show this journey's real operations (at least an \
         Approve and a RequestLease entry) — got: {audit_stdout:?}",
    );
}

// HORO-1278 ground-truth regression tests — ADDITIONAL to `SCENARIO_ID`/
// `COVERS` above, not a replacement for either. These tests do NOT
// change this file's `COVERS` const (docs/qa/e2e/README.md's manifest
// and the Track B scenario record are updated by a later PR in this
// ticket's decomposition, per `.claude/CLAUDE.md`'s Docs Impact Gate —
// out of scope here) and do not touch the module docs above describing
// why F-M2-001 was previously excluded from Track B: that history is
// accurate as a record of the bug this ticket fixes. What follows is
// the machine-asserted proof that the fix actually closes the gap that
// history describes — every `eltanin` invocation below is spawned as a
// genuinely separate process and `.wait()`ed to completion before the
// next one runs, so no invocation's own process ever stays alive to
// paper over the exact anchoring bug HORO-1278 exists to fix.

const SESSION_PROFILE_TTL: &str = "1h";

fn session_start(launcher: &Path, agent: &Agentd, profile_dir: &Path) -> std::process::Output {
    eltanin_command(
        launcher,
        agent,
        profile_dir,
        &[
            "session",
            "start",
            "--profile",
            PROFILE_NAME,
            "--ttl",
            SESSION_PROFILE_TTL,
        ],
    )
    .spawn()
    .expect("spawn `eltanin session start`")
    .wait_with_output()
    .expect("wait for `eltanin session start`")
}

fn session_list(launcher: &Path, agent: &Agentd, profile_dir: &Path) -> std::process::Output {
    eltanin_command(launcher, agent, profile_dir, &["session", "list"])
        .spawn()
        .expect("spawn `eltanin session list`")
        .wait_with_output()
        .expect("wait for `eltanin session list`")
}

fn session_end(launcher: &Path, agent: &Agentd, profile_dir: &Path) -> std::process::Output {
    eltanin_command(launcher, agent, profile_dir, &["session", "end"])
        .spawn()
        .expect("spawn `eltanin session end`")
        .wait_with_output()
        .expect("wait for `eltanin session end`")
}

/// #3 (HORO-1278 ground truth): a Trusted Compute Session established by
/// one, short-lived `eltanin session start` process — which exits the
/// moment it prints its result, exactly like the real CLI always does —
/// must be honored by every *later, separate* `eltanin` invocation in
/// the same POSIX session (this test process's own session, which every
/// child below inherits by ordinary fork/exec, never `setsid()`). Before
/// HORO-1278's fix, `eltanin-agentd` anchored the session to the
/// connecting peer's own identity — i.e. `eltanin session start`'s own
/// pid — so this exact scenario denied every later invocation outright;
/// this test is the one that must have failed against the unmodified
/// pre-fix code (confirmed manually before implementing the fix; see
/// this PR's own description/commit history for that record) and must
/// pass now.
#[test]
fn f_m2_001_a_session_established_by_one_process_is_honored_by_later_separate_invocations() {
    let uid = real_euid();
    assert_non_root_precondition(uid);

    let dir = scenario_dir("f-m2-001-session-survives");
    let agent = Agentd::start_session_required(&dir, uid);
    let profile_dir = write_profile_dir(&dir);
    let launcher = copy_launcher(&dir, "eltanin-launcher");

    let start = session_start(&launcher, &agent, &profile_dir);
    assert!(
        start.status.success(),
        "[{SCENARIO_ID}] `eltanin session start` must succeed — stderr={:?}",
        String::from_utf8_lossy(&start.stderr),
    );

    let list = session_list(&launcher, &agent, &profile_dir);
    assert!(
        list.status.success(),
        "[{SCENARIO_ID}] `eltanin session list` must succeed — stderr={:?}",
        String::from_utf8_lossy(&list.stderr),
    );
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(
        !list_stdout.contains("no active Trusted Compute Session"),
        "[{SCENARIO_ID}] a session established by a now-exited separate process must be \
         reported by a later, separate `eltanin session list` invocation — got: {list_stdout:?}",
    );

    for (n, sentinel) in ["run-one", "run-two"].iter().enumerate() {
        let run = run_workload(&launcher, &agent, &profile_dir, sentinel);
        assert!(
            run.status.success(),
            "[{SCENARIO_ID}] run #{n} ({sentinel}) through a separate process in the \
             session-established POSIX session must be granted — got exit {:?}, stderr={:?}",
            run.status.code(),
            String::from_utf8_lossy(&run.stderr),
        );
        assert!(
            String::from_utf8_lossy(&run.stdout).contains(sentinel),
            "[{SCENARIO_ID}] the authorized workload's own stdout must pass through verbatim, \
             got: {:?}",
            String::from_utf8_lossy(&run.stdout),
        );
    }
}

/// #4 (HORO-1278): `eltanin session end`, itself run as yet another
/// separate process, must fail closed — a run after it must be denied,
/// never silently still-granted because some stale in-process state
/// survived.
#[test]
fn f_m2_001_session_end_from_a_later_separate_process_fails_closed() {
    let uid = real_euid();
    assert_non_root_precondition(uid);

    let dir = scenario_dir("f-m2-001-session-end");
    let agent = Agentd::start_session_required(&dir, uid);
    let profile_dir = write_profile_dir(&dir);
    let launcher = copy_launcher(&dir, "eltanin-launcher");

    let start = session_start(&launcher, &agent, &profile_dir);
    assert!(
        start.status.success(),
        "`eltanin session start` must succeed"
    );

    let before = run_workload(&launcher, &agent, &profile_dir, "before-end");
    assert!(
        before.status.success(),
        "[{SCENARIO_ID}] a run before `session end` must be granted — stderr={:?}",
        String::from_utf8_lossy(&before.stderr),
    );

    let end = session_end(&launcher, &agent, &profile_dir);
    assert!(
        end.status.success(),
        "[{SCENARIO_ID}] `eltanin session end` must succeed — stderr={:?}",
        String::from_utf8_lossy(&end.stderr),
    );

    let after = run_workload(&launcher, &agent, &profile_dir, "after-end");
    assert_eq!(
        after.status.code(),
        Some(77),
        "[{SCENARIO_ID}] a run after `eltanin session end` (a separate process) must be denied \
         — got exit {:?}, stderr={:?}",
        after.status.code(),
        String::from_utf8_lossy(&after.stderr),
    );
}

/// #5 (HORO-1278): a session established with a short TTL must deny a
/// later, separate `eltanin run` once it has genuinely expired, and
/// `eltanin session list` must honestly report no active session — not
/// merely "the establishing process is still observable," which is
/// exactly the wrong signal this ticket removes from the trust
/// decision.
#[test]
fn f_m2_001_an_expired_session_denies_a_later_separate_run() {
    let uid = real_euid();
    assert_non_root_precondition(uid);

    let dir = scenario_dir("f-m2-001-session-expiry");
    let agent = Agentd::start_session_required(&dir, uid);
    let profile_dir = write_profile_dir(&dir);
    let launcher = copy_launcher(&dir, "eltanin-launcher");

    let start = eltanin_command(
        &launcher,
        &agent,
        &profile_dir,
        &["session", "start", "--profile", PROFILE_NAME, "--ttl", "1"],
    )
    .spawn()
    .expect("spawn `eltanin session start`")
    .wait_with_output()
    .expect("wait for `eltanin session start`");
    assert!(
        start.status.success(),
        "[{SCENARIO_ID}] `eltanin session start --ttl 1` must succeed — stderr={:?}",
        String::from_utf8_lossy(&start.stderr),
    );

    // Sleep past the 1-second TTL. Nothing here re-uses the establishing
    // process — it has already exited by the time this sleep starts.
    std::thread::sleep(Duration::from_millis(1500));

    let run = run_workload(&launcher, &agent, &profile_dir, "after-expiry");
    assert_eq!(
        run.status.code(),
        Some(77),
        "[{SCENARIO_ID}] a run after the session's own TTL has elapsed (a separate process) \
         must be denied — got exit {:?}, stderr={:?}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr),
    );

    let list = session_list(&launcher, &agent, &profile_dir);
    assert!(list.status.success(), "`eltanin session list` must succeed");
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(
        list_stdout.contains("no active Trusted Compute Session"),
        "[{SCENARIO_ID}] an expired session must be honestly reported as gone, not just denied \
         at the run gate — got: {list_stdout:?}",
    );
}
