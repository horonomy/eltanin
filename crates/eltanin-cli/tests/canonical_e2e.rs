//! The canonical Product/Business E2E scenario for F-M1-008 (HORO-847):
//! the ALLOW and DENY `eltanin run` journeys this repo's user-facing
//! Quickstart (`docs/product/QUICKSTART.md`) documents, and the "Track
//! B" evidence `docs/qa/e2e/F-M1-008-controlled-launch.md` cites.
//!
//! Unlike `launch_lifecycle.rs` (which drives `eltanin` against a
//! scripted `FakeAgent`, purpose-built to exercise every internal branch
//! of `crate::supervise`), this file drives the two real binaries —
//! `eltanin-agentd` and `eltanin` — against each other over a real Unix
//! Domain Socket, with a real on-disk policy file. That is the only way
//! to make "user docs commands match tested workflow" true: a Quickstart
//! necessarily includes agent-side setup (`ELTANIN_AGENT_POLICY`,
//! `ELTANIN_AGENT_SOCKET_MODE`, `ELTANIN_AGENT_LEASE_TTL_SECS`) that a
//! `FakeAgent` scenario never touches, and a real agent's DENY leg proves
//! actual default-deny (`DenialReason::NoMatchingRule`), not a scripted
//! response. `launch_lifecycle.rs` is not duplicated or modified by this
//! file — it remains the deeper internal-branch coverage; this file is
//! the shallow, user-facing, whole-system journey.
//!
//! Linux and macOS (this repo's `ubuntu-latest` and `macos-latest` CI
//! runners; widened from Linux-only by HORO-1013, which added a real
//! macOS peer-credential/workload-identity collector) — mirrors
//! `crates/eltanin-agent/tests/authz_end_to_end.rs`'s own file-level
//! gate. Requires the workspace to already be built (`cargo build
//! --workspace` or `cargo test --workspace`, both of which CI always
//! runs first) so `eltanin-agentd`'s and `eltanin-explain`'s binaries
//! exist next to `eltanin`'s.
//!
//! **Named limitation** (see `docs/qa/e2e/F-M1-008-controlled-launch.md`
//! for the full record): this scenario runs against `FakeBackend`
//! (`eltanin-agentd`'s only backend today), so it proves the
//! *authorization* path end to end, not real GPU hardware enforcement —
//! that evidence is F-M1-002/F-M1-007's, gated on bare-metal hardware
//! access. It also, by construction (the reused fixture — see D-B),
//! makes no workload-executable-identity claim: only uid is varied
//! between the ALLOW and DENY legs.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;
use std::time::{Duration, Instant};

use eltanin_cli::sequence::LaunchStage;
use rustix::process::{kill_process, Pid, Signal};

/// Stable Track B scenario identifier. Cited verbatim by
/// `docs/product/QUICKSTART.md` and
/// `docs/qa/e2e/F-M1-008-controlled-launch.md` — see
/// `tests/docs_sync.rs` for the assertions pinning that. Bump the
/// trailing version if this scenario's *observable behavior* changes
/// (exit codes, commands, fixture shape) — not for a wording-only edit.
pub const SCENARIO_ID: &str = "E2E-F-M1-008-controlled-launch-v1";

/// Every Feature this one scenario's ALLOW/DENY journey provides Track B
/// (Product/Business E2E) evidence for, per
/// `docs/qa/e2e/F-M1-008-controlled-launch.md`'s coverage table:
/// F-M1-008 is the launch path itself; the others are the dependencies
/// it necessarily exercises live (workload identity, policy evaluation,
/// the lease, the agent transport, and audit).
pub const COVERS: &[&str] = &[
    "F-M1-008", "F-M1-003", "F-M1-004", "F-M1-005", "F-M1-006", "F-M1-009",
];

/// The name `eltanin run --profile` resolves in this scenario — also
/// the exact name the Quickstart tells a reader to write to
/// `~/.config/eltanin/profiles/gpu.json`.
const PROFILE_NAME: &str = "gpu";

/// The published `eltanin run` policy example
/// (`docs/product/POLICY_EXAMPLES.md`'s "Worked example") — reused
/// verbatim rather than duplicated, so this scenario and the docs can
/// never silently disagree about what MVP 1.0 can express. Its
/// `allow-alice-via-eltanin-run` rule's `"expected": 1000` is
/// text-substituted with this process's own uid ([`allow_policy_json`])
/// so the scenario runs correctly as whichever user CI (or a reader)
/// happens to be.
const POLICY_FIXTURE: &str = include_str!("fixtures/eltanin_run_example_policy.json");

/// The published `eltanin run` profile example
/// (`docs/product/QUICKSTART.md`'s profile document) — reused verbatim;
/// see `tests/profile_loader.rs` for its other, unrelated use in this
/// crate (a plain `include_str!`, so sharing it introduces no coupling
/// between the two test binaries).
const PROFILE_FIXTURE: &str = include_str!("fixtures/example_profile.json");

/// A private (`0o700`) per-test-process base directory. Mirrors
/// `crates/eltanin-agent/tests/support/mod.rs::private_base_dir` exactly
/// and for the same reason: `eltanin-agentd`'s own `BoundSocket::bind`
/// refuses to bind directly under `/tmp` (world/group-writable), so
/// every real-agentd test needs its own private subdirectory.
fn private_base_dir() -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    static INIT: Once = Once::new();
    let real_tmp = fs::canonicalize("/tmp").unwrap_or_else(|_| PathBuf::from("/tmp"));
    let base = real_tmp.join(format!("eltanin-cli-canonical-e2e-{}", std::process::id()));
    INIT.call_once(|| {
        fs::create_dir_all(&base).expect("create private test base dir");
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700))
            .expect("chmod private test base dir");
    });
    base
}

/// A fresh, uniquely-named scratch directory under [`private_base_dir`]
/// for one test's policy/profile/socket/audit-log files. Explicitly
/// chmod'd `0o700` — a bare `create_dir_all` under a permissive umask
/// (e.g. `umask 000`) would otherwise leave it group/other-writable,
/// which `BoundSocket::bind`'s parent-directory check would then reject
/// (or, worse, not reject, in a umask this loose actually still leaves
/// the write bit set — either way, not the private directory this
/// function's contract promises).
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
/// binary this test binary already gets via `CARGO_BIN_EXE_eltanin`.
/// `CARGO_BIN_EXE_*` is per-package — `eltanin-agentd` and
/// `eltanin-explain` live in `eltanin-agent`/`eltanin-audit`, packages
/// this crate has no dependency on, so Cargo does not set an env var for
/// them here. Every binary in one workspace build lands in the same
/// `target/<profile>/` directory regardless of which package owns it,
/// so deriving the path this way is exact, not a guess.
fn sibling_bin(name: &str) -> PathBuf {
    let eltanin = PathBuf::from(env!("CARGO_BIN_EXE_eltanin"));
    let dir = eltanin.parent().expect("eltanin binary has a parent dir");
    let path = dir.join(name);
    assert!(
        path.exists(),
        "[{SCENARIO_ID}] expected {name} to already be built next to {}; build the whole \
         workspace first: `cargo build --workspace` (CI always does this before `cargo test \
         --workspace`)",
        eltanin.display(),
    );
    path
}

/// This process's own effective uid, via a real kernel call (not
/// `/proc` parsing) — the same value `eltanin-agentd`'s
/// `SO_PEERCRED`-derived `uid` condition will observe for the `eltanin`
/// process it authorizes, since both processes share the same real
/// account.
fn real_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// The scenario's precondition, asserted rather than engineered around:
/// the fixture's `deny-root` rule (`"expected": 0`,
/// `docs/product/POLICY_EXAMPLES.md`) would otherwise silently swallow
/// the ALLOW leg for a test process actually running as uid 0.
fn assert_non_root_precondition(uid: u32) {
    assert_ne!(
        uid, 0,
        "[{SCENARIO_ID}] this scenario's fixture denies uid 0 outright (see \
         docs/product/POLICY_EXAMPLES.md's \"deny-root\" rule) — this scenario cannot run as \
         root; re-run as a non-root user"
    );
}

/// Write the policy fixture into `dir`, with its one `uid`-`expected`
/// allow condition rewritten to `allow_uid`. The `deny-root` rule's own
/// `"expected": 0` is untouched — see [`assert_non_root_precondition`]
/// for why that is always safe to leave alone here.
fn write_policy(dir: &Path, allow_uid: u32) -> PathBuf {
    let original = "\"expected\": 1000";
    assert_eq!(
        POLICY_FIXTURE.matches(original).count(),
        1,
        "[{SCENARIO_ID}] fixtures/eltanin_run_example_policy.json must contain exactly one \
         {original:?} (the allow rule's uid condition) for this scenario's uid substitution to \
         unambiguously target it — a future fixture edit introducing a second occurrence must \
         update this substitution, not silently rewrite the wrong rule"
    );
    let text = POLICY_FIXTURE.replacen(original, &format!("\"expected\": {allow_uid}"), 1);
    let path = dir.join("policy.json");
    fs::write(&path, text).expect("write policy fixture");
    path
}

/// Write the profile fixture into `dir` as `{PROFILE_NAME}.json`, and
/// return `dir` itself as the `ELTANIN_PROFILE_DIR` to point `eltanin
/// run` at.
fn write_profile_dir(dir: &Path) -> PathBuf {
    fs::write(dir.join(format!("{PROFILE_NAME}.json")), PROFILE_FIXTURE)
        .expect("write profile fixture");
    dir.to_path_buf()
}

/// A running `eltanin-agentd` process, bound to a private socket under
/// its own [`scenario_dir`], killed on drop so a test failure never
/// leaks a listening agent.
struct Agentd {
    child: Child,
    socket_path: PathBuf,
}

impl Agentd {
    /// Start `eltanin-agentd` with a policy allowing exactly `allow_uid`
    /// (plus the fixture's standing `deny-root` rule), and block until
    /// its socket exists or it demonstrably fails to start.
    fn start(dir: &Path, allow_uid: u32, audit_log: Option<&Path>) -> Self {
        let policy_path = write_policy(dir, allow_uid);
        let socket_path = dir.join("agent.sock");
        // `sun_path` (the kernel struct backing a Unix socket address) is
        // ~107 bytes on Linux but only ~103 on macOS (`sockaddr_un` is
        // 104 bytes there vs. Linux's 108) — same guard as
        // `crates/eltanin-agent/tests/support/mod.rs::temp_socket_path`,
        // needed here too since this path is one segment longer
        // (`base/scenario-n/agent.sock` vs. that file's `base/tag-n.sock`).
        // The `< 100` bound below is chosen to clear both platforms'
        // limits with margin, not just Linux's.
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
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match audit_log {
            Some(log) => {
                command.env("ELTANIN_AUDIT_LOG", log);
            }
            None => {
                command.env_remove("ELTANIN_AUDIT_LOG");
            }
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
        // Check for an already-reaped child first (e.g. `wait_for_socket`
        // observed an early exit and `try_wait` already consumed it
        // before panicking): once reaped, `self.child.id()`'s pid number
        // is free for the kernel to reuse, so signaling it here could hit
        // an unrelated process that happened to reuse the pid — a stray
        // SIGTERM landing on someone else's process, not a no-op.
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return;
        }
        // Best-effort graceful shutdown via the daemon's own documented
        // SIGTERM path (`daemon.rs::run`); fall back to a hard kill so a
        // test failure elsewhere in this file never leaks a listening
        // agentd process.
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

/// Build (but do not run) the exact `eltanin run` command this
/// scenario's two legs share — also, verbatim, the command
/// `docs/product/QUICKSTART.md` shows (see `tests/docs_sync.rs`).
fn eltanin_command(agent: &Agentd, profile_dir: &Path, workload_argv: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_eltanin"));
    command
        .env("ELTANIN_AGENT_SOCKET", &agent.socket_path)
        .env("ELTANIN_PROFILE_DIR", profile_dir)
        .arg("run")
        .arg("--profile")
        .arg(PROFILE_NAME)
        .arg("--")
        .args(workload_argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[test]
fn allow_journey_authorizes_and_runs_the_workload() {
    let uid = real_euid();
    assert_non_root_precondition(uid);

    let dir = scenario_dir("allow");
    let agent = Agentd::start(&dir, uid, None);
    let profile_dir = write_profile_dir(&dir);

    let output = eltanin_command(&agent, &profile_dir, &["echo", "authorized-compute-ok"])
        .output()
        .expect("run eltanin binary");

    assert!(
        output.status.success(),
        "[{SCENARIO_ID}/ALLOW] Quickstart step 3 ({:?}, S4→S6): expected the workload to run \
         to completion after an observed LeaseGranted, got exit {:?} — violates \
         NORTH_STAR.md invariant 1 (\"Authorization before consumption\"). stdout={:?} \
         stderr={:?}",
        LaunchStage::SpawnWorkload,
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("authorized-compute-ok"),
        "[{SCENARIO_ID}/ALLOW] the authorized workload's own stdout must pass through `eltanin \
         run` verbatim, got: {:?}",
        String::from_utf8_lossy(&output.stdout),
    );
}

#[test]
fn deny_journey_never_spawns_the_workload() {
    let uid = real_euid();
    assert_non_root_precondition(uid);

    let dir = scenario_dir("deny");
    // One past our own uid: guaranteed to match neither the allow rule
    // (which names exactly our own uid) nor, since the precondition
    // above already proved we are not uid 0, the deny-root rule either
    // — so this is a genuine default-deny (NoMatchingRule), not a
    // scripted ExplicitDeny.
    let agent = Agentd::start(&dir, uid.wrapping_add(1), None);
    let profile_dir = write_profile_dir(&dir);
    let sentinel = dir.join("workload-ran");

    let output = eltanin_command(
        &agent,
        &profile_dir,
        &["sh", "-c", &format!("touch {}", sentinel.display())],
    )
    .output()
    .expect("run eltanin binary");

    assert_eq!(
        output.status.code(),
        Some(77),
        "[{SCENARIO_ID}/DENY] Quickstart step 3 ({:?}): expected exit 77 (denied by policy) \
         for a caller matching no policy rule, got {:?} — violates NORTH_STAR.md invariant 1 \
         (\"Authorization before consumption. Default deny for protected compute.\"). \
         stderr={:?}",
        LaunchStage::RequestLease,
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !sentinel.exists(),
        "[{SCENARIO_ID}/DENY] the workload must never run on a denied request — there is no \
         {:?} between S4 (RequestLease) and S6 (SpawnWorkload) in the launch sequence \
         (CLI_CONTRACT.md), so this sentinel file must not exist — violates NORTH_STAR.md \
         invariant 1",
        LaunchStage::SpawnWorkload,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Specifically "no policy rule allows this request"
    // (`describe_denial_reason(DenialReason::NoMatchingRule)`), not the
    // generic word "denied" — both `NoMatchingRule` and `ExplicitDeny`
    // render through `LaunchFailure::message()` as "request denied:
    // {…}", so asserting on the generic word alone would still pass if a
    // future policy-engine regression evaluated this as a scripted
    // `ExplicitDeny` instead of a genuine default-deny, silently
    // invalidating this scenario's whole point.
    assert!(
        stderr.contains("no policy rule allows this request") && stderr.contains("eltanin-explain"),
        "[{SCENARIO_ID}/DENY] stderr must name a genuine default-deny (NoMatchingRule) and the \
         `eltanin-explain` next action (LaunchFailure::Denied's message/next_action), got: \
         {stderr:?}",
    );
}

#[test]
fn deny_journey_is_explainable_via_the_audit_log() {
    let uid = real_euid();
    assert_non_root_precondition(uid);

    let dir = scenario_dir("explain");
    let audit_log = dir.join("audit.ndjson");
    let agent = Agentd::start(&dir, uid.wrapping_add(1), Some(&audit_log));
    let profile_dir = write_profile_dir(&dir);

    let mut command = eltanin_command(&agent, &profile_dir, &["true"]);
    let child = command.spawn().expect("spawn eltanin binary");
    // eltanin-explain --pid selects on the *connecting peer's* pid,
    // which through `eltanin run` is always eltanin's own pid (the
    // workload is never spawned on a denied request) — never the
    // workload's, and never the wire's caller-supplied RequestId
    // (`LaunchFailure::next_action`'s own documented invariant).
    let pid = child.id();
    let output = child.wait_with_output().expect("wait for eltanin binary");
    assert_eq!(
        output.status.code(),
        Some(77),
        "[{SCENARIO_ID}/DENY] precondition for this test: the run must be denied so there is a \
         denial to explain, got exit {:?} — stderr={:?}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );

    let explain_output = Command::new(sibling_bin("eltanin-explain"))
        .arg("--log")
        .arg(&audit_log)
        .arg("--pid")
        .arg(pid.to_string())
        .output()
        .expect("run eltanin-explain binary");

    assert!(
        explain_output.status.success() && !explain_output.stdout.is_empty(),
        "[{SCENARIO_ID}/DENY] `eltanin-explain --pid {pid}` — the denial's own documented next \
         action (LaunchFailure::next_action) — must produce a non-empty decision record for a \
         real denial, got exit {:?}, stdout={:?} stderr={:?} — violates NORTH_STAR.md invariant \
         3 (\"Monitoring != Security\": audit/explain must be genuine evidence, not a stub)",
        explain_output.status.code(),
        String::from_utf8_lossy(&explain_output.stdout),
        String::from_utf8_lossy(&explain_output.stderr),
    );
}
