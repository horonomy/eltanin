//! A real-hardware Apple Silicon canonical Product/Business E2E scenario
//! (F-M1-010, HORO-1014): the same `eltanin run` ALLOW/DENY journey
//! `canonical_e2e.rs` already proves against `echo`/`sh`, but with the
//! real, repository-owned `metal_workload_fixture` binary
//! (`crates/eltanin-apple/src/bin/metal_workload_fixture.rs`) as the
//! managed workload — so this scenario proves the "ALLOW -> workload
//! runs -> result verifies -> audit evidence correlated; DENY ->
//! managed workload does not run" journey Jira's "Eltanin Integration"
//! section asks for, using genuine Metal GPU compute rather than a
//! placeholder command.
//!
//! This file is **not** `canonical_e2e.rs`'s `E2E-F-M1-008-controlled-launch-v1`
//! scenario, does not modify it, and deliberately does not declare its
//! own `pub const COVERS` claim the way that file does:
//! `crates/eltanin-cli/tests/qa_governance_sync.rs` only ever
//! `include_str!`s `canonical_e2e.rs` and
//! `docs/qa/e2e/F-M1-008-controlled-launch.md`, so this file is
//! deliberately invisible to those drift guards rather than forced to
//! satisfy a coverage-table shape meant for a different scenario.
//! Producing this fixture's own formal Track B scenario ID/record
//! (expected to be `B-M1-APPLE`, per HORO-1015's Jira description and
//! its HORO-1018 governance comment) is HORO-1015's scope, not this
//! ticket's — see [`PROVISIONAL_SCENARIO_ID`] below and
//! `docs/qa/test-plans/mvp-1.0.md`'s citation of this file.
//!
//! # Why this is real-hardware-only, `#[ignore]`d, and macOS-only
//!
//! Mirrors `crates/eltanin-apple/tests/metal_compute_probe.rs`'s own
//! precedent and `.github/workflows/ci.yml`'s `test-macos` job comment
//! (HORO-1012/1013): `metal_workload_fixture` unconditionally dispatches
//! a real Metal kernel and hard-asserts success, with no
//! hardware-availability skip — exactly the evidence class ADR 0007
//! decided must never run on a virtualized/hosted CI GPU. Unlike
//! `metal_compute_probe.rs` (a test *inside* `eltanin-apple`, kept off
//! CI via `ci.yml`'s `--exclude eltanin-apple`), this file lives in
//! `eltanin-cli`, a package `ci.yml`'s `test-macos` job does *not*
//! exclude — so each test function here is additionally marked
//! `#[ignore]`, meaning `cargo test --workspace` (what CI actually runs)
//! compiles this file on every platform gate but never executes it.
//! `#![cfg(target_os = "macos")]` additionally keeps it from compiling
//! at all on Linux CI, where `eltanin-apple`'s bin still builds (its
//! Metal calls are target-gated internally) but there is no Metal
//! device to prove anything against.
//!
//! Run for real, by hand, on a physical Apple Silicon Mac:
//! ```sh
//! cargo build --workspace
//! cargo test -p eltanin-cli --test apple_metal_canonical_e2e -- --ignored
//! ```
#![cfg(target_os = "macos")]

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;
use std::time::{Duration, Instant};

use rustix::process::{kill_process, Pid, Signal};

/// A provisional identifier for this scenario, used only in this file's
/// own assertion-failure messages. Not a stable Track B scenario ID in
/// the sense `docs/qa/e2e/README.md`'s manifest defines one (see this
/// file's own doc comment) — HORO-1015 assigns the formal `B-M1-APPLE`
/// ID and record once it runs this journey as part of physical M3 Max
/// QA closure.
const PROVISIONAL_SCENARIO_ID: &str = "F-M1-010-apple-metal-fixture (provisional, pre-B-M1-APPLE)";

const PROFILE_NAME: &str = "gpu";

const POLICY_FIXTURE: &str = include_str!("fixtures/eltanin_run_example_policy.json");
const PROFILE_FIXTURE: &str = include_str!("fixtures/example_profile.json");

/// A private (`0o700`) per-test-process base directory — same rationale
/// and shape as `canonical_e2e.rs::private_base_dir`, duplicated rather
/// than shared, since integration test binaries cannot share private
/// items across files.
fn private_base_dir() -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    static INIT: Once = Once::new();
    let real_tmp = fs::canonicalize("/tmp").unwrap_or_else(|_| PathBuf::from("/tmp"));
    let base = real_tmp.join(format!(
        "eltanin-cli-apple-metal-e2e-{}",
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
/// same pattern as `canonical_e2e.rs::sibling_bin`. This is how this
/// crate (which has no `eltanin-apple` dependency) locates the
/// `metal_workload_fixture` binary that crate's own `[[bin]]` builds.
fn sibling_bin(name: &str) -> PathBuf {
    let eltanin = PathBuf::from(env!("CARGO_BIN_EXE_eltanin"));
    let dir = eltanin.parent().expect("eltanin binary has a parent dir");
    let path = dir.join(name);
    assert!(
        path.exists(),
        "[{PROVISIONAL_SCENARIO_ID}] expected {name} to already be built next to {}; build the \
         whole workspace first: `cargo build --workspace`",
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
        "[{PROVISIONAL_SCENARIO_ID}] this scenario's fixture denies uid 0 outright (see \
         docs/product/POLICY_EXAMPLES.md's \"deny-root\" rule) — this scenario cannot run as \
         root; re-run as a non-root user"
    );
}

fn write_policy(dir: &Path, allow_uid: u32) -> PathBuf {
    let original = "\"expected\": 1000";
    assert_eq!(
        POLICY_FIXTURE.matches(original).count(),
        1,
        "[{PROVISIONAL_SCENARIO_ID}] fixtures/eltanin_run_example_policy.json must contain \
         exactly one {original:?} for this scenario's uid substitution to unambiguously target \
         it"
    );
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

/// A running `eltanin-agentd` process, bound to a private socket under
/// its own [`scenario_dir`], killed on drop — same shape as
/// `canonical_e2e.rs::Agentd`, duplicated for the same reason as the
/// other helpers above.
struct Agentd {
    child: Child,
    socket_path: PathBuf,
}

impl Agentd {
    /// Start `eltanin-agentd`, optionally wired to write NDJSON audit
    /// records to `audit_log` — same optional-audit-log shape as
    /// `canonical_e2e.rs::Agentd::start`, needed here so the
    /// explain-evidence tests below can inspect a real audit trail for
    /// this fixture's own ALLOW/DENY journeys, not just the Linux
    /// scenario's.
    fn start(dir: &Path, allow_uid: u32, audit_log: Option<&Path>) -> Self {
        let policy_path = write_policy(dir, allow_uid);
        let socket_path = dir.join("agent.sock");
        assert!(
            socket_path.as_os_str().len() < 100,
            "[{PROVISIONAL_SCENARIO_ID}] socket path too long for sun_path: {}",
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
                    "[{PROVISIONAL_SCENARIO_ID}] eltanin-agentd exited early ({status}) before \
                     creating its socket at {} — stderr: {stderr}",
                    self.socket_path.display(),
                );
            }
            assert!(
                Instant::now() < deadline,
                "[{PROVISIONAL_SCENARIO_ID}] eltanin-agentd did not create its socket within 5s \
                 at {}",
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
#[ignore = "real Apple Silicon hardware only — run by hand with `-- --ignored` after \
            `cargo build --workspace`; see this file's doc comment"]
fn allow_journey_runs_the_real_metal_workload_and_verifies_output() {
    let uid = real_euid();
    assert_non_root_precondition(uid);

    let dir = scenario_dir("allow");
    let agent = Agentd::start(&dir, uid, None);
    let profile_dir = write_profile_dir(&dir);
    let evidence_path = dir.join("evidence.json");
    let fixture_bin = sibling_bin("metal_workload_fixture");
    let evidence_arg = evidence_path.to_string_lossy().into_owned();

    let output = eltanin_command(
        &agent,
        &profile_dir,
        &[
            fixture_bin.to_str().expect("utf-8 fixture path"),
            "--evidence-out",
            &evidence_arg,
        ],
    )
    .output()
    .expect("run eltanin binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "[{PROVISIONAL_SCENARIO_ID}/ALLOW] expected the real Metal workload to run to \
         completion after an ALLOW decision, got exit {:?} — stdout={stdout:?} stderr={stderr:?}",
        output.status.code(),
    );

    // The workload's own stdout (its JSON evidence report) must pass
    // through `eltanin run` verbatim — proves this was a real managed
    // launch of the fixture, not a stub.
    assert!(
        stdout.contains("\"fixture\": \"eltanin-apple-metal-workload-fixture\"")
            && stdout.contains("\"all_elements_verified\": true")
            && stdout.contains("\"gpu_command_completed\": true"),
        "[{PROVISIONAL_SCENARIO_ID}/ALLOW] expected the fixture's own verified-Metal-compute \
         JSON evidence on stdout, got: {stdout:?}"
    );

    // The `--evidence-out` file is independent proof the fixture wrote
    // real evidence to disk, not just to a captured pipe.
    let evidence_file = fs::read_to_string(&evidence_path).unwrap_or_else(|e| {
        panic!(
            "[{PROVISIONAL_SCENARIO_ID}/ALLOW] expected --evidence-out to have written {}: \
                 {e}",
            evidence_path.display()
        )
    });
    assert!(
        evidence_file.contains("\"all_elements_verified\": true"),
        "[{PROVISIONAL_SCENARIO_ID}/ALLOW] evidence file must record a verified result, got: \
         {evidence_file:?}"
    );
}

#[test]
#[ignore = "real Apple Silicon hardware only — run by hand with `-- --ignored` after \
            `cargo build --workspace`; see this file's doc comment"]
fn allow_journey_is_explainable_via_the_audit_log() {
    let uid = real_euid();
    assert_non_root_precondition(uid);

    let dir = scenario_dir("allow-explain");
    let audit_log = dir.join("audit.ndjson");
    let agent = Agentd::start(&dir, uid, Some(&audit_log));
    let profile_dir = write_profile_dir(&dir);
    let fixture_bin = sibling_bin("metal_workload_fixture");

    let mut command = eltanin_command(
        &agent,
        &profile_dir,
        &[fixture_bin.to_str().expect("utf-8 fixture path")],
    );
    let child = command.spawn().expect("spawn eltanin binary");
    // Same rationale as `canonical_e2e.rs::deny_journey_is_explainable_via_the_audit_log`:
    // `eltanin-explain --pid` selects on the connecting peer's pid, which
    // through `eltanin run` is always `eltanin`'s own pid, never the real
    // Metal workload's.
    let pid = child.id();
    let output = child.wait_with_output().expect("wait for eltanin binary");
    assert!(
        output.status.success(),
        "[{PROVISIONAL_SCENARIO_ID}/ALLOW] precondition for this test: the run must be granted \
         so there is a real Metal-compute grant to explain, got exit {:?} — stderr={:?}",
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
        "[{PROVISIONAL_SCENARIO_ID}/ALLOW] `eltanin-explain --pid {pid}` must produce a \
         non-empty decision record correlated with the real Metal-compute grant, got exit {:?}, \
         stdout={:?} stderr={:?} — violates NORTH_STAR.md invariant 3 (\"Monitoring != \
         Security\": audit/explain must be genuine evidence, not a stub)",
        explain_output.status.code(),
        String::from_utf8_lossy(&explain_output.stdout),
        String::from_utf8_lossy(&explain_output.stderr),
    );
}

#[test]
#[ignore = "real Apple Silicon hardware only — run by hand with `-- --ignored` after \
            `cargo build --workspace`; see this file's doc comment"]
fn deny_journey_is_explainable_via_the_audit_log() {
    let uid = real_euid();
    assert_non_root_precondition(uid);

    let dir = scenario_dir("deny-explain");
    let audit_log = dir.join("audit.ndjson");
    let agent = Agentd::start(&dir, uid.wrapping_add(1), Some(&audit_log));
    let profile_dir = write_profile_dir(&dir);
    let fixture_bin = sibling_bin("metal_workload_fixture");

    let mut command = eltanin_command(
        &agent,
        &profile_dir,
        &[fixture_bin.to_str().expect("utf-8 fixture path")],
    );
    let child = command.spawn().expect("spawn eltanin binary");
    let pid = child.id();
    let output = child.wait_with_output().expect("wait for eltanin binary");
    assert_eq!(
        output.status.code(),
        Some(77),
        "[{PROVISIONAL_SCENARIO_ID}/DENY] precondition for this test: the run must be denied so \
         there is a denial to explain, got exit {:?} — stderr={:?}",
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
        "[{PROVISIONAL_SCENARIO_ID}/DENY] `eltanin-explain --pid {pid}` must produce a non-empty \
         decision record for a real denial of the managed Metal workload, got exit {:?}, \
         stdout={:?} stderr={:?} — violates NORTH_STAR.md invariant 3 (\"Monitoring != \
         Security\": audit/explain must be genuine evidence, not a stub)",
        explain_output.status.code(),
        String::from_utf8_lossy(&explain_output.stdout),
        String::from_utf8_lossy(&explain_output.stderr),
    );
}

#[test]
#[ignore = "real Apple Silicon hardware only — run by hand with `-- --ignored` after \
            `cargo build --workspace`; see this file's doc comment"]
fn deny_journey_never_spawns_the_real_metal_workload() {
    let uid = real_euid();
    assert_non_root_precondition(uid);

    let dir = scenario_dir("deny");
    // Guaranteed to match neither the allow rule (our own uid) nor the
    // deny-root rule (we just asserted we're not uid 0) — a genuine
    // default-deny, not a scripted explicit deny.
    let agent = Agentd::start(&dir, uid.wrapping_add(1), None);
    let profile_dir = write_profile_dir(&dir);
    let evidence_path = dir.join("evidence.json");
    let fixture_bin = sibling_bin("metal_workload_fixture");
    let evidence_arg = evidence_path.to_string_lossy().into_owned();

    let output = eltanin_command(
        &agent,
        &profile_dir,
        &[
            fixture_bin.to_str().expect("utf-8 fixture path"),
            "--evidence-out",
            &evidence_arg,
        ],
    )
    .output()
    .expect("run eltanin binary");

    assert_eq!(
        output.status.code(),
        Some(77),
        "[{PROVISIONAL_SCENARIO_ID}/DENY] expected exit 77 (denied by policy), got {:?} — \
         stderr={:?}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );

    // The strongest possible proof the managed workload never ran at
    // all: the fixture's own evidence file, which only the fixture
    // itself can create, must not exist. Unlike a `touch`-based
    // sentinel, this is the real workload's real output path, not a
    // stand-in shell command.
    assert!(
        !evidence_path.exists(),
        "[{PROVISIONAL_SCENARIO_ID}/DENY] the real Metal workload must never run on a denied \
         request — found an evidence file at {} that only a real fixture run could have \
         created",
        evidence_path.display(),
    );
}
