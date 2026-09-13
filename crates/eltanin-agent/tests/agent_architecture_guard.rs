//! Architecture test: `eltanin-agent`'s transport modules stay
//! transport/runtime only (F-M1-006, HORO-839/HORO-840) — they must
//! never name `eltanin-core`'s policy/lease *evaluation* API. The
//! `authz` module is the one named, auditable exception: HORO-840
//! implements policy evaluation and lease issue/release there, behind
//! [`eltanin_agent::handler::RequestHandler`], never in a transport
//! module. Source must contain no `unsafe` code anywhere, `authz`
//! included. Same blunt lexical-scan idiom as `eltanin-core`'s
//! `architecture_no_vendor_leak.rs` and `eltanin-protocol`'s
//! `protocol_no_self_asserted_identity.rs`: comment lines are stripped,
//! string literals are not specially handled.
//!
//! The exemption for `authz` is a fixed hole, not an escape hatch:
//! [`REQUIRED_SCANNED`] asserts every transport module file was actually
//! scanned, so moving transport code into `authz/` to dodge the product-
//! logic scan fails this test instead of silently succeeding.

use std::fs;
use std::path::{Path, PathBuf};

const FORBIDDEN_PRODUCT_LOGIC: &[&str] = &[
    "PolicySet",
    "PolicyDecision",
    "PolicyDocument",
    "LeaseIssuer",
    "ComputeLease",
    ".evaluate(",
    ".issue(",
    ".revoke(",
];

/// Every transport-module source file that must actually be scanned by
/// [`agent_source_never_names_policy_or_lease_evaluation_logic`]. If a
/// new transport file is added under `src/` without being named here,
/// this test fails loudly rather than silently widening the exemption.
const REQUIRED_SCANNED: &[&str] = &[
    "lib.rs",
    "config.rs",
    "connection.rs",
    "daemon.rs",
    "handler.rs",
    "listener.rs",
    "peer.rs",
    "runtime.rs",
    "server.rs",
    "eltanin-agentd.rs",
    // Test-only fixture binary (F-M2-001, HORO-791) — not a transport
    // module, but registered here rather than widening the `authz/`
    // exemption to cover it: it lives under `src/bin/`, and this list's
    // own purpose is to make sure no `src/` file is silently
    // unaccounted for, transport or not.
    "session_probe_fixture.rs",
];

/// Path component that marks a file as belonging to the one exempted
/// module — HORO-840's policy/lease integration.
const PRODUCT_LOGIC_DIR: &str = "authz";

fn strip_comment_lines(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn code_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            code_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// `true` only for a file directly under `src/authz/` — anchored to the
/// *first* path component under `src/`, not merely "some component of
/// this path is named `authz` anywhere." An unanchored `.any()` over
/// every component would also exempt e.g. a hypothetical
/// `src/transport/authz/leak.rs`, which is not the one named module this
/// test's exemption is supposed to cover.
fn is_authz_file(path: &Path, src_dir: &Path) -> bool {
    path.strip_prefix(src_dir)
        .ok()
        .and_then(|relative| relative.components().next())
        .is_some_and(|first| first.as_os_str() == PRODUCT_LOGIC_DIR)
}

#[test]
fn agent_source_never_names_policy_or_lease_evaluation_logic_outside_authz() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    code_files(&src_dir, &mut files);
    assert!(
        !files.is_empty(),
        "expected to find eltanin-agent source files to scan"
    );

    let transport_files: Vec<&PathBuf> = files
        .iter()
        .filter(|f| !is_authz_file(f, &src_dir))
        .collect();

    // The exemption is a fixed hole, not an escape hatch: every named
    // transport file must actually have been scanned below. A file
    // moved into authz/ to dodge the scan, or a new transport file added
    // without updating REQUIRED_SCANNED, fails here instead of silently
    // widening what's exempt.
    for required in REQUIRED_SCANNED {
        assert!(
            transport_files
                .iter()
                .any(|f| f.file_name().is_some_and(|n| n == *required)),
            "expected src/{required} to be scanned as a transport module, but it was not found \
             (renamed? moved into authz/?)"
        );
    }
    assert_eq!(
        transport_files.len(),
        REQUIRED_SCANNED.len(),
        "a transport-module file exists under src/ that REQUIRED_SCANNED does not name — add it \
         explicitly rather than widening the authz/ exemption"
    );

    let authz_dir = src_dir.join(PRODUCT_LOGIC_DIR);
    assert!(
        authz_dir.is_dir() && files.iter().any(|f| is_authz_file(f, &src_dir)),
        "expected a non-empty src/authz/ module — HORO-840's policy/lease integration must live \
         in the one named, auditable place this test exempts, not scattered elsewhere"
    );

    let mut violations = Vec::new();
    for file in &transport_files {
        let contents = fs::read_to_string(file).expect("read source file");
        let code_only = strip_comment_lines(&contents);
        for term in FORBIDDEN_PRODUCT_LOGIC {
            if code_only.contains(term) {
                violations.push(format!(
                    "{}: names forbidden product logic {term:?}",
                    file.display()
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "eltanin-agent's transport modules must stay policy/lease-evaluation-free — that logic \
         belongs in src/authz/, behind RequestHandler, but found:\n{}",
        violations.join("\n")
    );
}

#[test]
fn agent_source_contains_no_unsafe_code() {
    // Belt-and-suspenders alongside #![forbid(unsafe_code)] in lib.rs:
    // this also catches an `unsafe` block appearing anywhere the forbid
    // attribute wouldn't apply (e.g. a future submodule that
    // accidentally overrides it with `#[allow(unsafe_code)]`). Scans
    // everything, authz/ and src/bin/ included — this exemption has no
    // carve-out.
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    code_files(&src_dir, &mut files);

    let mut violations = Vec::new();
    for file in &files {
        let contents = fs::read_to_string(file).expect("read source file");
        for line in strip_comment_lines(&contents).lines() {
            let trimmed = line.trim_start();
            // Exclude `#![forbid(unsafe_code)]`/`#[allow(unsafe_code)]`
            // style attribute lines — they *name* the word as a lint
            // identifier, not as the `unsafe` keyword introducing a
            // block/fn/impl/trait.
            if trimmed.starts_with('#') {
                continue;
            }
            if line.contains("unsafe") {
                violations.push(format!("{}: {trimmed}", file.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "eltanin-agent must contain no unsafe code (SO_PEERCRED/signal handling are isolated in \
         eltanin-linux/signal-hook via safe wrappers), but found it in:\n{}",
        violations.join("\n")
    );
}

/// `eltanin-agent`'s own `src/` must never construct a `PeerContext`
/// directly, by any constructor — production or `test-support`-gated
/// alike. The only legitimate way `eltanin-agent` ever obtains one is
/// by calling a platform collector's `collect_peer_context`
/// (`eltanin_linux::peer`/`eltanin_macos::peer`, via
/// `OsPeerContextSource`), never by calling `eltanin_core::peer`'s
/// constructors itself. Before the peer contract's relocation to
/// `eltanin-core` (HORO-1013), this was structurally impossible — the
/// constructors lived crate-private inside `eltanin-linux`; this test
/// compensates mechanically now that they are `pub` (even if
/// `test-support`-feature-gated) on a crate `eltanin-agent` depends on
/// unconditionally.
#[test]
fn agent_source_never_constructs_a_peer_context_directly() {
    const FORBIDDEN_PEER_CONSTRUCTORS: &[&str] = &[
        "PeerCredential::from_kernel",
        "PeerCredential::new",
        "PeerContext::for_test",
        "PeerContext::new",
        "PeerContext::from_kernel_observation",
        "PeerContext::peer_unmapped",
    ];

    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    code_files(&src_dir, &mut files);
    assert!(
        !files.is_empty(),
        "expected to find eltanin-agent source files to scan"
    );

    let mut violations = Vec::new();
    for file in &files {
        let contents = fs::read_to_string(file).expect("read source file");
        let code_only = strip_comment_lines(&contents);
        for term in FORBIDDEN_PEER_CONSTRUCTORS {
            if code_only.contains(term) {
                violations.push(format!("{}: calls forbidden {term:?}", file.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "eltanin-agent's own src/ must never construct a PeerContext directly — only a platform \
         collector (eltanin-linux/eltanin-macos) may, via its own collect_peer_context, but \
         found:\n{}",
        violations.join("\n")
    );
}
