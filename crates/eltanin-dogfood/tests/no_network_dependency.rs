//! DFC-ADAPT-03 (primary property): "fixtures pass; dependency audit
//! shows no networking crate added" — ADR-0012 §12's Eltanin row.
//!
//! Walks `cargo metadata`'s real resolved dependency graph, starting
//! from the `eltanin-dogfood` package node, following only *normal* and
//! *build* dependency edges (never `dev`, since a dev-dependency is
//! never compiled into a downstream consumer of this crate — see
//! `Cargo.toml`'s `[dev-dependencies]` comment on why `eltanin-protocol`
//! is there at all). A `Cargo.lock`/manifest text scan alone cannot prove
//! a *per-crate* subtree (the lock also lists `eltanin-cli`'s
//! `signal-hook`/`rustix`, which have nothing to do with this crate), so
//! this test asks `cargo` itself.
//!
//! If `cargo metadata` cannot be run at all, this test fails loudly —
//! silently skipping would be exactly the tautology the task forbids.

use std::collections::{HashSet, VecDeque};
use std::process::Command;

use serde_json::Value;

const FORBIDDEN_CRATES: &[&str] = &[
    "reqwest",
    "hyper",
    "ureq",
    "curl",
    "native-tls",
    "tokio-rustls",
    "rustls",
    "socket2",
    "tokio",
    "mio",
];

#[test]
fn eltanin_dogfood_dependency_tree_contains_no_networking_crate() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_manifest = format!("{manifest_dir}/../../Cargo.toml");

    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--manifest-path",
            &workspace_manifest,
        ])
        .output()
        .expect("cargo metadata must run — a failure here is not a pass, it's an unproven claim");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata must produce valid JSON");

    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .expect("resolve.nodes must be an array");

    // Build id -> node lookup, and id -> crate name lookup (from the
    // package list, since a node's own `id` doesn't carry a bare name).
    let packages = metadata["packages"]
        .as_array()
        .expect("packages must be an array");
    let mut name_by_id = std::collections::HashMap::new();
    for pkg in packages {
        let id = pkg["id"].as_str().expect("package id");
        let name = pkg["name"].as_str().expect("package name");
        name_by_id.insert(id.to_string(), name.to_string());
    }
    let mut node_by_id = std::collections::HashMap::new();
    for node in nodes {
        let id = node["id"].as_str().expect("node id").to_string();
        node_by_id.insert(id, node);
    }

    let root_id = name_by_id
        .iter()
        .find(|(_, name)| name.as_str() == "eltanin-dogfood")
        .map(|(id, _)| id.clone())
        .expect("eltanin-dogfood must appear in cargo metadata's package list");

    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(root_id);
    let mut visited_names: Vec<String> = Vec::new();

    while let Some(id) = queue.pop_front() {
        if !visited.insert(id.clone()) {
            continue;
        }
        let name = name_by_id.get(&id).cloned().unwrap_or_default();
        visited_names.push(name);

        let Some(node) = node_by_id.get(&id) else {
            continue;
        };
        let deps = node["deps"].as_array().cloned().unwrap_or_default();
        for dep in deps {
            let dep_kinds = dep["dep_kinds"].as_array().cloned().unwrap_or_default();
            // Follow only normal (kind == null) and build-dependency
            // edges — never `dev`, which is never compiled into a
            // downstream consumer of this crate.
            let follow = dep_kinds.iter().any(|k| {
                let kind = k["kind"].as_str();
                kind.is_none() || kind == Some("build")
            }) || dep_kinds.is_empty();
            if !follow {
                continue;
            }
            if let Some(pkg_id) = dep["pkg"].as_str() {
                queue.push_back(pkg_id.to_string());
            }
        }
    }

    let violations: Vec<&String> = visited_names
        .iter()
        .filter(|name| FORBIDDEN_CRATES.contains(&name.as_str()))
        .collect();

    assert!(
        violations.is_empty(),
        "eltanin-dogfood's resolved (non-dev) dependency tree must contain no networking \
         crate, but found: {violations:?}. Full tree walked: {visited_names:?}"
    );
}
