//! Dependency-direction guard: `eltanin-agent` (the live enforcement
//! path) must never depend on `eltanin-dogfood` — mirrors
//! `eltanin-audit`'s own `architecture_no_vendor_leak.rs`
//! (`eltanin_audit_never_depends_on_eltanin_linux_or_eltanin_agent`)
//! exactly. This is the mechanical half of the ticket's "never wired
//! into a live sink/enforcement path" requirement: this crate is a
//! read-only reader of the NDJSON log (see `src/lib.rs`'s own docs), and
//! this test proves the live agent binary has no path back into it.

use std::fs;
use std::path::Path;

#[test]
fn eltanin_agent_never_depends_on_eltanin_dogfood() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let agent_manifest = Path::new(manifest_dir).join("../eltanin-agent/Cargo.toml");
    let manifest = fs::read_to_string(&agent_manifest).unwrap_or_else(|e| {
        panic!(
            "failed to read {} — adjust this test if eltanin-agent's crate path ever changes: {e}",
            agent_manifest.display()
        )
    });
    let lower = manifest.to_lowercase();
    assert!(
        !lower.contains("eltanin-dogfood") && !lower.contains("eltanin_dogfood"),
        "eltanin-agent (the live enforcement path) must never depend on eltanin-dogfood — this \
         adapter is a read-only reader of the audit log and must never be reachable from the \
         daemon's own dependency graph"
    );
}
