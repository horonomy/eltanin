//! Profile filesystem loader coverage (F-M1-008, HORO-846).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use eltanin_cli::profile::{load_profile_from_dir, profile_dir, ProfileLoadError, ProfileName};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn temp_profile_dir() -> PathBuf {
    let n = NEXT_DIR.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "eltanin-cli-profile-loader-{}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn name(raw: &str) -> ProfileName {
    ProfileName::parse(std::ffi::OsStr::new(raw)).unwrap()
}

#[test]
fn a_valid_profile_document_loads() {
    let dir = temp_profile_dir();
    std::fs::write(
        dir.join("dev.json"),
        include_str!("fixtures/example_profile.json"),
    )
    .unwrap();

    let document = load_profile_from_dir(&dir, &name("dev")).unwrap();
    assert_eq!(document.resource.local_id, "gpu-0");
}

#[test]
fn a_missing_profile_names_the_path_it_tried() {
    let dir = temp_profile_dir();
    let error = load_profile_from_dir(&dir, &name("missing")).unwrap_err();
    match error {
        ProfileLoadError::NotFound { name, path } => {
            assert_eq!(name, "missing");
            assert_eq!(path, dir.join("missing.json"));
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn a_malformed_json_profile_is_reported_as_json() {
    let dir = temp_profile_dir();
    std::fs::write(dir.join("bad.json"), "{ not json").unwrap();
    assert!(matches!(
        load_profile_from_dir(&dir, &name("bad")),
        Err(ProfileLoadError::Json { .. })
    ));
}

#[test]
fn an_unsupported_schema_version_is_reported_as_version() {
    let dir = temp_profile_dir();
    std::fs::write(
        dir.join("skewed.json"),
        r#"{"version":9999,"payload":{"resource":{"vendor":"fake","kind":"gpu","local_id":"gpu-0"},"action":"compute"}}"#,
    )
    .unwrap();
    assert!(matches!(
        load_profile_from_dir(&dir, &name("skewed")),
        Err(ProfileLoadError::Version { .. })
    ));
}

/// The only test in this binary that touches process-global env vars —
/// safe from self-races since nothing else in this file does.
#[test]
fn eltanin_profile_dir_takes_precedence_over_xdg_config_home() {
    let saved_profile_dir = std::env::var_os("ELTANIN_PROFILE_DIR");
    let saved_xdg = std::env::var_os("XDG_CONFIG_HOME");

    std::env::set_var("ELTANIN_PROFILE_DIR", "/explicit/profile/dir");
    std::env::set_var("XDG_CONFIG_HOME", "/xdg/config/home");
    let resolved = profile_dir().unwrap();

    match saved_profile_dir {
        Some(v) => std::env::set_var("ELTANIN_PROFILE_DIR", v),
        None => std::env::remove_var("ELTANIN_PROFILE_DIR"),
    }
    match saved_xdg {
        Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
        None => std::env::remove_var("XDG_CONFIG_HOME"),
    }

    assert_eq!(resolved, PathBuf::from("/explicit/profile/dir"));
}
