//! `ProfileName`/`ProfileDocument` coverage (F-M1-008, HORO-845).

use std::ffi::OsStr;

use eltanin_cli::profile::{ProfileDocument, ProfileName, ProfileNameError};
use eltanin_core::resource::{Action, ResourceIdentity, ResourceKind, ResourceVendor};

#[test]
fn a_simple_name_is_accepted() {
    let name = ProfileName::parse(OsStr::new("dev-workstation")).unwrap();
    assert_eq!(name.as_str(), "dev-workstation");
}

#[test]
fn an_empty_name_is_rejected() {
    assert_eq!(
        ProfileName::parse(OsStr::new("")),
        Err(ProfileNameError::Empty)
    );
}

#[test]
fn a_name_containing_a_slash_is_rejected() {
    assert_eq!(
        ProfileName::parse(OsStr::new("../etc/passwd")),
        Err(ProfileNameError::ContainsSlash)
    );
    assert_eq!(
        ProfileName::parse(OsStr::new("a/b")),
        Err(ProfileNameError::ContainsSlash)
    );
}

#[test]
fn dot_and_dotdot_are_rejected_as_path_traversal() {
    assert_eq!(
        ProfileName::parse(OsStr::new(".")),
        Err(ProfileNameError::PathTraversal)
    );
    assert_eq!(
        ProfileName::parse(OsStr::new("..")),
        Err(ProfileNameError::PathTraversal)
    );
}

#[test]
fn a_name_over_the_length_limit_is_rejected() {
    let long = "a".repeat(65);
    assert_eq!(
        ProfileName::parse(OsStr::new(&long)),
        Err(ProfileNameError::TooLong(65))
    );
}

#[test]
fn a_name_at_the_length_limit_is_accepted() {
    let exactly_64 = "a".repeat(64);
    assert!(ProfileName::parse(OsStr::new(&exactly_64)).is_ok());
}

#[cfg(unix)]
#[test]
fn a_non_utf8_name_is_rejected() {
    use std::os::unix::ffi::OsStrExt;
    let non_utf8 = OsStr::from_bytes(&[0x66, 0xff, 0x6f]);
    assert_eq!(ProfileName::parse(non_utf8), Err(ProfileNameError::NotUtf8));
}

#[test]
fn a_profile_document_round_trips_through_the_versioned_envelope() {
    let document = ProfileDocument {
        resource: ResourceIdentity {
            vendor: ResourceVendor::fake(),
            kind: ResourceKind::gpu(),
            local_id: "gpu-0".to_string(),
        },
        action: Action::Compute,
    };
    let envelope = eltanin_core::envelope::Versioned::current(document.clone());
    let json = serde_json::to_string(&envelope).unwrap();
    let decoded: eltanin_core::envelope::Versioned<ProfileDocument> =
        serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.payload, document);
}

#[test]
fn a_profile_document_carries_no_executable_identity_field() {
    // Structural pin on the design decision: a profile cannot express an
    // executable-identity constraint, so it cannot be misused to smuggle
    // one in. See docs/product/CLI_CONTRACT.md's MVP 1.0 limitation
    // statement.
    let document = ProfileDocument {
        resource: ResourceIdentity {
            vendor: ResourceVendor::fake(),
            kind: ResourceKind::gpu(),
            local_id: "gpu-0".to_string(),
        },
        action: Action::Compute,
    };
    let json = serde_json::to_value(&document).unwrap();
    let object = json.as_object().unwrap();
    assert!(!object.contains_key("executable_path"));
    assert!(!object.contains_key("executable_hash"));
}
