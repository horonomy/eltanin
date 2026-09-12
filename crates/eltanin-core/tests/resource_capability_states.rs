//! Exhaustive coverage of [`ResourceCapabilities::supports`]'s fail-closed
//! contract (HORO-1011, ADR 0006): `true` iff a capability's state is
//! exactly `SupportState::Supported` — never for `Partial`, `Unsupported`,
//! or an absent (`NotEvaluated`) entry.

use eltanin_core::resource::{Capability, ResourceCapabilities, SupportState};

const ALL_CAPABILITIES: &[Capability] = &[
    Capability::DiscoverResource,
    Capability::ObserveResource,
    Capability::ObserveWorkload,
    Capability::AttributeWorkload,
    Capability::Authorize,
    Capability::ControlledLaunch,
    Capability::DeviceEnforce,
    Capability::DeviceRevoke,
    Capability::Attest,
];

const ALL_STATES: &[SupportState] = &[
    SupportState::Supported,
    SupportState::Partial,
    SupportState::Unsupported,
    SupportState::NotEvaluated,
];

#[test]
fn supports_is_true_only_for_the_supported_state_across_every_dimension() {
    for &capability in ALL_CAPABILITIES {
        for &state in ALL_STATES {
            let caps = ResourceCapabilities::from_states([(capability, state)]);
            assert_eq!(
                caps.supports(capability),
                state == SupportState::Supported,
                "capability {capability:?} in state {state:?} disagreed with supports()"
            );
            assert_eq!(caps.state_of(capability), state);
        }
    }
}

#[test]
fn an_absent_capability_is_not_evaluated_and_never_supported() {
    let caps = ResourceCapabilities::from_states([(Capability::DiscoverResource, SupportState::Supported)]);
    for &capability in ALL_CAPABILITIES {
        if capability == Capability::DiscoverResource {
            continue;
        }
        assert_eq!(caps.state_of(capability), SupportState::NotEvaluated);
        assert!(!caps.supports(capability));
    }
}

#[test]
fn an_empty_capabilities_set_reports_every_dimension_not_evaluated() {
    let caps = ResourceCapabilities::default();
    for &capability in ALL_CAPABILITIES {
        assert_eq!(caps.state_of(capability), SupportState::NotEvaluated);
        assert!(!caps.supports(capability));
    }
}

#[test]
fn new_marks_every_listed_capability_supported_and_nothing_else() {
    let caps = ResourceCapabilities::new([Capability::ControlledLaunch, Capability::Attest]);
    assert!(caps.supports(Capability::ControlledLaunch));
    assert!(caps.supports(Capability::Attest));
    assert!(!caps.supports(Capability::DeviceEnforce));
    assert_eq!(caps.state_of(Capability::DeviceEnforce), SupportState::NotEvaluated);
}

#[test]
fn is_proven_agrees_with_supports_for_every_state() {
    for &state in ALL_STATES {
        assert_eq!(state.is_proven(), state == SupportState::Supported);
    }
}
