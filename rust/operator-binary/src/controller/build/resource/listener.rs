use stackable_operator::{crd::listener, v2::types::kubernetes::ListenerClassName};

use crate::{
    controller::{ValidatedCluster, build::PLACEHOLDER_LISTENER_ROLE_GROUP},
    crd::{APP_PORT, APP_PORT_NAME, SupersetRole},
};

pub const LISTENER_VOLUME_DIR: &str = "/stackable/listener";

pub fn build_group_listener(
    validated: &ValidatedCluster,
    role: &SupersetRole,
    listener_class: &ListenerClassName,
    listener_group_name: String,
) -> listener::v1alpha1::Listener {
    // The group listener is a role-level object, so the constant `none` placeholder role-group is
    // used for the recommended labels.
    let metadata = validated
        .object_meta(listener_group_name, role, &PLACEHOLDER_LISTENER_ROLE_GROUP)
        .build();

    let spec = listener::v1alpha1::ListenerSpec {
        class_name: Some(listener_class.to_string()),
        ports: Some(listener_ports()),
        ..Default::default()
    };

    listener::v1alpha1::Listener {
        metadata,
        spec,
        status: None,
    }
}

pub fn listener_ports() -> Vec<listener::v1alpha1::ListenerPort> {
    vec![listener::v1alpha1::ListenerPort {
        name: APP_PORT_NAME.to_owned(),
        port: APP_PORT.into(),
        protocol: Some(super::PROTOCOL_TCP.to_owned()),
    }]
}
