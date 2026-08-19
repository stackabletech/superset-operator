use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    crd::listener,
    v2::{builder::meta::ownerreference_from_resource, types::kubernetes::ListenerClassName},
};

use crate::{
    controller::{ValidatedCluster, build::recommended_labels_for_role_resources},
    crd::{APP_PORT, APP_PORT_NAME, SupersetRole},
};

pub const LISTENER_VOLUME_DIR: &str = "/stackable/listener";

pub fn build_group_listener(
    validated: &ValidatedCluster,
    role: &SupersetRole,
    listener_class: &ListenerClassName,
    listener_group_name: String,
) -> listener::v1alpha1::Listener {
    // The group listener is a role-level object, so it carries the recommended labels for role
    // resources (no role-group label).
    let metadata = ObjectMetaBuilder::new()
        .name_and_namespace(validated)
        .name(listener_group_name)
        .ownerreference(ownerreference_from_resource(validated, None, Some(true)))
        .with_labels(recommended_labels_for_role_resources(validated, role))
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
