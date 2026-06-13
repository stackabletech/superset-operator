use stackable_operator::{
    builder::meta::ObjectMetaBuilder, crd::listener,
    v2::builder::meta::ownerreference_from_resource,
};

use crate::{
    controller::ValidatedCluster,
    crd::{APP_PORT, APP_PORT_NAME, SupersetRole},
};

pub const LISTENER_VOLUME_NAME: &str = "listener";
pub const LISTENER_VOLUME_DIR: &str = "/stackable/listener";

pub fn build_group_listener(
    validated: &ValidatedCluster,
    role: &SupersetRole,
    listener_class: String,
    listener_group_name: String,
) -> listener::v1alpha1::Listener {
    let metadata = ObjectMetaBuilder::new()
        .name_and_namespace(validated)
        .name(listener_group_name)
        .ownerreference(ownerreference_from_resource(validated, None, Some(true)))
        // The group listener is a role-level object, so a constant `none` role-group is used as the
        // role-group label value.
        .with_labels(validated.recommended_labels_for(
            &role.role_name(),
            &"none".parse().expect("'none' is a valid role group name"),
        ))
        .build();

    let spec = listener::v1alpha1::ListenerSpec {
        class_name: Some(listener_class),
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
        protocol: Some("TCP".to_owned()),
    }]
}

pub fn default_listener_class() -> String {
    "cluster-internal".to_string()
}
