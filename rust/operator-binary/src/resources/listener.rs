use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder, crd::listener, kvp::ObjectLabels,
    v2::builder::meta::ownerreference_from_resource,
};

use crate::{
    controller::ValidatedCluster,
    crd::{APP_PORT, APP_PORT_NAME},
};

pub const LISTENER_VOLUME_NAME: &str = "listener";
pub const LISTENER_VOLUME_DIR: &str = "/stackable/listener";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to build Metadata"))]
    MetadataBuild {
        source: stackable_operator::builder::meta::Error,
    },
}

pub fn build_group_listener(
    validated: &ValidatedCluster,
    object_labels: ObjectLabels<ValidatedCluster>,
    listener_class: String,
    listener_group_name: String,
) -> Result<listener::v1alpha1::Listener, Error> {
    let metadata = ObjectMetaBuilder::new()
        .name_and_namespace(validated)
        .name(listener_group_name)
        .ownerreference(ownerreference_from_resource(validated, None, Some(true)))
        .with_recommended_labels(&object_labels)
        .context(MetadataBuildSnafu)?
        .build();

    let spec = listener::v1alpha1::ListenerSpec {
        class_name: Some(listener_class),
        ports: Some(listener_ports()),
        ..Default::default()
    };

    let listener = listener::v1alpha1::Listener {
        metadata,
        spec,
        status: None,
    };

    Ok(listener)
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
