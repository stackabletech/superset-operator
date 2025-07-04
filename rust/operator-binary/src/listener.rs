use snafu::{ResultExt, Snafu};
use stackable_operator::{builder::meta::ObjectMetaBuilder, crd::listener, kvp::ObjectLabels};

use crate::crd::{APP_PORT, APP_PORT_NAME, v1alpha1};

pub const LISTENER_VOLUME_NAME: &str = "listener";
pub const LISTENER_VOLUME_DIR: &str = "/stackable/listener";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },
    #[snafu(display("failed to build Metadata"))]
    MetadataBuild {
        source: stackable_operator::builder::meta::Error,
    },
}

pub fn build_group_listener(
    superset: &v1alpha1::SupersetCluster,
    object_labels: ObjectLabels<v1alpha1::SupersetCluster>,
    listener_class: String,
    listener_group_name: String,
) -> Result<listener::v1alpha1::Listener, Error> {
    let metadata = ObjectMetaBuilder::new()
        .name_and_namespace(superset)
        .name(listener_group_name)
        .ownerreference_from_resource(superset, None, Some(true))
        .context(ObjectMissingMetadataForOwnerRefSnafu)?
        .with_recommended_labels(object_labels)
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
