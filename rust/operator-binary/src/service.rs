use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    commons::product_image_selection::ResolvedProductImage,
    k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec},
    kvp::{Label, Labels},
    role_utils::RoleGroupRef,
};

use crate::{
    crd::{APP_NAME, APP_PORT, APP_PORT_NAME, METRICS_PORT, METRICS_PORT_NAME, v1alpha1},
    superset_controller::SUPERSET_CONTROLLER_NAME,
    util::build_recommended_labels,
};
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },
    #[snafu(display("failed to build Metadata"))]
    MetadataBuild {
        source: stackable_operator::builder::meta::Error,
    },
    #[snafu(display("failed to build Labels"))]
    LabelBuild {
        source: stackable_operator::kvp::LabelError,
    },
}

/// The rolegroup [`Service`] is a headless service that allows direct access to the instances of a certain rolegroup
///
/// This is mostly useful for internal communication between peers, or for clients that perform client-side load balancing.
pub fn build_node_rolegroup_headless_service(
    superset: &v1alpha1::SupersetCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup: &RoleGroupRef<v1alpha1::SupersetCluster>,
) -> Result<Service, Error> {
    let headless_service = Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(superset)
            .name(rolegroup_headless_service_name(rolegroup))
            .ownerreference_from_resource(superset, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                superset,
                SUPERSET_CONTROLLER_NAME,
                &resolved_product_image.app_version_label_value,
                &rolegroup.role,
                &rolegroup.role_group,
            ))
            .context(MetadataBuildSnafu)?
            .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_owned()),
            cluster_ip: Some("None".to_owned()),
            ports: Some(service_ports()),
            selector: Some(
                Labels::role_group_selector(
                    superset,
                    APP_NAME,
                    &rolegroup.role,
                    &rolegroup.role_group,
                )
                .context(LabelBuildSnafu)?
                .into(),
            ),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    };
    Ok(headless_service)
}

/// The rolegroup metrics [`Service`] is a service that exposes metrics and a prometheus scraping label
pub fn build_node_rolegroup_metrics_service(
    superset: &v1alpha1::SupersetCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup: &RoleGroupRef<v1alpha1::SupersetCluster>,
) -> Result<Service, Error> {
    let metrics_service = Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(superset)
            .name(rolegroup_metrics_service_name(rolegroup))
            .ownerreference_from_resource(superset, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                superset,
                SUPERSET_CONTROLLER_NAME,
                &resolved_product_image.app_version_label_value,
                &rolegroup.role,
                &rolegroup.role_group,
            ))
            .context(MetadataBuildSnafu)?
            .with_label(Label::try_from(("prometheus.io/scrape", "true")).context(LabelBuildSnafu)?)
            .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_owned()),
            cluster_ip: Some("None".to_owned()),
            ports: Some(metrics_ports()),
            selector: Some(
                Labels::role_group_selector(
                    superset,
                    APP_NAME,
                    &rolegroup.role,
                    &rolegroup.role_group,
                )
                .context(LabelBuildSnafu)?
                .into(),
            ),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    };

    Ok(metrics_service)
}

/// Headless service for cluster internal purposes only.
// TODO: Move to operator-rs
pub fn rolegroup_headless_service_name(
    rolegroup: &RoleGroupRef<v1alpha1::SupersetCluster>,
) -> String {
    format!("{name}-headless", name = rolegroup.object_name())
}

/// Headless metrics service exposes Prometheus endpoint only
// TODO: Move to operator-rs
pub fn rolegroup_metrics_service_name(
    rolegroup: &RoleGroupRef<v1alpha1::SupersetCluster>,
) -> String {
    format!("{name}-metrics", name = rolegroup.object_name())
}

fn metrics_ports() -> Vec<ServicePort> {
    vec![ServicePort {
        name: Some(METRICS_PORT_NAME.to_string()),
        port: METRICS_PORT.into(),
        protocol: Some("TCP".to_string()),
        ..ServicePort::default()
    }]
}

fn service_ports() -> Vec<ServicePort> {
    vec![ServicePort {
        name: Some(APP_PORT_NAME.to_string()),
        port: APP_PORT.into(),
        protocol: Some("TCP".to_string()),
        ..ServicePort::default()
    }]
}
