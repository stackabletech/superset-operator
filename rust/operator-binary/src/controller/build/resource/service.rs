use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec},
    kvp::{Annotations, Labels},
    v2::{builder::meta::ownerreference_from_resource, types::operator::RoleGroupName},
};

use crate::{
    controller::ValidatedCluster,
    crd::{APP_PORT, APP_PORT_NAME, METRICS_PORT, METRICS_PORT_NAME, SupersetRole},
};

/// The rolegroup [`Service`] is a headless service that allows direct access to the instances of a certain rolegroup
///
/// This is mostly useful for internal communication between peers, or for clients that perform client-side load balancing.
pub fn build_node_rolegroup_headless_service(
    validated: &ValidatedCluster,
    role_group_name: &RoleGroupName,
) -> Service {
    Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(validated)
            .name(
                validated
                    .resource_names(&SupersetRole::Node, role_group_name)
                    .headless_service_name()
                    .to_string(),
            )
            .ownerreference(ownerreference_from_resource(validated, None, Some(true)))
            .with_labels(validated.recommended_labels(&SupersetRole::Node, role_group_name))
            .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_owned()),
            cluster_ip: Some("None".to_owned()),
            ports: Some(service_ports()),
            selector: Some(
                validated
                    .role_group_selector(&SupersetRole::Node, role_group_name)
                    .into(),
            ),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    }
}

/// The rolegroup metrics [`Service`] is a service that exposes metrics and a prometheus scraping label
pub fn build_node_rolegroup_metrics_service(
    validated: &ValidatedCluster,
    role_group_name: &RoleGroupName,
) -> Service {
    let resource_names = validated.resource_names(&SupersetRole::Node, role_group_name);
    Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(validated)
            // `ResourceNames` has no metrics-service helper, so the `-metrics` suffix is appended to
            // the qualified role-group name (which is also the StatefulSet name).
            .name(format!("{}-metrics", resource_names.stateful_set_name()))
            .ownerreference(ownerreference_from_resource(validated, None, Some(true)))
            .with_labels(validated.recommended_labels(&SupersetRole::Node, role_group_name))
            .with_labels(prometheus_labels())
            .with_annotations(prometheus_annotations())
            .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_owned()),
            cluster_ip: Some("None".to_owned()),
            ports: Some(metrics_ports()),
            selector: Some(
                validated
                    .role_group_selector(&SupersetRole::Node, role_group_name)
                    .into(),
            ),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    }
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
/// Common labels for Prometheus
fn prometheus_labels() -> Labels {
    Labels::try_from([("prometheus.io/scrape", "true")]).expect("should be a valid label")
}

/// Common annotations for Prometheus
///
/// These annotations can be used in a ServiceMonitor.
///
/// see also <https://github.com/prometheus-community/helm-charts/blob/prometheus-27.32.0/charts/prometheus/values.yaml#L983-L1036>
fn prometheus_annotations() -> Annotations {
    Annotations::try_from([
        ("prometheus.io/path".to_owned(), "/metrics".to_owned()),
        ("prometheus.io/port".to_owned(), METRICS_PORT.to_string()),
        ("prometheus.io/scheme".to_owned(), "http".to_owned()),
        ("prometheus.io/scrape".to_owned(), "true".to_owned()),
    ])
    .expect("should be valid annotations")
}
