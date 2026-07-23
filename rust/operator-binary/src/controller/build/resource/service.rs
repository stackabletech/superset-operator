use stackable_operator::{
    k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec},
    v2::{
        builder::service::{Scheme, Scraping, prometheus_annotations, prometheus_labels},
        types::operator::RoleGroupName,
    },
};

use crate::{
    controller::ValidatedCluster,
    crd::{APP_PORT, APP_PORT_NAME, METRICS_PORT, METRICS_PORT_NAME, SupersetRole},
};

/// Service type for the cluster-internal rolegroup services.
const SERVICE_TYPE_CLUSTER_IP: &str = "ClusterIP";
/// `clusterIP: None` marks a [`Service`] as headless.
const SERVICE_CLUSTER_IP_NONE: &str = "None";

/// The rolegroup [`Service`] is a headless service that allows direct access to the instances of a certain rolegroup
///
/// This is mostly useful for internal communication between peers, or for clients that perform client-side load balancing.
pub fn build_rolegroup_headless_service(
    validated: &ValidatedCluster,
    role: &SupersetRole,
    role_group_name: &RoleGroupName,
) -> Service {
    Service {
        metadata: validated
            .object_meta(
                validated
                    .role_group_resource_names(role, role_group_name)
                    .headless_service_name()
                    .to_string(),
                role,
                role_group_name,
            )
            .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some(SERVICE_TYPE_CLUSTER_IP.to_owned()),
            cluster_ip: Some(SERVICE_CLUSTER_IP_NONE.to_owned()),
            ports: Some(service_ports()),
            selector: Some(validated.role_group_selector(role, role_group_name).into()),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    }
}

/// The rolegroup metrics [`Service`] is a service that exposes metrics and a prometheus scraping label
pub fn build_rolegroup_metrics_service(
    validated: &ValidatedCluster,
    role: &SupersetRole,
    role_group_name: &RoleGroupName,
) -> Service {
    let resource_names = validated.role_group_resource_names(role, role_group_name);
    Service {
        metadata: validated
            .object_meta(
                resource_names.metrics_service_name().to_string(),
                role,
                role_group_name,
            )
            .with_labels(prometheus_labels(&Scraping::Enabled))
            .with_annotations(prometheus_annotations(
                &Scraping::Enabled,
                &Scheme::Http,
                "/metrics",
                &METRICS_PORT,
            ))
            .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some(SERVICE_TYPE_CLUSTER_IP.to_owned()),
            cluster_ip: Some(SERVICE_CLUSTER_IP_NONE.to_owned()),
            ports: Some(metrics_ports()),
            selector: Some(validated.role_group_selector(role, role_group_name).into()),
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
        protocol: Some(super::PROTOCOL_TCP.to_string()),
        ..ServicePort::default()
    }]
}

fn service_ports() -> Vec<ServicePort> {
    vec![ServicePort {
        name: Some(APP_PORT_NAME.to_string()),
        port: APP_PORT.into(),
        protocol: Some(super::PROTOCOL_TCP.to_string()),
        ..ServicePort::default()
    }]
}
