use stackable_operator::{
    k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec},
    v2::{
        builder::service::{Scheme, Scraping, prometheus_annotations, prometheus_labels},
        types::operator::RoleGroupName,
    },
};

use crate::{
    controller::{ValidatedCluster, build::object_meta},
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
        metadata: object_meta(
            validated,
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
        metadata: object_meta(
            validated,
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

#[cfg(test)]
mod tests {
    use serde_json::json;
    use stackable_operator::v2::types::operator::RoleGroupName;

    use super::*;
    use crate::controller::{
        build::test_support::validated_cluster, test_support::app_version_label,
    };

    /// Every metrics Service must carry the Prometheus scrape label and the
    /// `prometheus.io/path|port|scheme|scrape` annotations, or Prometheus stops discovering the
    /// endpoints.
    #[test]
    fn test_rolegroup_metrics_service() {
        let validated = validated_cluster();
        let role_group_name: RoleGroupName = "default".parse().expect("valid role group name");

        let service =
            build_rolegroup_metrics_service(&validated, &SupersetRole::Node, &role_group_name);

        assert_eq!(
            json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "annotations": {
                        "prometheus.io/path": "/metrics",
                        "prometheus.io/port": "9102",
                        "prometheus.io/scheme": "http",
                        "prometheus.io/scrape": "true"
                    },
                    "labels": {
                        "app.kubernetes.io/component": "node",
                        "app.kubernetes.io/instance": "simple-superset",
                        "app.kubernetes.io/managed-by": "superset.stackable.tech_supersetcluster",
                        "app.kubernetes.io/name": "superset",
                        "app.kubernetes.io/role-group": "default",
                        "app.kubernetes.io/version": app_version_label("4.1.4"),
                        "prometheus.io/scrape": "true",
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "simple-superset-node-default-metrics",
                    "namespace": "default",
                    "ownerReferences": [
                        {
                            "apiVersion": "superset.stackable.tech/v1alpha1",
                            "controller": true,
                            "kind": "SupersetCluster",
                            "name": "simple-superset",
                            "uid": "01234567-89ab-cdef-0123-456789abcdef"
                        }
                    ]
                },
                "spec": {
                    "clusterIP": "None",
                    "ports": [
                        {
                            "name": "metrics",
                            "port": 9102,
                            "protocol": "TCP"
                        }
                    ],
                    "publishNotReadyAddresses": true,
                    "selector": {
                        "app.kubernetes.io/component": "node",
                        "app.kubernetes.io/instance": "simple-superset",
                        "app.kubernetes.io/name": "superset",
                        "app.kubernetes.io/role-group": "default"
                    },
                    "type": "ClusterIP"
                }
            }),
            serde_json::to_value(service).expect("must be serializable")
        );
    }
}
