//! Builders that assemble Kubernetes resources for superset rolegroups.

use std::str::FromStr;

use snafu::{ResultExt, Snafu};
use stackable_operator::v2::types::operator::{ProductVersion, RoleGroupName};

use crate::{
    controller::{
        KubernetesResources, ValidatedCluster,
        build::resource::{
            config_map::build_rolegroup_config_map,
            deployment::build_rolegroup_deployment,
            listener::build_group_listener,
            pdb::build_pdb,
            rbac::{build_role_binding, build_service_account},
            service::{build_rolegroup_headless_service, build_rolegroup_metrics_service},
            statefulset::build_node_rolegroup_statefulset,
        },
    },
    crd::SupersetRole,
};

pub mod command;
pub mod properties;
pub mod resource;

// Placeholder role-group name used for the recommended labels of the role-level `Listener`
// (which is not tied to a single role group).
stackable_operator::constant!(pub(crate) NONE_ROLE_GROUP_NAME: RoleGroupName = "none");

// Product version used for the recommended labels of PVC templates, which cannot be modified after
// deployment. A constant `none` keeps those labels stable across version upgrades.
stackable_operator::constant!(pub(crate) UNVERSIONED_PRODUCT_VERSION: ProductVersion = "none");

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to build ConfigMap for role group {role_group}"))]
    ConfigMap {
        source: resource::config_map::Error,
        role_group: RoleGroupName,
    },

    #[snafu(display("failed to build StatefulSet for role group {role_group}"))]
    StatefulSet {
        source: resource::statefulset::Error,
        role_group: RoleGroupName,
    },

    #[snafu(display("failed to build Deployment for role group {role_group}"))]
    Deployment {
        source: resource::deployment::Error,
        role_group: RoleGroupName,
    },
}

/// Builds every Kubernetes resource for the given validated cluster.
pub fn build(cluster: &ValidatedCluster) -> Result<KubernetesResources, Error> {
    let mut stateful_sets = vec![];
    let mut deployments = vec![];
    let mut services = vec![];
    let mut listeners = vec![];
    let mut config_maps = vec![];
    let mut pod_disruption_budgets = vec![];

    for (superset_role, role_group_configs) in &cluster.role_groups {
        for (role_group_name, rolegroup_config) in role_group_configs {
            let config = &rolegroup_config.config;

            config_maps.push(
                build_rolegroup_config_map(
                    cluster,
                    superset_role,
                    role_group_name,
                    config,
                    &rolegroup_config.config_overrides,
                )
                .context(ConfigMapSnafu {
                    role_group: role_group_name.clone(),
                })?,
            );

            // Every role exposes metrics via the statsd-exporter sidecar, so each rolegroup gets a
            // metrics Service.
            services.push(build_rolegroup_metrics_service(
                cluster,
                superset_role,
                role_group_name,
            ));

            match superset_role {
                SupersetRole::Node => {
                    // Only the `Node` role's StatefulSet references a headless Service (as its
                    // `serviceName`); the `Worker`/`Beat` Deployments have no `serviceName` and do
                    // not serve the HTTP port, so they get no headless Service.
                    services.push(build_rolegroup_headless_service(
                        cluster,
                        superset_role,
                        role_group_name,
                    ));

                    stateful_sets.push(
                        build_node_rolegroup_statefulset(
                            cluster,
                            superset_role,
                            role_group_name,
                            rolegroup_config,
                        )
                        .context(StatefulSetSnafu {
                            role_group: role_group_name.clone(),
                        })?,
                    );
                }
                SupersetRole::Worker | SupersetRole::Beat => {
                    deployments.push(
                        build_rolegroup_deployment(
                            cluster,
                            superset_role,
                            role_group_name,
                            rolegroup_config,
                        )
                        .context(DeploymentSnafu {
                            role_group: role_group_name.clone(),
                        })?,
                    );
                }
            }
        }

        // Role-level resources (group listener, PDB) are built once per role, after its role
        // groups — not once per role group.
        if let Some(role_config) = cluster.role_configs.get(superset_role) {
            if let (Some(listener_class), Some(listener_group_name)) = (
                &role_config.listener_class,
                &role_config.group_listener_name,
            ) {
                listeners.push(build_group_listener(
                    cluster,
                    superset_role,
                    listener_class,
                    listener_group_name.to_string(),
                ));
            }

            if let Some(pdb_config) = &role_config.pdb {
                pod_disruption_budgets.extend(build_pdb(pdb_config, cluster, superset_role));
            }
        }
    }

    Ok(KubernetesResources {
        stateful_sets,
        deployments,
        services,
        listeners,
        config_maps,
        pod_disruption_budgets,
        service_accounts: vec![build_service_account(cluster)],
        role_bindings: vec![build_role_binding(cluster)],
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use stackable_operator::{kube::Resource, utils::yaml_from_str_singleton_map};

    use super::build;
    use crate::{
        controller::{
            ValidatedCluster, test_support::default_dereferenced, validate::validate_cluster,
        },
        crd::v1alpha1,
    };

    /// A validated cluster with a `node`, `worker` and `beat` role (one `default` role group each).
    fn validated_cluster() -> ValidatedCluster {
        let input = r#"
        apiVersion: superset.stackable.tech/v1alpha1
        kind: SupersetCluster
        metadata:
          name: simple-superset
          namespace: default
          uid: 01234567-89ab-cdef-0123-456789abcdef
        spec:
          image:
            productVersion: 4.1.4
          clusterConfig:
            credentialsSecret: superset-admin-credentials
            metadataDatabase:
              postgresql:
                host: superset-postgresql
                database: superset
                credentialsSecretName: superset-postgresql-credentials
          nodes:
            roleGroups:
              default:
                replicas: 1
          workers:
            roleGroups:
              default:
                replicas: 1
          beat:
            roleGroups:
              default:
                replicas: 1
        "#;
        let superset: v1alpha1::SupersetCluster =
            yaml_from_str_singleton_map(input).expect("illegal test input");
        validate_cluster(&superset, default_dereferenced(), "test-repo").expect("validated")
    }

    fn sorted_names(resources: &[impl Resource]) -> Vec<&str> {
        let mut names: Vec<&str> = resources
            .iter()
            .filter_map(|resource| resource.meta().name.as_deref())
            .collect();
        names.sort();
        names
    }

    /// The build step turns a validated cluster into the full set of Kubernetes resources: the
    /// `node` role becomes a StatefulSet, the `worker`/`beat` Celery roles become Deployments, and
    /// each role group additionally gets a ConfigMap and a metrics Service (plus a headless Service
    /// for the `node` role). Role-level Listeners and PDBs are emitted once per role.
    #[test]
    fn build_produces_expected_resource_names() {
        let cluster = validated_cluster();
        let resources = build(&cluster).expect("build succeeds");

        assert_eq!(
            sorted_names(&resources.stateful_sets),
            ["simple-superset-node-default"]
        );
        assert_eq!(
            sorted_names(&resources.deployments),
            [
                "simple-superset-beat-default",
                "simple-superset-worker-default"
            ]
        );
        assert_eq!(
            sorted_names(&resources.config_maps),
            [
                "simple-superset-beat-default",
                "simple-superset-node-default",
                "simple-superset-worker-default",
            ]
        );
        // Only the `node` role serves the web UI and gets a group Listener.
        assert_eq!(sorted_names(&resources.listeners), ["simple-superset-node"]);
        // A default PDB per role.
        assert_eq!(
            sorted_names(&resources.pod_disruption_budgets),
            [
                "simple-superset-beat",
                "simple-superset-node",
                "simple-superset-worker"
            ]
        );
    }

    /// Locks the RBAC resource names, the roleRef, and the recommended label set against
    /// accidental drift. The fixture's cluster name deliberately differs from the product name so
    /// that swapped `name`/`instance` label values cannot pass unnoticed.
    #[test]
    fn build_produces_rbac() {
        let cluster = validated_cluster();
        let resources = build(&cluster).expect("build succeeds");

        assert_eq!(
            sorted_names(&resources.service_accounts),
            ["simple-superset-serviceaccount"]
        );
        assert_eq!(
            sorted_names(&resources.role_bindings),
            ["simple-superset-rolebinding"]
        );

        let expected_labels = BTreeMap::from(
            [
                ("app.kubernetes.io/component", "none"),
                ("app.kubernetes.io/instance", "simple-superset"),
                (
                    "app.kubernetes.io/managed-by",
                    "superset.stackable.tech_supersetcluster",
                ),
                ("app.kubernetes.io/name", "superset"),
                ("app.kubernetes.io/role-group", "none"),
                ("app.kubernetes.io/version", "4.1.4-stackable0.0.0-dev"),
                ("stackable.tech/vendor", "Stackable"),
            ]
            .map(|(key, value)| (key.to_string(), value.to_string())),
        );
        let service_account = resources
            .service_accounts
            .first()
            .expect("a ServiceAccount is built");
        assert_eq!(
            service_account.metadata.labels,
            Some(expected_labels.clone())
        );

        let role_binding = resources
            .role_bindings
            .first()
            .expect("a RoleBinding is built");
        assert_eq!(role_binding.metadata.labels, Some(expected_labels));
        assert_eq!(role_binding.role_ref.name, "superset-clusterrole");
    }
}
