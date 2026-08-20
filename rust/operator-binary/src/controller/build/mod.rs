//! Builders that assemble Kubernetes resources for superset rolegroups.

use std::marker::PhantomData;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    kvp::Labels,
    v2::{
        builder::meta::ownerreference_from_resource,
        kvp::label,
        types::operator::{RoleGroupName, RoleName},
    },
};

use crate::{
    controller::{
        CONTROLLER_NAME, KubernetesResources, OPERATOR_NAME, PRODUCT_NAME, Prepared,
        ValidatedCluster,
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
pub fn build(cluster: &ValidatedCluster) -> Result<KubernetesResources<Prepared>, Error> {
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
        status: PhantomData,
    })
}

/// Returns an [`ObjectMetaBuilder`] pre-filled with the namespace, an owner reference back to
/// the cluster, and the recommended labels for a resource named `name` in `role`/
/// `role_group_name`.
///
/// Consolidates the metadata chain repeated by the role-group child-resource builders. Call
/// sites that need extra labels/annotations chain them onto the returned builder.
pub(crate) fn object_meta(
    validated: &ValidatedCluster,
    name: impl Into<String>,
    role: &SupersetRole,
    role_group_name: &RoleGroupName,
) -> ObjectMetaBuilder {
    let mut builder = ObjectMetaBuilder::new();
    builder
        .name_and_namespace(validated)
        .name(name)
        .ownerreference(ownerreference_from_resource(validated, None, Some(true)))
        .with_labels(recommended_labels_for_role_group_resources(
            validated,
            role,
            role_group_name,
        ));
    builder
}

pub(crate) fn recommended_labels_for_cluster_resources(cluster: &ValidatedCluster) -> Labels {
    label::recommended_labels_for_cluster_resources(
        &cluster.name,
        &PRODUCT_NAME,
        &cluster.product_version,
        &OPERATOR_NAME,
        &CONTROLLER_NAME,
    )
}

pub(crate) fn recommended_labels_for_role_resources(
    cluster: &ValidatedCluster,
    role_name: &RoleName,
) -> Labels {
    label::recommended_labels_for_role_resources(
        &cluster.name,
        &PRODUCT_NAME,
        &cluster.product_version,
        &OPERATOR_NAME,
        &CONTROLLER_NAME,
        role_name,
    )
}

pub(crate) fn recommended_labels_for_role_group_resources(
    cluster: &ValidatedCluster,
    role_name: &RoleName,
    role_group_name: &RoleGroupName,
) -> Labels {
    label::recommended_labels_for_role_group_resources(
        &cluster.name,
        &PRODUCT_NAME,
        &cluster.product_version,
        &OPERATOR_NAME,
        &CONTROLLER_NAME,
        role_name,
        role_group_name,
    )
}

pub(crate) fn recommended_labels_for_unversioned_role_group_resources(
    cluster: &ValidatedCluster,
    role_name: &RoleName,
    role_group_name: &RoleGroupName,
) -> Labels {
    label::recommended_labels_for_unversioned_role_group_resources(
        &cluster.name,
        &PRODUCT_NAME,
        &OPERATOR_NAME,
        &CONTROLLER_NAME,
        role_name,
        role_group_name,
    )
}

/// Selector labels matching the pods of a role group.
pub(crate) fn role_group_selector(
    cluster: &ValidatedCluster,
    role_name: &RoleName,
    role_group_name: &RoleGroupName,
) -> Labels {
    label::role_group_selector(&cluster.name, &PRODUCT_NAME, role_name, role_group_name)
}

#[cfg(test)]
pub(crate) mod test_support {
    use stackable_operator::utils::yaml_from_str_singleton_map;

    use crate::{
        controller::{
            ValidatedCluster, test_support::default_dereferenced, validate::validate_cluster,
        },
        crd::v1alpha1,
    };

    /// A validated cluster with a `node`, `worker` and `beat` role (one `default` role group
    /// each).
    ///
    /// The cluster name (`simple-superset`) deliberately differs from the product name
    /// (`superset`), so tests asserting recommended labels catch swapped `name`/`instance`
    /// values.
    pub fn validated_cluster() -> ValidatedCluster {
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
}

#[cfg(test)]
mod tests {
    use stackable_operator::kube::Resource;

    use super::{build, test_support::validated_cluster};

    /// The group listener is a role-level object, so it carries the recommended labels for role
    /// resources: a `component` label for the role, but no `role-group` label.
    #[test]
    fn group_listener_carries_role_level_labels() {
        let cluster = validated_cluster();
        let resources = build(&cluster).expect("build succeeds");

        let listener = resources
            .listeners
            .iter()
            .find(|listener| listener.meta().name.as_deref() == Some("simple-superset-node"))
            .expect("node group listener");
        let labels = listener
            .meta()
            .labels
            .as_ref()
            .expect("the listener has labels");

        assert_eq!(
            labels
                .get("app.kubernetes.io/component")
                .map(String::as_str),
            Some("node")
        );
        assert!(
            !labels.contains_key("app.kubernetes.io/role-group"),
            "a role-level listener must not carry a role-group label"
        );
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
        // The cluster-shared RBAC pair.
        assert_eq!(
            sorted_names(&resources.service_accounts),
            ["simple-superset-serviceaccount"]
        );
        assert_eq!(
            sorted_names(&resources.role_bindings),
            ["simple-superset-rolebinding"]
        );
    }
}
