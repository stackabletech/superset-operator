//! Builds the RBAC resources (ServiceAccount + RoleBinding) shared by all role groups.

use stackable_operator::{
    k8s_openapi::api::{core::v1::ServiceAccount, rbac::v1::RoleBinding},
    v2::rbac,
};

use crate::controller::{ValidatedCluster, build::recommended_labels_for_cluster_resources};

/// Builds the [`ServiceAccount`] that the role-group Pods run under.
pub fn build_service_account(cluster: &ValidatedCluster) -> ServiceAccount {
    rbac::build_service_account(
        cluster,
        &cluster.cluster_resource_names(),
        recommended_labels_for_cluster_resources(cluster),
    )
}

/// Builds the [`RoleBinding`] that binds the [`ServiceAccount`] from [`build_service_account`] to
/// the operator-deployed ClusterRole.
pub fn build_role_binding(cluster: &ValidatedCluster) -> RoleBinding {
    rbac::build_role_binding(
        cluster,
        &cluster.cluster_resource_names(),
        recommended_labels_for_cluster_resources(cluster),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::controller::{
        build::test_support::validated_cluster, test_support::app_version_label,
    };

    // `simple-superset` vs `superset`: see the swap-guard note on `validated_cluster`.

    #[test]
    fn test_service_account() {
        let service_account = build_service_account(&validated_cluster());

        assert_eq!(
            json!({
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {
                    // The RBAC resources are cluster-shared, so role and role group are `none`.
                    "labels": {
                        "app.kubernetes.io/instance": "simple-superset",
                        "app.kubernetes.io/managed-by": "superset.stackable.tech_supersetcluster",
                        "app.kubernetes.io/name": "superset",
                        "app.kubernetes.io/version": app_version_label("4.1.4"),
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "simple-superset-serviceaccount",
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
                }
            }),
            serde_json::to_value(service_account).expect("must be serializable")
        );
    }

    #[test]
    fn test_role_binding() {
        let role_binding = build_role_binding(&validated_cluster());

        assert_eq!(
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/instance": "simple-superset",
                        "app.kubernetes.io/managed-by": "superset.stackable.tech_supersetcluster",
                        "app.kubernetes.io/name": "superset",
                        "app.kubernetes.io/version": app_version_label("4.1.4"),
                        "stackable.tech/vendor": "Stackable"
                    },
                    "name": "simple-superset-rolebinding",
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
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "superset-clusterrole"
                },
                "subjects": [
                    {
                        "kind": "ServiceAccount",
                        "name": "simple-superset-serviceaccount",
                        "namespace": "default"
                    }
                ]
            }),
            serde_json::to_value(role_binding).expect("must be serializable")
        );
    }
}
