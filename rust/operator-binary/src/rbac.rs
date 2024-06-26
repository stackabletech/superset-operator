use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    k8s_openapi::api::{
        core::v1::ServiceAccount,
        rbac::v1::{RoleBinding, RoleRef, Subject},
    },
    kube::{Resource, ResourceExt},
};

/// Obsolete: only used in the DB controller for historical reasons. Scheduled for deletion
/// once the entire DB controller is deleted as discused here: <https://github.com/stackabletech/superset-operator/issues/351>
///
/// Build RBAC objects for the product workloads.
/// The `rbac_prefix` is meant to be the product name, for example: zookeeper, airflow, etc.
/// and it is a assumed that a ClusterRole named `{rbac_prefix}-clusterrole` exists.
pub fn build_rbac_resources<T: Resource>(
    resource: &T,
    rbac_prefix: &str,
) -> (ServiceAccount, RoleBinding) {
    let sa_name = format!("{rbac_prefix}-sa");
    let service_account = ServiceAccount {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(resource)
            .name(sa_name.clone())
            .build(),
        ..ServiceAccount::default()
    };

    let role_binding = RoleBinding {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(resource)
            .name(format!("{rbac_prefix}-rolebinding"))
            .build(),
        role_ref: RoleRef {
            kind: "ClusterRole".to_string(),
            name: format!("{rbac_prefix}-clusterrole"),
            api_group: "rbac.authorization.k8s.io".to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: sa_name,
            namespace: resource.namespace(),
            ..Subject::default()
        }]),
    };

    (service_account, role_binding)
}
