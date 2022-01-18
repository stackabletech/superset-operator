use serde::{Deserialize, Serialize};
use stackable_operator::k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use stackable_operator::kube::CustomResource;
use stackable_operator::schemars::{self, JsonSchema};

use crate::SupersetClusterRef;

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "command.superset.stackable.tech",
    version = "v1alpha1",
    kind = "Init",
    plural = "inits",
    status = "CommandStatus",
    namespaced,
    crates(
        kube_core = "stackable_operator::kube::core",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct InitCommandSpec {
    pub cluster_ref: SupersetClusterRef,
    pub credentials_secret: String,
    pub load_examples: bool,
}

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "command.superset.stackable.tech",
    version = "v1alpha1",
    kind = "AddDruids",
    plural = "adddruids",
    status = "CommandStatus",
    namespaced,
    crates(
        kube_core = "stackable_operator::kube::core",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct AddDruidsCommandSpec {
    pub cluster_ref: SupersetClusterRef,
    pub credentials_secret: String,
    pub druid_connections: Vec<DruidConnection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DruidConnection {
    /// The Druid Cluster to connect
    pub cluster: String,
    /// The namespace.  If not provided, the same namespace as the superset cluster will be assumed
    pub namespace: Option<String>,
    /// The name, used internally by Superset for display purposes.
    pub name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CommandStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<Time>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<Time>,
}
