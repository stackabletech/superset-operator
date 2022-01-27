use serde::{Deserialize, Serialize};
use stackable_operator::k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use stackable_operator::k8s_openapi::chrono::Utc;
use stackable_operator::kube::CustomResource;
use stackable_operator::kube::ResourceExt;
use stackable_operator::schemars::{self, JsonSchema};

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "command.superset.stackable.tech",
    version = "v1alpha1",
    kind = "DruidConnection",
    plural = "druidconnections",
    status = "DruidConnectionStatus",
    namespaced,
    crates(
        kube_core = "stackable_operator::kube::core",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct DruidConnectionSpec {
    pub superset_cluster_name: String,
    pub superset_cluster_namespace: String,
    pub druid_cluster_name: String,
    pub druid_cluster_namespace: String,
}

impl DruidConnection {
    pub fn job_name(&self) -> String {
        format!("{}-import", self.name())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DruidConnectionStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<Time>,
    pub condition: DruidConnectionStatusCondition,
}

impl DruidConnectionStatus {
    pub fn new() -> Self {
        Self {
            started_at: Some(Time(Utc::now())),
            condition: DruidConnectionStatusCondition::Provisioned,
        }
    }

    pub fn importing(&self) -> Self {
        let mut new = self.clone();
        new.condition = DruidConnectionStatusCondition::Importing;
        new
    }

    pub fn ready(&self) -> Self {
        let mut new = self.clone();
        new.condition = DruidConnectionStatusCondition::Ready;
        new
    }

    pub fn failed(&self) -> Self {
        let mut new = self.clone();
        new.condition = DruidConnectionStatusCondition::Failed;
        new
    }
}

impl Default for DruidConnectionStatus {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
pub enum DruidConnectionStatusCondition {
    Provisioned,
    Importing,
    Ready,
    Failed,
}
