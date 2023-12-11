use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stackable_operator::k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use stackable_operator::k8s_openapi::chrono::Utc;
use stackable_operator::kube::CustomResource;
use stackable_operator::kube::ResourceExt;
use stackable_operator::schemars::{self, JsonSchema};

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("{druid_connection} is missing a namespace, this should not happen!"))]
    NoNamespace { druid_connection: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClusterRef {
    pub name: String,
    pub namespace: Option<String>,
}

/// The DruidConnection resource can be used to automatically deploy a Druid datasource in Superset.
/// Learn more about it in the [Superset operator usage guide](DOCS_BASE_URL_PLACEHOLDER/superset/usage-guide/connecting-druid).
#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "superset.stackable.tech",
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
    pub superset: ClusterRef,
    pub druid: ClusterRef,
}

impl DruidConnection {
    pub fn job_name(&self) -> String {
        format!("{}-import", self.name_unchecked())
    }

    pub fn superset_name(&self) -> String {
        self.spec.superset.name.clone()
    }

    pub fn superset_namespace(&self) -> Result<String> {
        if let Some(superset_ns) = &self.spec.superset.namespace {
            Ok(superset_ns.clone())
        } else if let Some(ns) = self.namespace() {
            Ok(ns)
        } else {
            NoNamespaceSnafu {
                druid_connection: self.name_unchecked(),
            }
            .fail()
        }
    }

    pub fn druid_name(&self) -> String {
        self.spec.druid.name.clone()
    }

    pub fn druid_namespace(&self) -> Result<String> {
        if let Some(druid_ns) = &self.spec.druid.namespace {
            Ok(druid_ns.clone())
        } else if let Some(ns) = self.namespace() {
            Ok(ns)
        } else {
            NoNamespaceSnafu {
                druid_connection: self.name_unchecked(),
            }
            .fail()
        }
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
            condition: DruidConnectionStatusCondition::Pending,
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
    Pending,
    Importing,
    Ready,
    Failed,
}
