use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stackable_operator::{
    k8s_openapi::{apimachinery::pkg::apis::meta::v1::Time, chrono::Utc},
    kube::{CustomResource, ResourceExt},
    schemars::{self, JsonSchema},
};
use stackable_versioned::versioned;

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("{druid_connection} is missing a namespace, this should not happen!"))]
    NoNamespace { druid_connection: String },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[versioned(version(name = "v1alpha1"))]
pub mod versioned {
    /// The DruidConnection resource can be used to automatically deploy a Druid datasource in Superset.
    /// Learn more about it in the [Superset operator usage guide](DOCS_BASE_URL_PLACEHOLDER/superset/usage-guide/connecting-druid).
    #[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[versioned(k8s(
        group = "superset.stackable.tech",
        plural = "druidconnections",
        status = "DruidConnectionStatus",
        namespaced,
        crates(
            kube_core = "stackable_operator::kube::core",
            k8s_openapi = "stackable_operator::k8s_openapi",
            schemars = "stackable_operator::schemars"
        )
    ))]
    #[serde(rename_all = "camelCase")]
    pub struct DruidConnectionSpec {
        /// The Superset to connect.
        pub superset: v1alpha1::ClusterRef,
        /// The Druid to connect.
        pub druid: v1alpha1::ClusterRef,
    }

    #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ClusterRef {
        /// The name of the stacklet.
        pub name: String,
        /// The namespace. Defaults to the namespace of the `DruidConnection` if it is not specified.
        pub namespace: Option<String>,
    }

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
    #[serde(rename_all = "camelCase")]
    pub struct DruidConnectionStatus {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub started_at: Option<Time>,
        pub condition: v1alpha1::DruidConnectionStatusCondition,
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
    pub enum DruidConnectionStatusCondition {
        Pending,
        Importing,
        Ready,
        Failed,
    }
}

impl v1alpha1::DruidConnection {
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

impl v1alpha1::DruidConnectionStatus {
    pub fn new() -> Self {
        Self {
            started_at: Some(Time(Utc::now())),
            condition: v1alpha1::DruidConnectionStatusCondition::Pending,
        }
    }

    pub fn importing(&self) -> Self {
        let mut new = self.clone();
        new.condition = v1alpha1::DruidConnectionStatusCondition::Importing;
        new
    }

    pub fn ready(&self) -> Self {
        let mut new = self.clone();
        new.condition = v1alpha1::DruidConnectionStatusCondition::Ready;
        new
    }

    pub fn failed(&self) -> Self {
        let mut new = self.clone();
        new.condition = v1alpha1::DruidConnectionStatusCondition::Failed;
        new
    }
}

impl Default for v1alpha1::DruidConnectionStatus {
    fn default() -> Self {
        Self::new()
    }
}
