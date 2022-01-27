use crate::{SupersetCluster, APP_NAME};
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::builder::ObjectMetaBuilder;
use stackable_operator::k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use stackable_operator::k8s_openapi::chrono::Utc;
use stackable_operator::kube::CustomResource;
use stackable_operator::kube::ResourceExt;
use stackable_operator::schemars::{self, JsonSchema};

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to retrieve superset version"))]
    NoSupersetVersion,
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, CustomResource, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "command.superset.stackable.tech",
    version = "v1alpha1",
    kind = "SupersetDB",
    plural = "supersetdbs",
    status = "SupersetDBStatus",
    namespaced,
    crates(
        kube_core = "stackable_operator::kube::core",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct SupersetDBSpec {
    pub superset_version: String,
    pub credentials_secret: String,
    pub load_examples: bool,
}

impl SupersetDB {
    /// Returns a SupersetDB resource with the same name, namespace and Superset version as the cluster.
    pub fn for_superset(superset: &SupersetCluster) -> Result<Self> {
        let version = superset
            .spec
            .version
            .as_deref()
            .context(NoSupersetVersionSnafu)?;
        Ok(Self {
            metadata: ObjectMetaBuilder::new()
                .name_and_namespace(superset)
                .ownerreference_from_resource(superset, None, Some(true))
                .context(ObjectMissingMetadataForOwnerRefSnafu)?
                .with_recommended_labels(superset, APP_NAME, version, "", "") // TODO fill in missing fields
                .build(),
            spec: SupersetDBSpec {
                superset_version: version.to_string(),
                credentials_secret: superset.spec.credentials_secret.clone(),
                load_examples: superset.spec.load_examples_on_init.unwrap_or_default(),
            },
            status: Some(SupersetDBStatus::new()),
        })
    }

    pub fn job_name(&self) -> String {
        self.name()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SupersetDBStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<Time>,
    pub condition: SupersetDBStatusCondition,
}

impl SupersetDBStatus {
    pub fn new() -> Self {
        Self {
            started_at: Some(Time(Utc::now())),
            condition: SupersetDBStatusCondition::Provisioned,
        }
    }

    pub fn initializing(&self) -> Self {
        let mut new = self.clone();
        new.condition = SupersetDBStatusCondition::Initializing;
        new
    }

    pub fn ready(&self) -> Self {
        let mut new = self.clone();
        new.condition = SupersetDBStatusCondition::Ready;
        new
    }

    pub fn failed(&self) -> Self {
        let mut new = self.clone();
        new.condition = SupersetDBStatusCondition::Failed;
        new
    }
}

impl Default for SupersetDBStatus {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
pub enum SupersetDBStatusCondition {
    Provisioned,
    Initializing,
    Ready,
    Failed,
}
