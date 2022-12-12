use crate::{SupersetCluster, APP_NAME};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stackable_operator::builder::ObjectMetaBuilder;
use stackable_operator::commons::product_image_selection::{ProductImage, ResolvedProductImage};
use stackable_operator::k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use stackable_operator::k8s_openapi::chrono::Utc;
use stackable_operator::kube::CustomResource;
use stackable_operator::kube::ResourceExt;
use stackable_operator::labels::{self, APP_VERSION_LABEL};
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

#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "superset.stackable.tech",
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
    /// The Superset image to use<
    pub image: ProductImage,
    pub credentials_secret: String,
    pub load_examples: bool,
}

impl SupersetDB {
    /// Returns a SupersetDB resource with the same name, namespace and Superset version as the cluster.
    pub fn for_superset(
        superset: &SupersetCluster,
        resolved_product_image: &ResolvedProductImage,
    ) -> Result<Self> {
        Ok(Self {
            // The db is deliberately not owned by the cluster so it doesn't get deleted when the
            // cluster gets deleted.  The schema etc. still exists in the postgres db and can be reused
            // when the cluster is created again.
            metadata: ObjectMetaBuilder::new()
                .name_and_namespace(superset)
                .with_labels(labels::build_common_labels_for_all_managed_resources(
                    &superset.name_any(),
                    APP_NAME,
                ))
                .with_label(APP_VERSION_LABEL, &resolved_product_image.app_version_label)
                .build(),
            spec: SupersetDBSpec {
                image: superset.spec.image.clone(),
                credentials_secret: superset.spec.credentials_secret.clone(),
                load_examples: superset.spec.load_examples_on_init.unwrap_or_default(),
            },
            status: None,
        })
    }

    pub fn job_name(&self) -> String {
        self.name_unchecked()
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
            condition: SupersetDBStatusCondition::Pending,
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
    Pending,
    Initializing,
    Ready,
    Failed,
}
