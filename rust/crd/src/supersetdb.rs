use crate::{SupersetCluster, APP_NAME};
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::ObjectMetaBuilder,
    commons::product_image_selection::{ProductImage, ResolvedProductImage},
    config::{
        fragment::{self, Fragment, ValidationError},
        merge::Merge,
    },
    k8s_openapi::{apimachinery::pkg::apis::meta::v1::Time, chrono::Utc},
    kube::CustomResource,
    kube::ResourceExt,
    labels::{self, APP_VERSION_LABEL},
    product_logging::{self, spec::Logging},
    schemars::{self, JsonSchema},
};
use strum::{Display, EnumIter};

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("fragment validation failure"))]
    FragmentValidationFailure { source: ValidationError },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(
    Clone,
    Debug,
    Deserialize,
    Display,
    Eq,
    EnumIter,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum Container {
    SupersetInitDb,
    Vector,
}

#[derive(Clone, Debug, Default, Eq, Fragment, JsonSchema, PartialEq)]
#[fragment_attrs(
    derive(
        Clone,
        Debug,
        Default,
        Deserialize,
        Merge,
        JsonSchema,
        PartialEq,
        Serialize
    ),
    serde(rename_all = "camelCase")
)]
pub struct SupersetDbConfig {
    #[fragment_attrs(serde(default))]
    pub logging: Logging<Container>,
}

impl SupersetDbConfig {
    fn default_config() -> SupersetDbConfigFragment {
        SupersetDbConfigFragment {
            logging: product_logging::spec::default_logging(),
        }
    }
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector_aggregator_config_map_name: Option<String>,
    pub config: SupersetDbConfigFragment,
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
                vector_aggregator_config_map_name: superset
                    .spec
                    .vector_aggregator_config_map_name
                    .clone(),
                config: SupersetDbConfigFragment {
                    logging: superset
                        .spec
                        .database_initialization
                        .clone()
                        .unwrap_or_default()
                        .logging,
                },
            },
            status: None,
        })
    }

    pub fn job_name(&self) -> String {
        self.name_unchecked()
    }

    pub fn merged_config(&self) -> Result<SupersetDbConfig, Error> {
        let defaults = SupersetDbConfig::default_config();
        let mut config = self.spec.config.to_owned();
        config.merge(&defaults);
        fragment::validate(config).context(FragmentValidationFailureSnafu)
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
