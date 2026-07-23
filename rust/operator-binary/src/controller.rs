//! Ensures that `Pod`s are configured and running for each [`SupersetCluster`]
pub(crate) mod build;
pub mod dereference;
pub mod validate;
use std::{collections::BTreeMap, str::FromStr, sync::Arc};

use const_format::concatcp;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    cli::OperatorEnvironmentOptions,
    client::Client,
    cluster_resources::ClusterResourceApplyStrategy,
    commons::{
        affinity::StackableAffinity,
        product_image_selection::ResolvedProductImage,
        random_secret_creation::{self, create_random_secret_if_not_exists},
        resources::{NoRuntimeLimits, Resources},
    },
    crd::listener,
    k8s_openapi::api::{
        apps::v1::{Deployment, StatefulSet},
        core::v1::{ConfigMap, Secret, Service, ServiceAccount},
        policy::v1::PodDisruptionBudget,
        rbac::v1::RoleBinding,
    },
    kube::{
        Resource,
        api::ObjectMeta,
        core::{DeserializeGuard, error_boundary},
        runtime::controller::Action,
    },
    kvp::Labels,
    logging::controller::ReconcilerError,
    shared::time::Duration,
    status::condition::{
        compute_conditions, deployment::DeploymentConditionBuilder,
        operations::ClusterOperationsConditionBuilder, statefulset::StatefulSetConditionBuilder,
    },
    v2::{
        HasName, HasUid, NameIsValidLabelValue,
        builder::meta::ownerreference_from_resource,
        cluster_resources::cluster_resources_new,
        kvp::label::{recommended_labels, role_group_selector},
        product_logging::framework::{ValidatedContainerLogConfigChoice, VectorContainerLogConfig},
        role_group_utils::ResourceNames,
        role_utils::{self, GenericCommonConfig, RoleGroupConfig},
        types::{
            kubernetes::{ListenerClassName, ListenerName, NamespaceName, Uid},
            operator::{
                ClusterName, ControllerName, OperatorName, ProductName, ProductVersion,
                RoleGroupName, RoleName,
            },
        },
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};
use tracing::instrument;

use crate::{
    OPERATOR_NAME,
    crd::{
        APP_NAME, INTERNAL_SECRET_SECRET_KEY, SupersetRole,
        authentication::SupersetClientAuthenticationDetailsResolved,
        authorization::SupersetOpaConfigResolved,
        databases::{
            CeleryBrokerConnection, CeleryResultsBackendConnection, MetadataDatabaseConnection,
        },
        v1alpha1::{
            SupersetCluster, SupersetClusterStatus, SupersetConfig, SupersetConfigOverrides,
            SupersetStorageConfig,
        },
    },
};

pub const SUPERSET_CONTROLLER_NAME: &str = "supersetcluster";
pub const SUPERSET_FULL_CONTROLLER_NAME: &str =
    concatcp!(SUPERSET_CONTROLLER_NAME, '.', OPERATOR_NAME);
pub const CONTAINER_IMAGE_BASE_NAME: &str = "superset";

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub operator_environment: OperatorEnvironmentOptions,
}

/// Every Kubernetes resource produced by the build step.
///
/// The `Node` role is provisioned via a `StatefulSet` (it serves the Superset web UI), while the
/// `Worker`/`Beat` Celery roles are provisioned via `Deployment`s; the build step collects both.
pub struct KubernetesResources {
    pub stateful_sets: Vec<StatefulSet>,
    pub deployments: Vec<Deployment>,
    pub services: Vec<Service>,
    pub listeners: Vec<listener::v1alpha1::Listener>,
    pub config_maps: Vec<ConfigMap>,
    pub pod_disruption_budgets: Vec<PodDisruptionBudget>,
    pub service_accounts: Vec<ServiceAccount>,
    pub role_bindings: Vec<RoleBinding>,
}

/// Per-role configuration extracted during validation.
#[derive(Clone, Debug)]
pub struct ValidatedRoleConfig {
    pub pdb: Option<stackable_operator::commons::pdb::PdbConfig>,
    pub listener_class: Option<ListenerClassName>,
    pub group_listener_name: Option<ListenerName>,
}

/// A validated, merged Superset role-group config.
///
/// Aliasing [`RoleGroupConfig`] keeps `replicas` optional (`Option<u16>`), so an
/// unset value is propagated all the way to the StatefulSet/Deployment `replicas` field. That lets
/// an external controller such as a HorizontalPodAutoscaler own the replica count instead of the
/// operator forcing a default.
pub type SupersetRoleGroupConfig =
    RoleGroupConfig<ValidatedSupersetConfig, GenericCommonConfig, SupersetConfigOverrides>;

/// A validated Superset config: the merged [`SupersetConfig`] exploded into named fields, with its
/// raw `logging` replaced by the up-front–validated [`ValidatedLogging`] (so an invalid custom log
/// ConfigMap name or a missing Vector aggregator name fails reconciliation during validation rather
/// than at resource-build time). The raw [`SupersetConfig`] does not survive into this struct, so
/// the build step never sees the un-validated CRD type.
#[derive(Clone, Debug)]
pub struct ValidatedSupersetConfig {
    pub affinity: StackableAffinity,
    pub graceful_shutdown_timeout: Option<Duration>,
    pub logging: ValidatedLogging,
    pub resources: Resources<SupersetStorageConfig, NoRuntimeLimits>,
    pub row_limit: Option<i32>,
    pub webserver_timeout: Option<u32>,
}

impl ValidatedSupersetConfig {
    /// Builds the validated config from the merged [`SupersetConfig`], swapping in the
    /// already-validated logging.
    fn from_merged(merged: SupersetConfig, logging: ValidatedLogging) -> Self {
        Self {
            affinity: merged.affinity,
            graceful_shutdown_timeout: merged.graceful_shutdown_timeout,
            logging,
            resources: merged.resources,
            row_limit: merged.row_limit,
            webserver_timeout: merged.webserver_timeout,
        }
    }
}

/// Validated logging configuration for the Superset and (optional) Vector container.
///
/// Produced up-front by `validate_logging` so that an invalid custom log ConfigMap name or a
/// missing Vector aggregator discovery ConfigMap name fails reconciliation during validation rather
/// than at resource-build time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedLogging {
    pub superset_container: ValidatedContainerLogConfigChoice,
    pub vector_container: Option<VectorContainerLogConfig>,
    pub enable_vector_agent: bool,
}

/// Cluster-wide configuration that applies to every role and role group.
///
/// Carries the dereferenced external references, so every downstream build step reads them from
/// here rather than from the raw cluster object.
#[derive(Clone, Debug)]
pub struct ValidatedClusterConfig {
    pub authentication_config: SupersetClientAuthenticationDetailsResolved,
    pub opa_config: Option<SupersetOpaConfigResolved>,
    /// Name of the Secret holding the admin user credentials.
    pub credentials_secret_name: String,
    /// Name of the auto-generated Secret holding the Flask `SECRET_KEY`.
    pub secret_key_secret_name: String,
    /// Name of the Secret holding the Mapbox API key, if configured.
    pub mapbox_secret: Option<String>,
    /// Connection to the metadata database.
    pub metadata_database: MetadataDatabaseConnection,
    /// Connection to the Celery results backend, if configured.
    pub celery_results_backend: Option<CeleryResultsBackendConnection>,
    /// Connection to the Celery broker, if configured.
    pub celery_broker: Option<CeleryBrokerConnection>,
}

/// The validated cluster: proves that config merging succeeded for every role and role group
/// before any Kubernetes resources are created.
#[derive(Clone, Debug)]
pub struct ValidatedCluster {
    /// `ObjectMeta` carrying `name`, `namespace` and `uid`, captured during validation, so this
    /// struct can stand in as the owner [`Resource`] for child objects.
    metadata: ObjectMeta,
    pub name: ClusterName,
    pub namespace: NamespaceName,
    pub uid: Uid,
    pub product_version: ProductVersion,
    pub image: ResolvedProductImage,
    pub cluster_config: ValidatedClusterConfig,
    pub role_groups: BTreeMap<SupersetRole, BTreeMap<RoleGroupName, SupersetRoleGroupConfig>>,
    pub role_configs: BTreeMap<SupersetRole, ValidatedRoleConfig>,
}

impl ValidatedCluster {
    pub fn new(
        name: ClusterName,
        namespace: NamespaceName,
        uid: Uid,
        image: ResolvedProductImage,
        cluster_config: ValidatedClusterConfig,
        role_groups: BTreeMap<SupersetRole, BTreeMap<RoleGroupName, SupersetRoleGroupConfig>>,
        role_configs: BTreeMap<SupersetRole, ValidatedRoleConfig>,
    ) -> Self {
        let product_version = ProductVersion::from_str(&image.app_version_label_value)
            .expect("the app version label value is a valid product version");
        Self {
            // Capture only the identity fields needed to own child objects, derived from the
            // typed cluster identity rather than the raw CRD.
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                uid: Some(uid.to_string()),
                ..ObjectMeta::default()
            },
            image,
            cluster_config,
            role_groups,
            role_configs,
            name,
            namespace,
            uid,
            product_version,
        }
    }

    pub fn role_group_resource_names(
        &self,
        role: &SupersetRole,
        role_group_name: &RoleGroupName,
    ) -> ResourceNames {
        ResourceNames {
            cluster_name: self.name.clone(),
            role_name: role.role_name(),
            role_group_name: role_group_name.clone(),
        }
    }

    /// Type-safe names for the per-cluster RBAC resources: the ServiceAccount shared by all
    /// Pods, its (namespaced) RoleBinding, and the operator-deployed ClusterRole it binds.
    pub fn cluster_resource_names(&self) -> role_utils::ResourceNames {
        role_utils::ResourceNames {
            cluster_name: self.name.clone(),
            product_name: product_name(),
        }
    }

    pub fn recommended_labels(
        &self,
        role: &SupersetRole,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        self.recommended_labels_for(&role.role_name(), role_group_name)
    }

    pub fn recommended_labels_for(
        &self,
        role_name: &RoleName,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        self.recommended_labels_with(&self.product_version, role_name, role_group_name)
    }

    /// Recommended labels with a constant `none` version, for PVC templates that cannot be modified
    /// after deployment (keeps the labels stable across version upgrades).
    pub fn unversioned_recommended_labels(
        &self,
        role: &SupersetRole,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        self.recommended_labels_with(
            &build::UNVERSIONED_PRODUCT_VERSION,
            &role.role_name(),
            role_group_name,
        )
    }

    fn recommended_labels_with(
        &self,
        product_version: &ProductVersion,
        role_name: &RoleName,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        recommended_labels(
            self,
            &product_name(),
            product_version,
            &operator_name(),
            &controller_name(),
            role_name,
            role_group_name,
        )
    }

    pub fn role_group_selector(
        &self,
        role: &SupersetRole,
        role_group_name: &RoleGroupName,
    ) -> Labels {
        role_group_selector(self, &product_name(), &role.role_name(), role_group_name)
    }

    /// Returns an [`ObjectMetaBuilder`] pre-filled with the namespace, an owner reference back to
    /// this cluster, and the recommended labels for a resource named `name` in `role`/
    /// `role_group_name`.
    ///
    /// Consolidates the metadata chain repeated by the role-group child-resource builders. Call
    /// sites that need extra labels/annotations chain them onto the returned builder.
    pub(crate) fn object_meta(
        &self,
        name: impl Into<String>,
        role: &SupersetRole,
        role_group_name: &RoleGroupName,
    ) -> ObjectMetaBuilder {
        let mut builder = ObjectMetaBuilder::new();
        builder
            .name_and_namespace(self)
            .name(name)
            .ownerreference(ownerreference_from_resource(self, None, Some(true)))
            .with_labels(self.recommended_labels(role, role_group_name));
        builder
    }
}

/// Lets [`ValidatedCluster`] stand in for the raw [`SupersetCluster`] when building owner
/// references and metadata for child objects. Kind/group/version are delegated to the CRD; the
/// `metadata` (name, namespace, uid) is captured during validation.
impl Resource for ValidatedCluster {
    type DynamicType = <SupersetCluster as Resource>::DynamicType;
    type Scope = <SupersetCluster as Resource>::Scope;

    fn kind(dt: &Self::DynamicType) -> std::borrow::Cow<'_, str> {
        SupersetCluster::kind(dt)
    }

    fn group(dt: &Self::DynamicType) -> std::borrow::Cow<'_, str> {
        SupersetCluster::group(dt)
    }

    fn version(dt: &Self::DynamicType) -> std::borrow::Cow<'_, str> {
        SupersetCluster::version(dt)
    }

    fn plural(dt: &Self::DynamicType) -> std::borrow::Cow<'_, str> {
        SupersetCluster::plural(dt)
    }

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }

    fn meta_mut(&mut self) -> &mut ObjectMeta {
        &mut self.metadata
    }
}

impl HasName for ValidatedCluster {
    fn to_name(&self) -> String {
        self.name.to_string()
    }
}

impl HasUid for ValidatedCluster {
    fn to_uid(&self) -> Uid {
        self.uid.clone()
    }
}

impl NameIsValidLabelValue for ValidatedCluster {
    fn to_label_value(&self) -> String {
        self.name.to_label_value()
    }
}

/// The product name (`superset`) as a type-safe label value.
pub(crate) fn product_name() -> ProductName {
    ProductName::from_str(APP_NAME).expect("'superset' is a valid product name")
}

/// The operator name as a type-safe label value.
pub(crate) fn operator_name() -> OperatorName {
    OperatorName::from_str(OPERATOR_NAME).expect("the operator name is a valid label value")
}

/// The controller name as a type-safe label value.
pub(crate) fn controller_name() -> ControllerName {
    ControllerName::from_str(SUPERSET_CONTROLLER_NAME)
        .expect("the controller name is a valid label value")
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to dereference external objects"))]
    Dereference { source: dereference::Error },

    #[snafu(display("failed to validate cluster"))]
    Validate { source: validate::Error },

    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to build the Kubernetes resources"))]
    BuildResources { source: build::Error },

    #[snafu(display("failed to apply Kubernetes resource"))]
    ApplyResource {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("SupersetCluster object is invalid"))]
    InvalidSupersetCluster {
        source: error_boundary::InvalidObject,
    },

    #[snafu(display("failed to create SECRET_KEY secret"))]
    CreateSecretKeySecret {
        source: random_secret_creation::Error,
    },

    #[snafu(display("failed to retrieve credentials secret {secret_name:?}"))]
    RetrieveCredentialsSecret {
        source: stackable_operator::client::Error,
        secret_name: String,
    },

    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to create SECRET_KEY secret from migrated value"))]
    CreateRandomSecret {
        source: stackable_operator::client::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub async fn reconcile_superset(
    superset: Arc<DeserializeGuard<SupersetCluster>>,
    ctx: Arc<Ctx>,
) -> Result<Action> {
    tracing::info!("Starting reconcile");

    let superset = superset
        .0
        .as_ref()
        .map_err(error_boundary::InvalidObject::clone)
        .context(InvalidSupersetClusterSnafu)?;

    let client = &ctx.client;

    let cluster_operation_cond_builder =
        ClusterOperationsConditionBuilder::new(&superset.spec.cluster_config.cluster_operation);

    let dereferenced = dereference::dereference(client, superset)
        .await
        .context(DereferenceSnafu)?;

    let validated = validate::validate_cluster(
        superset,
        dereferenced,
        &ctx.operator_environment.image_repository,
    )
    .context(ValidateSnafu)?;

    let mut cluster_resources = cluster_resources_new(
        &product_name(),
        &operator_name(),
        &controller_name(),
        &validated.name,
        &validated.namespace,
        &validated.uid,
        ClusterResourceApplyStrategy::from(&superset.spec.cluster_config.cluster_operation),
        &superset.spec.object_overrides,
    );

    // TODO: Can be removed after SDP 26.7 is released (it's only a migration from 26.3 - 26.7)
    // (don't forget about the snafu Error variants).
    // Removal is tracked in https://github.com/stackabletech/superset-operator/issues/755
    migrate_legacy_secret_key_secret_from_26_3(superset, &validated, client).await?;
    create_random_secret_if_not_exists(
        &validated.cluster_config.secret_key_secret_name,
        INTERNAL_SECRET_SECRET_KEY,
        256,
        &validated,
        client,
    )
    .await
    .context(CreateSecretKeySecretSnafu)?;

    let resources = build::build(&validated).context(BuildResourcesSnafu)?;

    let mut statefulset_cond_builder = StatefulSetConditionBuilder::default();
    let mut deployment_cond_builder = DeploymentConditionBuilder::default();

    // The StatefulSets/Deployments are applied last, so every ConfigMap and Secret they mount
    // already exists — otherwise a changed mount would restart the Pods.
    // See https://github.com/stackabletech/commons-operator/issues/111 for details.
    for service_account in resources.service_accounts {
        cluster_resources
            .add(client, service_account)
            .await
            .context(ApplyResourceSnafu)?;
    }
    for role_binding in resources.role_bindings {
        cluster_resources
            .add(client, role_binding)
            .await
            .context(ApplyResourceSnafu)?;
    }
    for service in resources.services {
        cluster_resources
            .add(client, service)
            .await
            .context(ApplyResourceSnafu)?;
    }
    for config_map in resources.config_maps {
        cluster_resources
            .add(client, config_map)
            .await
            .context(ApplyResourceSnafu)?;
    }
    for listener in resources.listeners {
        cluster_resources
            .add(client, listener)
            .await
            .context(ApplyResourceSnafu)?;
    }
    for pdb in resources.pod_disruption_budgets {
        cluster_resources
            .add(client, pdb)
            .await
            .context(ApplyResourceSnafu)?;
    }
    for statefulset in resources.stateful_sets {
        statefulset_cond_builder.add(
            cluster_resources
                .add(client, statefulset)
                .await
                .context(ApplyResourceSnafu)?,
        );
    }
    for deployment in resources.deployments {
        deployment_cond_builder.add(
            cluster_resources
                .add(client, deployment)
                .await
                .context(ApplyResourceSnafu)?,
        );
    }

    cluster_resources
        .delete_orphaned_resources(client)
        .await
        .context(DeleteOrphanedResourcesSnafu)?;

    let status = SupersetClusterStatus {
        conditions: compute_conditions(
            superset,
            &[
                &statefulset_cond_builder,
                &deployment_cond_builder,
                &cluster_operation_cond_builder,
            ],
        ),
    };
    client
        .apply_patch_status(OPERATOR_NAME, superset, &status)
        .await
        .context(ApplyStatusSnafu)?;

    Ok(Action::await_change())
}

// TODO: Can be removed after SDP 26.7 is released (it's only a migration from 26.3 - 26.7)
// (don't forget about the snafu Error variants).
// Removal is tracked in https://github.com/stackabletech/superset-operator/issues/755
#[instrument(skip_all)]
async fn migrate_legacy_secret_key_secret_from_26_3(
    superset: &SupersetCluster,
    validated: &ValidatedCluster,
    client: &Client,
) -> Result<()> {
    let old_secret_name = &validated.cluster_config.credentials_secret_name;
    let new_secret_name = &validated.cluster_config.secret_key_secret_name;
    let secret_namespace = &validated.namespace;

    let new_secret = client
        .get_opt::<Secret>(new_secret_name, secret_namespace.as_ref())
        .await
        .with_context(|_| RetrieveCredentialsSecretSnafu {
            secret_name: new_secret_name,
        })?;
    if new_secret.is_some() {
        tracing::debug!("SECRET_KEY Secret already exists, nothing to migrate");
        return Ok(());
    }

    let old_secret = client
        .get_opt::<Secret>(old_secret_name, secret_namespace.as_ref())
        .await
        .with_context(|_| RetrieveCredentialsSecretSnafu {
            secret_name: old_secret_name,
        })?;
    let old_secret_key = old_secret
        .and_then(|secret| secret.data)
        // Note: We remove the key to take ownership
        .and_then(|mut data| data.remove("connections.secretKey"))
        .and_then(|key| String::from_utf8(key.0).ok());
    if let Some(old_secret_key) = old_secret_key {
        tracing::info!(
            old.secret.name = old_secret_name,
            old.secret.namespace = %secret_namespace,
            new.secret.name = new_secret_name,
            new.secret.namespace = %secret_namespace,
            "Migrating old SECRET_KEY to new Secret"
        );

        let secret = Secret {
            metadata: ObjectMetaBuilder::new()
                .name(new_secret_name)
                .namespace(secret_namespace)
                .ownerreference_from_resource(superset, None, Some(true))
                .context(ObjectMissingMetadataForOwnerRefSnafu)?
                .build(),
            string_data: Some(BTreeMap::from([(
                INTERNAL_SECRET_SECRET_KEY.to_string(),
                old_secret_key,
            )])),
            ..Secret::default()
        };
        client
            .create(&secret)
            .await
            .context(CreateRandomSecretSnafu)?;
    }

    Ok(())
}

pub fn error_policy(
    _obj: Arc<DeserializeGuard<SupersetCluster>>,
    error: &Error,
    _ctx: Arc<Ctx>,
) -> Action {
    match error {
        Error::InvalidSupersetCluster { .. } => Action::await_change(),
        _ => Action::requeue(*Duration::from_secs(5)),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::{
        controller::dereference::DereferencedObjects,
        crd::authentication::{
            self, SupersetClientAuthenticationDetailsResolved, v1alpha1::FlaskRolesSyncMoment,
        },
    };

    /// A [`DereferencedObjects`] with no authentication classes and no OPA config, for tests that
    /// build a `ValidatedCluster` without exercising the dereference step.
    pub(crate) fn default_dereferenced() -> DereferencedObjects {
        DereferencedObjects {
            authentication_config: SupersetClientAuthenticationDetailsResolved {
                authentication_classes_resolved: vec![],
                user_registration: true,
                user_registration_role: authentication::DEFAULT_USER_REGISTRATION_ROLE.to_string(),
                sync_roles_at: FlaskRolesSyncMoment::default(),
            },
            opa_config: None,
        }
    }
}
