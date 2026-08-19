//! Ensures that `Pod`s are configured and running for each [`SupersetCluster`]
pub mod apply;
pub(crate) mod build;
pub mod dereference;
pub mod update_status;
pub mod validate;
use std::{collections::BTreeMap, marker::PhantomData, str::FromStr, sync::Arc};

use const_format::concatcp;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    cluster_resources::ClusterResourceApplyStrategy,
    commons::{
        affinity::StackableAffinity,
        product_image_selection::ResolvedProductImage,
        resources::{NoRuntimeLimits, Resources},
    },
    constant,
    crd::listener,
    k8s_openapi::api::{
        apps::v1::{Deployment, StatefulSet},
        core::v1::{ConfigMap, Service, ServiceAccount},
        policy::v1::PodDisruptionBudget,
        rbac::v1::RoleBinding,
    },
    kube::{
        Resource,
        api::ObjectMeta,
        core::{DeserializeGuard, error_boundary},
        runtime::controller::Action,
    },
    logging::controller::ReconcilerError,
    shared::time::Duration,
    v2::{
        HasName, HasUid, NameIsValidLabelValue,
        product_logging::framework::{ValidatedContainerLogConfigChoice, VectorContainerLogConfig},
        role_group_utils::ResourceNames,
        role_utils::{self, GenericCommonConfig, RoleGroupConfig},
        types::{
            kubernetes::{ListenerClassName, ListenerName, NamespaceName, SecretName, Uid},
            operator::{
                ClusterName, ControllerName, OperatorName, ProductName, ProductVersion,
                RoleGroupName,
            },
        },
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    SUPERSET_OPERATOR_NAME,
    controller::{
        apply::{Applier, ensure_secrets},
        update_status::update_status,
    },
    crd::{
        APP_NAME, SupersetRole,
        authentication::SupersetClientAuthenticationDetailsResolved,
        authorization::SupersetOpaConfigResolved,
        databases::{
            CeleryBrokerConnection, CeleryResultsBackendConnection, MetadataDatabaseConnection,
        },
        v1alpha1::{
            SupersetCluster, SupersetConfig, SupersetConfigOverrides, SupersetStorageConfig,
        },
    },
};

pub const SUPERSET_CONTROLLER_NAME: &str = "supersetcluster";
pub const SUPERSET_FULL_CONTROLLER_NAME: &str =
    concatcp!(SUPERSET_CONTROLLER_NAME, '.', SUPERSET_OPERATOR_NAME);
pub const CONTAINER_IMAGE_BASE_NAME: &str = "superset";

constant!(pub(crate) PRODUCT_NAME: ProductName = APP_NAME);
constant!(pub(crate) OPERATOR_NAME: OperatorName = SUPERSET_OPERATOR_NAME);
constant!(pub(crate) CONTROLLER_NAME: ControllerName = SUPERSET_CONTROLLER_NAME);

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub operator_environment: OperatorEnvironmentOptions,
}

/// Marker for prepared Kubernetes resources which are not applied yet.
pub struct Prepared;

/// Marker for Kubernetes resources which are already applied.
pub struct Applied;

/// Every Kubernetes resource produced by the build step.
///
/// The `Node` role is provisioned via a `StatefulSet` (it serves the Superset web UI), while the
/// `Worker`/`Beat` Celery roles are provisioned via `Deployment`s; the build step collects both.
///
/// `T` marks whether these resources are merely [`Prepared`] or already [`Applied`]. The marker
/// lets the compiler prove that the cluster status is derived from the applied resources (which
/// carry the state the API server returned) rather than from the built ones.
pub struct KubernetesResources<T> {
    pub stateful_sets: Vec<StatefulSet>,
    pub deployments: Vec<Deployment>,
    pub services: Vec<Service>,
    pub listeners: Vec<listener::v1alpha1::Listener>,
    pub config_maps: Vec<ConfigMap>,
    pub pod_disruption_budgets: Vec<PodDisruptionBudget>,
    pub service_accounts: Vec<ServiceAccount>,
    pub role_bindings: Vec<RoleBinding>,
    pub status: PhantomData<T>,
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
    pub credentials_secret_name: SecretName,
    /// Name of the auto-generated Secret holding the Flask `SECRET_KEY`.
    pub secret_key_secret_name: SecretName,
    /// Name of the Secret holding the Mapbox API key, if configured.
    pub mapbox_secret: Option<SecretName>,
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
            role_name: role.into(),
            role_group_name: role_group_name.clone(),
        }
    }

    /// Type-safe names for the per-cluster RBAC resources: the ServiceAccount shared by all
    /// Pods, its (namespaced) RoleBinding, and the operator-deployed ClusterRole it binds.
    pub fn cluster_resource_names(&self) -> role_utils::ResourceNames {
        role_utils::ResourceNames {
            cluster_name: self.name.clone(),
            product_name: PRODUCT_NAME.clone(),
        }
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

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to dereference external objects"))]
    Dereference { source: dereference::Error },

    #[snafu(display("failed to validate cluster"))]
    Validate { source: validate::Error },

    #[snafu(display("failed to build the Kubernetes resources"))]
    BuildResources { source: build::Error },

    #[snafu(display("failed to ensure the SECRET_KEY Secret exists"))]
    EnsureSecrets { source: apply::Error },

    #[snafu(display("failed to apply the Kubernetes resources"))]
    ApplyResources { source: apply::Error },

    #[snafu(display("failed to update the cluster status"))]
    UpdateStatus { source: update_status::Error },

    #[snafu(display("SupersetCluster object is invalid"))]
    InvalidSupersetCluster {
        source: error_boundary::InvalidObject,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

/// Reconcile function of the SupersetCluster controller.
///
/// The reconcile function performs the following steps:
/// 1. Dereference the objects the SupersetCluster refers to (client required).
/// 2. Validate the cluster specification together with the dereferenced objects, yielding a
///    [`ValidatedCluster`] (no client required).
/// 3. Build the Kubernetes resource specifications from the validated cluster (no client
///    required).
/// 4. Ensure the Secrets exist that the resources mount but that the operator cannot build,
///    because their value has to be generated once and then kept (client required).
/// 5. Apply the resource specifications and delete the orphaned ones (client required).
/// 6. Update the cluster status from the applied resources (client required).
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

    let dereferenced = dereference::dereference(client, superset)
        .await
        .context(DereferenceSnafu)?;

    let validated = validate::validate_cluster(
        superset,
        dereferenced,
        &ctx.operator_environment.image_repository,
    )
    .context(ValidateSnafu)?;

    let resources = build::build(&validated).context(BuildResourcesSnafu)?;

    ensure_secrets(client, &validated)
        .await
        .context(EnsureSecretsSnafu)?;

    let applied = Applier::new(
        client,
        &validated,
        ClusterResourceApplyStrategy::from(&superset.spec.cluster_config.cluster_operation),
        &superset.spec.object_overrides,
    )
    .apply(resources)
    .await
    .context(ApplyResourcesSnafu)?;

    update_status(client, superset, &applied)
        .await
        .context(UpdateStatusSnafu)?;

    Ok(Action::await_change())
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
    /// The expected `app.kubernetes.io/version` label value for the given product version.
    ///
    /// The `-stackable` suffix carries the operator's own version, which is `0.0.0-dev` on main
    /// but rewritten by the release process — so tests must derive it rather than hardcode it,
    /// or they fail on release branches.
    pub fn app_version_label(product_version: &str) -> String {
        format!(
            "{product_version}-stackable{}",
            crate::built_info::PKG_VERSION
        )
    }

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

#[cfg(test)]
mod controller_tests {
    use super::{CONTROLLER_NAME, OPERATOR_NAME, PRODUCT_NAME};

    #[test]
    fn test_constants() {
        // Test that dereferencing the constants does not panic.
        let _ = *PRODUCT_NAME;
        let _ = *OPERATOR_NAME;
        let _ = *CONTROLLER_NAME;
    }
}
