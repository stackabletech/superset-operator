//! Ensures that `Pod`s are configured and running for each [`SupersetCluster`]
pub(crate) mod build;
pub mod dereference;
pub mod validate;
use std::{collections::BTreeMap, str::FromStr, sync::Arc};

use const_format::concatcp;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    commons::{
        product_image_selection::ResolvedProductImage, random_secret_creation,
        rbac::build_rbac_resources,
    },
    kube::{
        Resource, ResourceExt,
        api::ObjectMeta,
        core::{DeserializeGuard, error_boundary},
        runtime::controller::Action,
    },
    kvp::Labels,
    logging::controller::ReconcilerError,
    role_utils::RoleGroupRef,
    shared::time::Duration,
    status::condition::{
        compute_conditions, deployment::DeploymentConditionBuilder,
        operations::ClusterOperationsConditionBuilder, statefulset::StatefulSetConditionBuilder,
    },
    v2::{
        HasName, HasUid, NameIsValidLabelValue,
        kvp::label::{recommended_labels, role_group_selector},
        role_group_utils::ResourceNames,
        types::{
            kubernetes::Uid,
            operator::{
                ClusterName, ControllerName, OperatorName, ProductName, ProductVersion,
                RoleGroupName, RoleName,
            },
        },
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    OPERATOR_NAME,
    controller::build::resource::{
        deployment::{build_beat_rolegroup_deployment, build_worker_rolegroup_deployment},
        listener::build_group_listener,
        pdb::build_pdb,
        service::{build_node_rolegroup_headless_service, build_node_rolegroup_metrics_service},
        statefulset::build_server_rolegroup_statefulset,
    },
    crd::{
        APP_NAME, INTERNAL_SECRET_SECRET_KEY, SupersetRole,
        authentication::SupersetClientAuthenticationDetailsResolved,
        authorization::SupersetOpaConfigResolved,
        databases::{
            CeleryBrokerConnection, CeleryResultsBackendConnection, MetadataDatabaseConnection,
        },
        v1alpha1::{SupersetCluster, SupersetClusterStatus, SupersetConfig},
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

/// Per-role configuration extracted during validation.
#[derive(Clone, Debug)]
pub struct ValidatedRoleConfig {
    pub pdb: Option<stackable_operator::commons::pdb::PdbConfig>,
    pub listener_class: Option<String>,
    pub group_listener_name: Option<String>,
}

/// Per-rolegroup configuration: the merged CRD config plus the overrides.
///
/// This is the generic [`stackable_operator::v2::role_utils::RoleGroupConfig`]: the merged config
/// fragment in `config`, the typed `config_overrides` (role-group merged over role) and the merged
/// `env_overrides`/`cli_overrides`/`pod_overrides`. The config overrides are kept typed
/// ([`SupersetConfigOverrides`](crate::crd::v1alpha1::SupersetConfigOverrides)) and assembled into
/// the rendered `superset_config.py` later, in the build step.
pub type SupersetRoleGroupConfig = stackable_operator::v2::role_utils::RoleGroupConfig<
    SupersetConfig,
    stackable_operator::v2::role_utils::GenericCommonConfig,
    crate::crd::v1alpha1::SupersetConfigOverrides,
>;

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
    /// Name of the Vector aggregator discovery ConfigMap, if logging aggregation is enabled.
    pub vector_aggregator_config_map_name: Option<String>,
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
    pub product_version: ProductVersion,
    pub image: ResolvedProductImage,
    pub cluster_config: ValidatedClusterConfig,
    pub role_groups: BTreeMap<SupersetRole, BTreeMap<RoleGroupName, SupersetRoleGroupConfig>>,
    pub role_configs: BTreeMap<SupersetRole, ValidatedRoleConfig>,
}

impl ValidatedCluster {
    pub fn new(
        superset: &SupersetCluster,
        name: ClusterName,
        image: ResolvedProductImage,
        cluster_config: ValidatedClusterConfig,
        role_groups: BTreeMap<SupersetRole, BTreeMap<RoleGroupName, SupersetRoleGroupConfig>>,
        role_configs: BTreeMap<SupersetRole, ValidatedRoleConfig>,
    ) -> Self {
        let product_version = ProductVersion::from_str(&image.app_version_label_value)
            .expect("the app version label value is a valid product version");
        Self {
            // Capture only the identity fields needed to own child objects.
            metadata: ObjectMeta {
                name: Some(superset.name_any()),
                namespace: superset.namespace(),
                uid: superset.uid(),
                ..ObjectMeta::default()
            },
            image,
            cluster_config,
            role_groups,
            role_configs,
            name,
            product_version,
        }
    }

    pub fn resource_names(
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
            &ProductVersion::from_str("none").expect("'none' is a valid product version"),
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
        self.name_any()
    }
}

impl HasUid for ValidatedCluster {
    fn to_uid(&self) -> Uid {
        Uid::from_str(
            &self
                .metadata
                .uid
                .clone()
                .expect("the uid is captured during validation"),
        )
        .expect("the uid is a valid Kubernetes UID")
    }
}

impl NameIsValidLabelValue for ValidatedCluster {
    fn to_label_value(&self) -> String {
        self.name.to_label_value()
    }
}

/// The product name (`superset`) as a type-safe label value.
fn product_name() -> ProductName {
    ProductName::from_str(APP_NAME).expect("'superset' is a valid product name")
}

/// The operator name as a type-safe label value.
fn operator_name() -> OperatorName {
    OperatorName::from_str(OPERATOR_NAME).expect("the operator name is a valid label value")
}

/// The controller name as a type-safe label value.
fn controller_name() -> ControllerName {
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

    #[snafu(display("failed to create cluster resources"))]
    CreateClusterResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to apply Service for {rolegroup}"))]
    ApplyRoleGroupService {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },

    #[snafu(display("failed to apply ConfigMap for {rolegroup}"))]
    ApplyRoleGroupConfig {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },

    #[snafu(display("failed to apply StatefulSet for {rolegroup}"))]
    ApplyRoleGroupStatefulSet {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },

    #[snafu(display("failed to apply Deployment for {rolegroup}"))]
    ApplyRoleGroupDeployment {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },

    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to patch service account"))]
    ApplyServiceAccount {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to patch role binding"))]
    ApplyRoleBinding {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to build RBAC objects"))]
    BuildRBACObjects {
        source: stackable_operator::commons::rbac::Error,
    },

    #[snafu(display("failed to create PodDisruptionBudget"))]
    FailedToCreatePdb {
        source: crate::controller::build::resource::pdb::Error,
    },

    #[snafu(display("failed to apply PodDisruptionBudget"))]
    ApplyPdb {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to get required Labels"))]
    GetRequiredLabels {
        source:
            stackable_operator::kvp::KeyValuePairError<stackable_operator::kvp::LabelValueError>,
    },

    #[snafu(display("SupersetCluster object is invalid"))]
    InvalidSupersetCluster {
        source: error_boundary::InvalidObject,
    },

    #[snafu(display("failed to apply group listener"))]
    ApplyGroupListener {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to build statefulset"))]
    BuildStatefulSet {
        source: crate::controller::build::resource::statefulset::Error,
    },

    #[snafu(display("failed to build deployment"))]
    BuildDeployment {
        source: crate::controller::build::resource::deployment::Error,
    },

    #[snafu(display("failed to build configmap"))]
    BuildConfigMap {
        source: crate::controller::build::resource::config_map::Error,
    },

    #[snafu(display("failed to create SECRET_KEY secret"))]
    CreateSecretKeySecret {
        source: random_secret_creation::Error,
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

    let mut cluster_resources = ClusterResources::new(
        APP_NAME,
        OPERATOR_NAME,
        SUPERSET_CONTROLLER_NAME,
        &superset.object_ref(&()),
        ClusterResourceApplyStrategy::from(&superset.spec.cluster_config.cluster_operation),
        &superset.spec.object_overrides,
    )
    .context(CreateClusterResourcesSnafu)?;

    let (rbac_sa, rbac_rolebinding) = build_rbac_resources(
        superset,
        APP_NAME,
        cluster_resources
            .get_required_labels()
            .context(GetRequiredLabelsSnafu)?,
    )
    .context(BuildRBACObjectsSnafu)?;

    let rbac_sa = cluster_resources
        .add(client, rbac_sa)
        .await
        .context(ApplyServiceAccountSnafu)?;
    cluster_resources
        .add(client, rbac_rolebinding)
        .await
        .context(ApplyRoleBindingSnafu)?;

    random_secret_creation::create_random_secret_if_not_exists(
        &superset.shared_secret_key_secret_name(),
        INTERNAL_SECRET_SECRET_KEY,
        256,
        superset,
        client,
    )
    .await
    .context(CreateSecretKeySecretSnafu)?;

    let mut statefulset_cond_builder = StatefulSetConditionBuilder::default();
    let mut deployment_cond_builder = DeploymentConditionBuilder::default();

    for (superset_role, rolegroup_configs) in validated.role_groups.iter() {
        for (rolegroup_name, validated_rolegroup) in rolegroup_configs.iter() {
            let rolegroup = superset.rolegroup_ref(superset_role, rolegroup_name);
            let config = &validated_rolegroup.config;

            let rg_configmap = build::resource::config_map::build_rolegroup_config_map(
                &validated,
                superset_role,
                &rolegroup,
                config,
                &validated_rolegroup.config_overrides,
                &config.logging,
            )
            .context(BuildConfigMapSnafu)?;

            let rg_metrics_service = build_node_rolegroup_metrics_service(&validated, &rolegroup);

            let rg_headless_service = build_node_rolegroup_headless_service(&validated, &rolegroup);

            cluster_resources
                .add(client, rg_metrics_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    rolegroup: rolegroup.clone(),
                })?;

            cluster_resources
                .add(client, rg_headless_service)
                .await
                .with_context(|_| ApplyRoleGroupServiceSnafu {
                    rolegroup: rolegroup.clone(),
                })?;

            cluster_resources
                .add(client, rg_configmap)
                .await
                .with_context(|_| ApplyRoleGroupConfigSnafu {
                    rolegroup: rolegroup.clone(),
                })?;

            match superset_role {
                SupersetRole::Node => {
                    let rg_statefulset = build_server_rolegroup_statefulset(
                        &validated,
                        superset_role,
                        &rolegroup,
                        validated_rolegroup,
                        &rbac_sa.name_any(),
                    )
                    .context(BuildStatefulSetSnafu)?;

                    // Note: The StatefulSet needs to be applied after all ConfigMaps and Secrets it mounts
                    // to prevent unnecessary Pod restarts.
                    // See https://github.com/stackabletech/commons-operator/issues/111 for details.
                    statefulset_cond_builder.add(
                        cluster_resources
                            .add(client, rg_statefulset.clone())
                            .await
                            .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                                rolegroup: rolegroup.clone(),
                            })?,
                    );
                }
                SupersetRole::Worker => {
                    let rg_worker_deployment = build_worker_rolegroup_deployment(
                        &validated,
                        &rolegroup,
                        validated_rolegroup,
                        &rbac_sa.name_any(),
                    )
                    .context(BuildDeploymentSnafu)?;

                    // Note: The Deployment needs to be applied after all ConfigMaps and Secrets it mounts
                    // to prevent unnecessary Pod restarts.
                    // See https://github.com/stackabletech/commons-operator/issues/111 for details.
                    deployment_cond_builder.add(
                        cluster_resources
                            .add(client, rg_worker_deployment.clone())
                            .await
                            .with_context(|_| ApplyRoleGroupDeploymentSnafu {
                                rolegroup: rolegroup.clone(),
                            })?,
                    );
                }
                SupersetRole::Beat => {
                    let rg_beat_deployment = build_beat_rolegroup_deployment(
                        &validated,
                        &rolegroup,
                        validated_rolegroup,
                        &rbac_sa.name_any(),
                    )
                    .context(BuildDeploymentSnafu)?;

                    // Note: The Deployment needs to be applied after all ConfigMaps and Secrets it mounts
                    // to prevent unnecessary Pod restarts.
                    // See https://github.com/stackabletech/commons-operator/issues/111 for details.
                    deployment_cond_builder.add(
                        cluster_resources
                            .add(client, rg_beat_deployment.clone())
                            .await
                            .with_context(|_| ApplyRoleGroupDeploymentSnafu {
                                rolegroup: rolegroup.clone(),
                            })?,
                    );
                }
            }
        }

        // Role-level resources (group listener, PDB) are built once per role, after
        // its role groups — not once per role group.
        if let Some(role_config) = validated.role_configs.get(superset_role) {
            if let (Some(listener_class), Some(listener_group_name)) = (
                &role_config.listener_class,
                &role_config.group_listener_name,
            ) {
                let group_listener = build_group_listener(
                    &validated,
                    superset_role,
                    listener_class.clone(),
                    listener_group_name.clone(),
                );
                cluster_resources
                    .add(client, group_listener)
                    .await
                    .context(ApplyGroupListenerSnafu)?;
            }

            if let Some(pdb) = &role_config.pdb
                && let Some(pdb) =
                    build_pdb(pdb, &validated, superset_role).context(FailedToCreatePdbSnafu)?
            {
                cluster_resources
                    .add(client, pdb)
                    .await
                    .context(ApplyPdbSnafu)?;
            }
        }
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
