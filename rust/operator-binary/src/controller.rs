//! Ensures that `Pod`s are configured and running for each [`SupersetCluster`]
pub(crate) mod build;
pub mod dereference;
pub mod validate;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

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
        core::{DeserializeGuard, error_boundary},
        runtime::controller::Action,
    },
    logging::controller::ReconcilerError,
    role_utils::RoleGroupRef,
    shared::time::Duration,
    status::condition::{
        compute_conditions, deployment::DeploymentConditionBuilder,
        operations::ClusterOperationsConditionBuilder, statefulset::StatefulSetConditionBuilder,
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    OPERATOR_NAME,
    authorization::opa::SupersetOpaConfigResolved,
    crd::{
        APP_NAME, INTERNAL_SECRET_SECRET_KEY, SupersetRole,
        authentication::SupersetClientAuthenticationDetailsResolved,
        v1alpha1::{SupersetCluster, SupersetClusterStatus, SupersetConfig},
    },
    operations::pdb::add_pdbs,
    resources::{
        build_recommended_labels,
        deployment::{build_beat_rolegroup_deployment, build_worker_rolegroup_deployment},
        listener::build_group_listener,
        service::{build_node_rolegroup_headless_service, build_node_rolegroup_metrics_service},
        statefulset::build_server_rolegroup_statefulset,
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

/// Per-rolegroup configuration: the merged CRD config plus the assembled property maps.
#[derive(Clone, Debug)]
pub struct ValidatedRoleGroupConfig {
    pub merged_config: SupersetConfig,
    pub config_file_properties: BTreeMap<String, String>,
    pub env_overrides: BTreeMap<String, String>,
}

/// The validated cluster: proves that config merging succeeded for every role and role group
/// before any Kubernetes resources are created. Carries the dereferenced external objects so
/// downstream code has a single "ready to use" view of the cluster.
pub struct ValidatedSupersetCluster {
    pub image: ResolvedProductImage,
    pub role_groups: HashMap<SupersetRole, BTreeMap<String, ValidatedRoleGroupConfig>>,
    pub role_configs: HashMap<SupersetRole, ValidatedRoleConfig>,
    pub authentication_config: SupersetClientAuthenticationDetailsResolved,
    pub opa_config: Option<SupersetOpaConfigResolved>,
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
        source: crate::operations::pdb::Error,
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

    #[snafu(display("failed to build listener"))]
    BuildListener {
        source: crate::resources::listener::Error,
    },

    #[snafu(display("failed to build service"))]
    BuildService {
        source: crate::resources::service::Error,
    },

    #[snafu(display("failed to build statefulset"))]
    BuildStatefulSet {
        source: crate::resources::statefulset::Error,
    },

    #[snafu(display("failed to build deployment"))]
    BuildDeployment {
        source: crate::resources::deployment::Error,
    },

    #[snafu(display("failed to build configmap"))]
    BuildConfigMap {
        source: crate::controller::build::config_map::Error,
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
            let config = &validated_rolegroup.merged_config;

            let rg_configmap = build::config_map::build_rolegroup_config_map(
                superset,
                &validated,
                &rolegroup,
                &validated_rolegroup.config_file_properties,
                &config.logging,
            )
            .context(BuildConfigMapSnafu)?;

            let rg_metrics_service =
                build_node_rolegroup_metrics_service(superset, &validated.image, &rolegroup)
                    .context(BuildServiceSnafu)?;

            let rg_headless_service =
                build_node_rolegroup_headless_service(superset, &validated.image, &rolegroup)
                    .context(BuildServiceSnafu)?;

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
                        superset,
                        &validated,
                        superset_role,
                        &rolegroup,
                        &validated_rolegroup.config_file_properties,
                        &validated_rolegroup.env_overrides,
                        &rbac_sa.name_any(),
                        config,
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
                        superset,
                        &validated.image,
                        superset_role,
                        &rolegroup,
                        &validated_rolegroup.env_overrides,
                        &rbac_sa.name_any(),
                        config,
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
                        superset,
                        &validated.image,
                        superset_role,
                        &rolegroup,
                        &validated_rolegroup.env_overrides,
                        &rbac_sa.name_any(),
                        config,
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

            if let Some(role_config) = validated.role_configs.get(superset_role) {
                if let (Some(listener_class), Some(listener_group_name)) = (
                    &role_config.listener_class,
                    &role_config.group_listener_name,
                ) {
                    let group_listener = build_group_listener(
                        superset,
                        build_recommended_labels(
                            superset,
                            SUPERSET_CONTROLLER_NAME,
                            &validated.image.app_version_label_value,
                            &superset_role.to_string(),
                            "none",
                        ),
                        listener_class.clone(),
                        listener_group_name.clone(),
                    )
                    .context(BuildListenerSnafu)?;
                    cluster_resources
                        .add(client, group_listener)
                        .await
                        .context(ApplyGroupListenerSnafu)?;
                }

                if let Some(pdb) = &role_config.pdb {
                    add_pdbs(pdb, superset, superset_role, client, &mut cluster_resources)
                        .await
                        .context(FailedToCreatePdbSnafu)?;
                }
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
