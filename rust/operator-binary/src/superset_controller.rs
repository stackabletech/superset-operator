//! Ensures that `Pod`s are configured and running for each [`SupersetCluster`]
use std::{borrow::Cow, sync::Arc};

use const_format::concatcp;
use product_config::{ProductConfigManager, types::PropertyNameKind};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    commons::{
        product_image_selection::{self, ResolvedProductImage},
        rbac::build_rbac_resources,
    },
    kube::{
        Resource, ResourceExt,
        core::{DeserializeGuard, error_boundary},
        runtime::controller::Action,
    },
    logging::controller::ReconcilerError,
    product_config_utils::{transform_all_roles_to_config, validate_all_roles_and_groups_config},
    role_utils::{GenericRoleConfig, RoleGroupRef},
    shared::time::Duration,
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder,
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    OPERATOR_NAME,
    authorization::opa::SupersetOpaConfigResolved,
    crd::{
        APP_NAME, SUPERSET_CONFIG_FILENAME, SupersetRole,
        authentication::SupersetClientAuthenticationDetailsResolved,
        v1alpha1::{SupersetCluster, SupersetClusterStatus},
    },
    operations::pdb::add_pdbs,
    resources::{
        configmap::build_rolegroup_config_map,
        listener::build_group_listener,
        service::{build_node_rolegroup_headless_service, build_node_rolegroup_metrics_service},
        statefulset::build_server_rolegroup_statefulset,
    },
    util::build_recommended_labels,
};

pub const SUPERSET_CONTROLLER_NAME: &str = "supersetcluster";
pub const SUPERSET_FULL_CONTROLLER_NAME: &str =
    concatcp!(SUPERSET_CONTROLLER_NAME, '.', OPERATOR_NAME);
pub const DOCKER_IMAGE_BASE_NAME: &str = "superset";

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub product_config: ProductConfigManager,
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object defines no node role"))]
    NoNodeRole,

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

    #[snafu(display("failed to generate product config"))]
    GenerateProductConfig {
        source: stackable_operator::product_config_utils::Error,
    },

    #[snafu(display("invalid product config"))]
    InvalidProductConfig {
        source: stackable_operator::product_config_utils::Error,
    },

    #[snafu(display("failed to apply authentication configuration"))]
    InvalidAuthenticationConfig {
        source: crate::crd::authentication::Error,
    },

    #[snafu(display("failed to resolve and merge config for role and role group"))]
    FailedToResolveConfig { source: crate::crd::Error },

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

    #[snafu(display("invalid OPA config"))]
    InvalidOpaConfig {
        source: stackable_operator::commons::opa::Error,
    },

    #[snafu(display("failed to apply group listener"))]
    ApplyGroupListener {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to configure listener"))]
    ListenerConfiguration {
        source: crate::resources::listener::Error,
    },

    #[snafu(display("failed to configure service"))]
    ServiceConfiguration {
        source: crate::resources::service::Error,
    },

    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: product_image_selection::Error,
    },

    #[snafu(display("failed to build statefulset"))]
    BuildStatefulSet {
        source: crate::resources::statefulset::Error,
    },

    #[snafu(display("failed to build configmap"))]
    BuildConfigMap {
        source: crate::resources::configmap::Error,
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
    let resolved_product_image: ResolvedProductImage = superset
        .spec
        .image
        .resolve(DOCKER_IMAGE_BASE_NAME, crate::built_info::PKG_VERSION)
        .context(ResolveProductImageSnafu)?;
    let superset_role = SupersetRole::Node;

    let cluster_operation_cond_builder =
        ClusterOperationsConditionBuilder::new(&superset.spec.cluster_config.cluster_operation);

    let auth_config = SupersetClientAuthenticationDetailsResolved::from(
        &superset.spec.cluster_config.authentication,
        client,
    )
    .await
    .context(InvalidAuthenticationConfigSnafu)?;

    let validated_config = validate_all_roles_and_groups_config(
        &resolved_product_image.product_version,
        &transform_all_roles_to_config(
            superset,
            [(
                superset_role.to_string(),
                (
                    vec![
                        PropertyNameKind::Env,
                        PropertyNameKind::File(SUPERSET_CONFIG_FILENAME.into()),
                    ],
                    superset.spec.nodes.clone().context(NoNodeRoleSnafu)?,
                ),
            )]
            .into(),
        )
        .context(GenerateProductConfigSnafu)?,
        &ctx.product_config,
        false,
        false,
    )
    .context(InvalidProductConfigSnafu)?;

    let role_node_config = validated_config
        .get(superset_role.to_string().as_str())
        .map(Cow::Borrowed)
        .unwrap_or_default();

    let mut cluster_resources = ClusterResources::new(
        APP_NAME,
        OPERATOR_NAME,
        SUPERSET_CONTROLLER_NAME,
        &superset.object_ref(&()),
        ClusterResourceApplyStrategy::from(&superset.spec.cluster_config.cluster_operation),
        &superset.spec.object_overrides,
    )
    .context(CreateClusterResourcesSnafu)?;

    let superset_opa_config = match superset.get_opa_config() {
        Some(opa_config) => Some(
            SupersetOpaConfigResolved::from_opa_config(client, superset, opa_config)
                .await
                .context(InvalidOpaConfigSnafu)?,
        ),
        None => None,
    };

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

    let mut ss_cond_builder = StatefulSetConditionBuilder::default();

    for (rolegroup_name, rolegroup_config) in role_node_config.iter() {
        let rolegroup = superset.node_rolegroup_ref(rolegroup_name);

        let config = superset
            .merged_config(&SupersetRole::Node, &rolegroup)
            .context(FailedToResolveConfigSnafu)?;

        let rg_configmap = build_rolegroup_config_map(
            superset,
            &resolved_product_image,
            &rolegroup,
            rolegroup_config,
            &auth_config,
            &superset_opa_config,
            &config.logging,
        )
        .context(BuildConfigMapSnafu)?;
        let rg_statefulset = build_server_rolegroup_statefulset(
            superset,
            &resolved_product_image,
            &superset_role,
            &rolegroup,
            rolegroup_config,
            &auth_config,
            &rbac_sa.name_any(),
            &config,
        )
        .context(BuildStatefulSetSnafu)?;

        let rg_metrics_service =
            build_node_rolegroup_metrics_service(superset, &resolved_product_image, &rolegroup)
                .context(ServiceConfigurationSnafu)?;

        let rg_headless_service =
            build_node_rolegroup_headless_service(superset, &resolved_product_image, &rolegroup)
                .context(ServiceConfigurationSnafu)?;

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

        // Note: The StatefulSet needs to be applied after all ConfigMaps and Secrets it mounts
        // to prevent unnecessary Pod restarts.
        // See https://github.com/stackabletech/commons-operator/issues/111 for details.
        ss_cond_builder.add(
            cluster_resources
                .add(client, rg_statefulset.clone())
                .await
                .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                    rolegroup: rolegroup.clone(),
                })?,
        );
    }

    if let Some(listener_class) = &superset_role.listener_class_name(superset) {
        if let Some(listener_group_name) = superset.group_listener_name(&superset_role) {
            let group_listener = build_group_listener(
                superset,
                build_recommended_labels(
                    superset,
                    SUPERSET_CONTROLLER_NAME,
                    &resolved_product_image.product_version,
                    &superset_role.to_string(),
                    "none",
                ),
                listener_class.to_string(),
                listener_group_name,
            )
            .context(ListenerConfigurationSnafu)?;
            cluster_resources
                .add(client, group_listener)
                .await
                .context(ApplyGroupListenerSnafu)?;
        }
    }

    let generic_role_config = superset.generic_role_config(&superset_role);
    if let Some(GenericRoleConfig {
        pod_disruption_budget: pdb,
    }) = generic_role_config
    {
        add_pdbs(
            &pdb,
            superset,
            &superset_role,
            client,
            &mut cluster_resources,
        )
        .await
        .context(FailedToCreatePdbSnafu)?;
    }

    cluster_resources
        .delete_orphaned_resources(client)
        .await
        .context(DeleteOrphanedResourcesSnafu)?;

    let status = SupersetClusterStatus {
        conditions: compute_conditions(
            superset,
            &[&ss_cond_builder, &cluster_operation_cond_builder],
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
