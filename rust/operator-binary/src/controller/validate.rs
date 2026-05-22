//! The validate step in the SupersetCluster controller.
//!
//! Synchronously validates inputs that don't require a Kubernetes client. Produces
//! [`ValidatedSupersetCluster`], consumed by the rest of `reconcile_superset`.

use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use product_config::{ProductConfigManager, types::PropertyNameKind};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    commons::product_image_selection::{self, ResolvedProductImage},
    product_config_utils::{
        ValidatedRoleConfigByPropertyKind, transform_all_roles_to_config,
        validate_all_roles_and_groups_config,
    },
    role_utils::GenericRoleConfig,
};
use strum::IntoEnumIterator;

use crate::{
    authorization::opa::SupersetOpaConfigResolved,
    built_info::PKG_VERSION,
    controller::{CONTAINER_IMAGE_BASE_NAME, dereference::DereferencedObjects},
    crd::{
        SUPERSET_CONFIG_FILENAME, SupersetRole,
        authentication::SupersetClientAuthenticationDetailsResolved,
        v1alpha1::{SupersetCluster, SupersetConfig},
    },
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: product_image_selection::Error,
    },

    #[snafu(display("failed to generate product config"))]
    GenerateProductConfig {
        source: stackable_operator::product_config_utils::Error,
    },

    #[snafu(display("invalid product config"))]
    InvalidProductConfig {
        source: stackable_operator::product_config_utils::Error,
    },

    #[snafu(display("failed to resolve and merge config for role and role group"))]
    FailedToResolveConfig { source: crate::crd::Error },

    #[snafu(display("failed to parse Superset role [{role}]"))]
    ParseRole {
        source: strum::ParseError,
        role: String,
    },
}

/// Per-role configuration extracted during validation.
#[derive(Clone, Debug)]
pub struct ValidatedRoleConfig {
    pub pdb: Option<stackable_operator::commons::pdb::PdbConfig>,
    pub listener_class: Option<String>,
    pub group_listener_name: Option<String>,
}

/// Per-rolegroup configuration: the merged CRD config plus the product-config properties.
#[derive(Clone, Debug)]
pub struct ValidatedRoleGroupConfig {
    pub merged_config: SupersetConfig,
    pub product_config_properties: HashMap<PropertyNameKind, BTreeMap<String, String>>,
}

/// The validated cluster: proves that product-config validation and config merging
/// succeeded for every role and role group before any Kubernetes resources are created.
/// Carries the dereferenced external objects so downstream code has a single "ready to use"
/// view of the cluster.
pub struct ValidatedSupersetCluster {
    pub image: ResolvedProductImage,
    pub role_groups: HashMap<SupersetRole, BTreeMap<String, ValidatedRoleGroupConfig>>,
    pub role_configs: HashMap<SupersetRole, ValidatedRoleConfig>,
    pub authentication_config: SupersetClientAuthenticationDetailsResolved,
    pub opa_config: Option<SupersetOpaConfigResolved>,
}

pub fn validate_cluster(
    superset: &SupersetCluster,
    dereferenced: DereferencedObjects,
    image_repository: &str,
    product_config_manager: &ProductConfigManager,
) -> Result<ValidatedSupersetCluster, Error> {
    let DereferencedObjects {
        authentication_config,
        opa_config,
    } = dereferenced;

    let resolved_product_image = superset
        .spec
        .image
        .resolve(CONTAINER_IMAGE_BASE_NAME, image_repository, PKG_VERSION)
        .context(ResolveProductImageSnafu)?;

    let mut roles = HashMap::new();
    for role in SupersetRole::iter() {
        if let Some(resolved_role) = superset.get_role(&role) {
            roles.insert(
                role.to_string(),
                (
                    vec![
                        PropertyNameKind::Env,
                        PropertyNameKind::File(SUPERSET_CONFIG_FILENAME.into()),
                    ],
                    resolved_role.clone(),
                ),
            );
        }
    }

    let role_config = transform_all_roles_to_config(superset, &roles);
    let validated_role_config: ValidatedRoleConfigByPropertyKind =
        validate_all_roles_and_groups_config(
            &resolved_product_image.product_version,
            &role_config.context(GenerateProductConfigSnafu)?,
            product_config_manager,
            false,
            false,
        )
        .context(InvalidProductConfigSnafu)?;

    let mut role_groups = HashMap::new();
    let mut role_configs = HashMap::new();

    for (role_name, rolegroup_configs) in validated_role_config.iter() {
        let superset_role = SupersetRole::from_str(role_name).context(ParseRoleSnafu {
            role: role_name.to_string(),
        })?;

        role_configs.insert(
            superset_role.clone(),
            ValidatedRoleConfig {
                pdb: superset.generic_role_config(&superset_role).map(
                    |GenericRoleConfig {
                         pod_disruption_budget,
                     }| pod_disruption_budget,
                ),
                listener_class: superset_role.listener_class_name(superset),
                group_listener_name: superset.group_listener_name(&superset_role),
            },
        );

        let mut group_configs = BTreeMap::new();
        for (rolegroup_name, rolegroup_config) in rolegroup_configs.iter() {
            let rolegroup_ref = superset.rolegroup_ref(&superset_role, rolegroup_name);
            let merged_config = superset
                .merged_config(&superset_role, &rolegroup_ref)
                .context(FailedToResolveConfigSnafu)?;

            group_configs.insert(
                rolegroup_name.clone(),
                ValidatedRoleGroupConfig {
                    merged_config,
                    product_config_properties: rolegroup_config.clone(),
                },
            );
        }

        role_groups.insert(superset_role, group_configs);
    }

    Ok(ValidatedSupersetCluster {
        image: resolved_product_image,
        role_groups,
        role_configs,
        authentication_config,
        opa_config,
    })
}
