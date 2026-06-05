use std::collections::BTreeMap;

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{configmap::ConfigMapBuilder, meta::ObjectMetaBuilder},
    commons::product_image_selection::ResolvedProductImage,
    k8s_openapi::api::core::v1::ConfigMap,
    product_logging::spec::Logging,
    role_utils::RoleGroupRef,
};

use crate::{
    authorization::opa::SupersetOpaConfigResolved,
    config::{product_logging::extend_config_map_with_log_config, superset_config},
    controller::SUPERSET_CONTROLLER_NAME,
    crd::{
        SUPERSET_CONFIG_FILENAME, authentication::SupersetClientAuthenticationDetailsResolved,
        v1alpha1::{Container, SupersetCluster},
    },
    resources::build_recommended_labels,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build superset_config.py for {rolegroup}"))]
    BuildSupersetConfig {
        source: superset_config::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },

    #[snafu(display("failed to build Metadata"))]
    BuildMetadata {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build ConfigMap for {rolegroup}"))]
    BuildRoleGroupConfig {
        source: stackable_operator::builder::configmap::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
#[allow(clippy::too_many_arguments)]
pub fn build_rolegroup_config_map(
    superset: &SupersetCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup: &RoleGroupRef<SupersetCluster>,
    config_file_properties: &BTreeMap<String, String>,
    authentication_config: &SupersetClientAuthenticationDetailsResolved,
    superset_opa_config: &Option<SupersetOpaConfigResolved>,
    logging: &Logging<Container>,
) -> Result<ConfigMap, Error> {
    let config_file = superset_config::build(
        superset,
        authentication_config,
        superset_opa_config,
        config_file_properties,
    )
    .with_context(|_| BuildSupersetConfigSnafu {
        rolegroup: rolegroup.clone(),
    })?;

    let mut cm_builder = ConfigMapBuilder::new();

    cm_builder
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(superset)
                .name(rolegroup.object_name())
                .ownerreference_from_resource(superset, None, Some(true))
                .context(ObjectMissingMetadataForOwnerRefSnafu)?
                .with_recommended_labels(&build_recommended_labels(
                    superset,
                    SUPERSET_CONTROLLER_NAME,
                    &resolved_product_image.app_version_label_value,
                    &rolegroup.role,
                    &rolegroup.role_group,
                ))
                .context(BuildMetadataSnafu)?
                .build(),
        )
        .add_data(SUPERSET_CONFIG_FILENAME, config_file);

    extend_config_map_with_log_config(
        rolegroup,
        logging,
        &Container::Superset,
        &Container::Vector,
        &mut cm_builder,
    );

    cm_builder
        .build()
        .with_context(|_| BuildRoleGroupConfigSnafu {
            rolegroup: rolegroup.clone(),
        })
}
