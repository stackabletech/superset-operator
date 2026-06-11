use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{configmap::ConfigMapBuilder, meta::ObjectMetaBuilder},
    k8s_openapi::api::core::v1::ConfigMap,
    product_logging::{framework::VECTOR_CONFIG_FILE, spec::Logging},
    role_utils::RoleGroupRef,
};

use crate::{
    controller::{
        SUPERSET_CONTROLLER_NAME, ValidatedCluster,
        build::properties::{ConfigFileName, logging, superset_config},
    },
    crd::{
        SupersetRole,
        v1alpha1::{Container, SupersetCluster, SupersetConfig, SupersetConfigOverrides},
    },
    resources::build_recommended_labels,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build {config_file} for {rolegroup}", config_file = ConfigFileName::SupersetConfig))]
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
pub fn build_rolegroup_config_map(
    validated: &ValidatedCluster,
    role: &SupersetRole,
    rolegroup: &RoleGroupRef<SupersetCluster>,
    merged_config: &SupersetConfig,
    config_overrides: &SupersetConfigOverrides,
    logging: &Logging<Container>,
) -> Result<ConfigMap, Error> {
    let config_file = superset_config::build(validated, role, merged_config, config_overrides)
        .with_context(|_| BuildSupersetConfigSnafu {
            rolegroup: rolegroup.clone(),
        })?;

    let mut cm_builder = ConfigMapBuilder::new();

    cm_builder
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(validated)
                .name(rolegroup.object_name())
                .ownerreference_from_resource(validated, None, Some(true))
                .context(ObjectMissingMetadataForOwnerRefSnafu)?
                .with_recommended_labels(&build_recommended_labels(
                    validated,
                    SUPERSET_CONTROLLER_NAME,
                    &validated.image.app_version_label_value,
                    &rolegroup.role,
                    &rolegroup.role_group,
                ))
                .context(BuildMetadataSnafu)?
                .build(),
        )
        .add_data(ConfigFileName::SupersetConfig.to_string(), config_file);

    if let Some(log_config) = logging::build_log_config(logging) {
        cm_builder.add_data(ConfigFileName::LogConfig.to_string(), log_config);
    }
    if let Some(vector_config) = logging::build_vector_config(rolegroup, logging) {
        cm_builder.add_data(VECTOR_CONFIG_FILE, vector_config);
    }

    cm_builder
        .build()
        .with_context(|_| BuildRoleGroupConfigSnafu {
            rolegroup: rolegroup.clone(),
        })
}
