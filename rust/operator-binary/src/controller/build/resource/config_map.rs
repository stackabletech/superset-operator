use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{configmap::ConfigMapBuilder, meta::ObjectMetaBuilder},
    k8s_openapi::api::core::v1::ConfigMap,
    product_logging::{framework::VECTOR_CONFIG_FILE, spec::Logging},
    v2::{builder::meta::ownerreference_from_resource, types::operator::RoleGroupName},
};

use crate::{
    controller::{
        ValidatedCluster,
        build::properties::{ConfigFileName, logging, superset_config},
    },
    crd::{
        SupersetRole,
        v1alpha1::{Container, SupersetConfig, SupersetConfigOverrides},
    },
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to build {config_file} for role group {role_group_name}", config_file = ConfigFileName::SupersetConfig))]
    SupersetConfig {
        source: superset_config::Error,
        role_group_name: RoleGroupName,
    },

    #[snafu(display("failed to build ConfigMap for role group {role_group_name}"))]
    RoleGroupConfig {
        source: stackable_operator::builder::configmap::Error,
        role_group_name: RoleGroupName,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
pub fn build_rolegroup_config_map(
    validated: &ValidatedCluster,
    role: &SupersetRole,
    role_group_name: &RoleGroupName,
    merged_config: &SupersetConfig,
    config_overrides: &SupersetConfigOverrides,
    logging: &Logging<Container>,
) -> Result<ConfigMap, Error> {
    let config_file = superset_config::build(validated, role, merged_config, config_overrides)
        .with_context(|_| SupersetConfigSnafu {
            role_group_name: role_group_name.clone(),
        })?;

    let mut cm_builder = ConfigMapBuilder::new();

    cm_builder
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(validated)
                .name(
                    validated
                        .resource_names(role, role_group_name)
                        .role_group_config_map()
                        .to_string(),
                )
                .ownerreference(ownerreference_from_resource(validated, None, Some(true)))
                .with_labels(validated.recommended_labels(role, role_group_name))
                .build(),
        )
        .add_data(ConfigFileName::SupersetConfig.to_string(), config_file);

    if let Some(log_config) = logging::build_log_config(logging) {
        cm_builder.add_data(ConfigFileName::LogConfig.to_string(), log_config);
    }
    if let Some(vector_config) =
        logging::build_vector_config(validated, role, role_group_name, logging)
    {
        cm_builder.add_data(VECTOR_CONFIG_FILE, vector_config);
    }

    cm_builder.build().with_context(|_| RoleGroupConfigSnafu {
        role_group_name: role_group_name.clone(),
    })
}
