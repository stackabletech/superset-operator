use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::configmap::ConfigMapBuilder, k8s_openapi::api::core::v1::ConfigMap,
    product_logging::framework::VECTOR_CONFIG_FILE, v2::types::operator::RoleGroupName,
};

use crate::{
    controller::{
        ValidatedCluster, ValidatedSupersetConfig,
        build::properties::{ConfigFileName, product_logging, superset_config},
    },
    crd::{SupersetRole, v1alpha1::SupersetConfigOverrides},
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
    config: &ValidatedSupersetConfig,
    config_overrides: &SupersetConfigOverrides,
) -> Result<ConfigMap, Error> {
    let config_file = superset_config::build(validated, role, config, config_overrides)
        .with_context(|_| SupersetConfigSnafu {
            role_group_name: role_group_name.clone(),
        })?;

    let mut cm_builder = ConfigMapBuilder::new();

    cm_builder
        .metadata(
            validated
                .object_meta(
                    validated
                        .resource_names(role, role_group_name)
                        .role_group_config_map()
                        .to_string(),
                    role,
                    role_group_name,
                )
                .build(),
        )
        .add_data(ConfigFileName::SupersetConfig.to_string(), config_file);

    if let Some(log_config) = product_logging::build_log_config(&config.logging.superset_container)
    {
        cm_builder.add_data(ConfigFileName::LogConfig.to_string(), log_config);
    }
    if let Some(vector_config) =
        product_logging::build_vector_config(config.logging.enable_vector_agent)
    {
        cm_builder.add_data(VECTOR_CONFIG_FILE, vector_config);
    }

    cm_builder.build().with_context(|_| RoleGroupConfigSnafu {
        role_group_name: role_group_name.clone(),
    })
}

#[cfg(test)]
mod tests {
    use stackable_operator::utils::yaml_from_str_singleton_map;

    use super::*;
    use crate::{
        controller::{test_support::default_dereferenced, validate::validate_cluster},
        crd::v1alpha1,
    };

    /// The rolegroup ConfigMap carries `superset_config.py` and (for automatic logging)
    /// `log_config.py`, and omits `vector.yaml` while the Vector agent is disabled (the default).
    #[test]
    fn build_rolegroup_config_map_renders_expected_data() {
        let input = r#"
        apiVersion: superset.stackable.tech/v1alpha1
        kind: SupersetCluster
        metadata:
          name: simple-superset
          namespace: default
          uid: 01234567-89ab-cdef-0123-456789abcdef
        spec:
          image:
            productVersion: 4.1.4
          clusterConfig:
            credentialsSecretName: superset-admin-credentials
            metadataDatabase:
              postgresql:
                host: superset-postgresql
                database: superset
                credentialsSecretName: superset-postgresql-credentials
          nodes:
            roleGroups:
              default:
                replicas: 1
        "#;
        let superset: v1alpha1::SupersetCluster =
            yaml_from_str_singleton_map(input).expect("illegal test input");
        let validated =
            validate_cluster(&superset, default_dereferenced(), "test-repo").expect("validated");

        let role_group_name: RoleGroupName = "default".parse().expect("valid role group name");
        let rolegroup_config = validated
            .role_groups
            .get(&SupersetRole::Node)
            .and_then(|groups| groups.get(&role_group_name))
            .expect("node default rolegroup");

        let config_map = build_rolegroup_config_map(
            &validated,
            &SupersetRole::Node,
            &role_group_name,
            &rolegroup_config.config,
            &rolegroup_config.config_overrides,
        )
        .expect("config map built");

        let data = config_map.data.expect("config map has data");
        assert!(data.contains_key("superset_config.py"));
        assert!(data.contains_key("log_config.py"));
        // The Vector agent is disabled by default, so no `vector.yaml` is rendered.
        assert!(!data.contains_key("vector.yaml"));

        let superset_config = &data["superset_config.py"];
        assert!(superset_config.contains("SQLALCHEMY_DATABASE_URI"));
        assert!(superset_config.contains("StatsdStatsLogger"));
    }
}
