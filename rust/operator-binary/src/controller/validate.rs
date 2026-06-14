//! The validate step in the SupersetCluster controller.
//!
//! Synchronously validates inputs that don't require a Kubernetes client. Produces
//! [`ValidatedCluster`], consumed by the rest of `reconcile_superset`.

use std::{collections::BTreeMap, str::FromStr};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    commons::product_image_selection,
    config::fragment,
    kube::ResourceExt,
    product_logging::spec::Logging,
    role_utils::GenericRoleConfig,
    v2::{
        builder::pod::container::{EnvVarName, EnvVarSet},
        product_logging::framework::{
            VectorContainerLogConfig, validate_logging_configuration_for_container,
        },
        role_utils::{GenericCommonConfig, with_validated_config},
        types::{
            kubernetes::ConfigMapName,
            operator::{ClusterName, RoleGroupName},
        },
    },
};
use strum::IntoEnumIterator;

use crate::{
    built_info::PKG_VERSION,
    controller::{
        CONTAINER_IMAGE_BASE_NAME, SupersetRoleGroupConfig, ValidatedCluster,
        ValidatedClusterConfig, ValidatedLogging, ValidatedRoleConfig,
        dereference::DereferencedObjects,
    },
    crd::{
        SupersetRole,
        v1alpha1::{
            Container, SupersetCluster, SupersetConfig, SupersetConfigFragment, SupersetRoleConfig,
        },
    },
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: product_image_selection::Error,
    },

    #[snafu(display("invalid cluster name {cluster_name}"))]
    ParseClusterName {
        source: stackable_operator::v2::macros::attributed_string_type::Error,
        cluster_name: String,
    },

    #[snafu(display("failed to resolve and merge config for role group {role_group}"))]
    FailedToResolveConfig {
        source: fragment::ValidationError,
        role_group: String,
    },

    #[snafu(display("failed to parse environment variable name"))]
    ParseEnvVarName {
        source: stackable_operator::v2::builder::pod::container::Error,
    },

    #[snafu(display("invalid role group name {role_group}"))]
    ParseRoleGroupName {
        source: stackable_operator::v2::macros::attributed_string_type::Error,
        role_group: String,
    },

    #[snafu(display("failed to validate logging configuration"))]
    ValidateLoggingConfig {
        source: stackable_operator::v2::product_logging::framework::Error,
    },

    #[snafu(display(
        "the Vector aggregator discovery ConfigMap name is required when the Vector agent is enabled"
    ))]
    MissingVectorAggregatorConfigMapName,

    #[snafu(display("invalid Vector aggregator discovery ConfigMap name"))]
    ParseVectorAggregatorConfigMapName {
        source: stackable_operator::v2::macros::attributed_string_type::Error,
    },
}

/// Validates the logging configuration for the Superset (and optional Vector) container.
///
/// `vector_aggregator_config_map_name` is the discovery ConfigMap name of the Vector aggregator;
/// it is required (and validated) only when the Vector agent is enabled.
fn validate_logging(
    logging: &Logging<Container>,
    vector_aggregator_config_map_name: &Option<ConfigMapName>,
) -> Result<ValidatedLogging, Error> {
    let superset_container =
        validate_logging_configuration_for_container(logging, &Container::Superset)
            .context(ValidateLoggingConfigSnafu)?;

    let vector_container = if logging.enable_vector_agent {
        let vector_aggregator_config_map_name = vector_aggregator_config_map_name
            .clone()
            .context(MissingVectorAggregatorConfigMapNameSnafu)?;
        Some(VectorContainerLogConfig {
            log_config: validate_logging_configuration_for_container(logging, &Container::Vector)
                .context(ValidateLoggingConfigSnafu)?,
            vector_aggregator_config_map_name,
        })
    } else {
        None
    };

    Ok(ValidatedLogging {
        superset_container,
        vector_container,
        enable_vector_agent: logging.enable_vector_agent,
    })
}

pub fn validate_cluster(
    superset: &SupersetCluster,
    dereferenced: DereferencedObjects,
    image_repository: &str,
) -> Result<ValidatedCluster, Error> {
    let DereferencedObjects {
        authentication_config,
        opa_config,
    } = dereferenced;

    let resolved_product_image = superset
        .spec
        .image
        .resolve(CONTAINER_IMAGE_BASE_NAME, image_repository, PKG_VERSION)
        .context(ResolveProductImageSnafu)?;

    // The Vector aggregator discovery ConfigMap name (validated here so an invalid name fails
    // up-front). It is only required when the Vector agent is enabled for a role group.
    let vector_aggregator_config_map_name = superset
        .spec
        .cluster_config
        .vector_aggregator_config_map_name
        .as_deref()
        .map(ConfigMapName::from_str)
        .transpose()
        .context(ParseVectorAggregatorConfigMapNameSnafu)?;

    let mut role_groups = BTreeMap::new();
    let mut role_configs = BTreeMap::new();

    for role in SupersetRole::iter() {
        let Some(resolved_role) = superset.get_role(&role) else {
            continue;
        };

        role_configs.insert(
            role.clone(),
            ValidatedRoleConfig {
                pdb: superset.generic_role_config(&role).map(
                    |GenericRoleConfig {
                         pod_disruption_budget,
                     }| pod_disruption_budget,
                ),
                listener_class: role.listener_class_name(superset),
                group_listener_name: superset.group_listener_name(&role),
            },
        );

        let default_config = SupersetConfig::default_config(&superset.name_any(), &role);

        let mut group_configs = BTreeMap::new();
        for (rolegroup_name, rolegroup) in &resolved_role.role_groups {
            let validated_rg = with_validated_config::<
                SupersetConfig,
                GenericCommonConfig,
                SupersetConfigFragment,
                SupersetRoleConfig,
                crate::crd::v1alpha1::SupersetConfigOverrides,
            >(rolegroup, resolved_role, &default_config)
            .with_context(|_| FailedToResolveConfigSnafu {
                role_group: rolegroup_name.clone(),
            })?;

            let mut env_overrides = EnvVarSet::new();
            for (name, value) in validated_rg.config.env_overrides {
                env_overrides = env_overrides.with_value(
                    &EnvVarName::from_str(&name).context(ParseEnvVarNameSnafu)?,
                    value,
                );
            }

            let role_group_name = RoleGroupName::from_str(rolegroup_name).with_context(|_| {
                ParseRoleGroupNameSnafu {
                    role_group: rolegroup_name.clone(),
                }
            })?;

            let logging = validate_logging(
                &validated_rg.config.config.logging,
                &vector_aggregator_config_map_name,
            )?;

            group_configs.insert(
                role_group_name,
                SupersetRoleGroupConfig {
                    replicas: validated_rg.replicas.unwrap_or(1),
                    config: validated_rg.config.config,
                    config_overrides: validated_rg.config.config_overrides,
                    env_overrides,
                    pod_overrides: validated_rg.config.pod_overrides,
                    logging,
                },
            );
        }

        role_groups.insert(role, group_configs);
    }

    let cluster_config = &superset.spec.cluster_config;

    let cluster_name =
        ClusterName::from_str(&superset.name_any()).with_context(|_| ParseClusterNameSnafu {
            cluster_name: superset.name_any(),
        })?;

    Ok(ValidatedCluster::new(
        superset,
        cluster_name,
        resolved_product_image,
        ValidatedClusterConfig {
            authentication_config,
            opa_config,
            credentials_secret_name: cluster_config.credentials_secret_name.clone(),
            secret_key_secret_name: superset.shared_secret_key_secret_name(),
            mapbox_secret: cluster_config.mapbox_secret.clone(),
            metadata_database: cluster_config.metadata_database.clone(),
            celery_results_backend: cluster_config.celery_results_backend.clone(),
            celery_broker: cluster_config.celery_broker.clone(),
        },
        role_groups,
        role_configs,
    ))
}

#[cfg(test)]
mod tests {

    use stackable_operator::utils::yaml_from_str_singleton_map;

    use super::validate_cluster;
    use crate::{
        controller::dereference::DereferencedObjects,
        crd::{
            SupersetRole,
            authentication::{
                SupersetClientAuthenticationDetailsResolved, v1alpha1::FlaskRolesSyncMoment,
            },
            v1alpha1,
        },
    };

    fn default_dereferenced() -> DereferencedObjects {
        DereferencedObjects {
            authentication_config: SupersetClientAuthenticationDetailsResolved {
                authentication_classes_resolved: vec![],
                user_registration: true,
                user_registration_role: "Public".to_string(),
                sync_roles_at: FlaskRolesSyncMoment::default(),
            },
            opa_config: None,
        }
    }

    /// Characterises the `superset_config.py` override resolution: role-level overrides are merged
    /// with role-group overrides, the role group winning on shared keys, and unique keys from both
    /// levels surviving.
    #[test]
    fn config_overrides_merge_role_group_over_role() {
        let input = r#"
        apiVersion: superset.stackable.tech/v1alpha1
        kind: SupersetCluster
        metadata:
          name: simple-superset
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
            configOverrides:
              superset_config.py:
                ROLE_ONLY: role
                SHARED: role
            roleGroups:
              default:
                replicas: 1
                configOverrides:
                  superset_config.py:
                    GROUP_ONLY: group
                    SHARED: group
        "#;
        let superset: v1alpha1::SupersetCluster =
            yaml_from_str_singleton_map(input).expect("illegal test input");

        let dereferenced = default_dereferenced();

        let validated = validate_cluster(&superset, dereferenced, "test-repo").expect("validated");
        let node = validated
            .role_groups
            .get(&SupersetRole::Node)
            .and_then(|groups| groups.get(&"default".parse().expect("valid role group name")))
            .expect("node default rolegroup");
        let overrides = &node.config_overrides.superset_config_py.overrides;

        assert_eq!(overrides.get("ROLE_ONLY"), Some(&"role".to_string()));
        assert_eq!(overrides.get("GROUP_ONLY"), Some(&"group".to_string()));
        assert_eq!(
            overrides.get("SHARED"),
            Some(&"group".to_string()),
            "role-group override should win over the role-level value"
        );
    }

    /// A `null` configOverrides value is rejected by the CRD. Values are typed as `String`
    /// (operator-rs `KeyValueConfigOverrides`; the `Option<String>` was removed in op-rs #1219),
    /// so `null` can no longer express "unset"/"inherit".
    #[test]
    fn config_overrides_null_value_is_rejected() {
        let input = r#"
        apiVersion: superset.stackable.tech/v1alpha1
        kind: SupersetCluster
        metadata:
          name: simple-superset
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
            configOverrides:
              superset_config.py:
                KEY: null
            roleGroups:
              default:
                replicas: 1
        "#;
        let result: Result<v1alpha1::SupersetCluster, _> = yaml_from_str_singleton_map(input);
        assert!(
            result.is_err(),
            "a `null` configOverrides value must be rejected: values are typed as String"
        );
    }
}
