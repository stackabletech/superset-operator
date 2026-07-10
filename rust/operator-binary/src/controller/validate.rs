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
        controller_utils::{get_cluster_name, get_namespace, get_uid},
        product_logging::framework::{
            VectorContainerLogConfig, validate_logging_configuration_for_container,
        },
        role_utils::{GenericCommonConfig, with_validated_config},
        types::{kubernetes::ConfigMapName, operator::RoleGroupName},
    },
};
use strum::IntoEnumIterator;

use crate::{
    built_info::PKG_VERSION,
    controller::{
        CONTAINER_IMAGE_BASE_NAME, SupersetRoleGroupConfig, ValidatedCluster,
        ValidatedClusterConfig, ValidatedLogging, ValidatedRoleConfig, ValidatedSupersetConfig,
        dereference::DereferencedObjects,
    },
    crd::{
        SupersetRole, SupersetRoleGroupType, SupersetRoleType,
        v1alpha1::{
            Container, SupersetCluster, SupersetConfig, SupersetConfigFragment,
            SupersetConfigOverrides, SupersetRoleConfig,
        },
    },
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: product_image_selection::Error,
    },

    #[snafu(display("failed to resolve cluster name"))]
    ResolveClusterName {
        source: stackable_operator::v2::controller_utils::Error,
    },

    #[snafu(display("failed to resolve namespace"))]
    ResolveNamespace {
        source: stackable_operator::v2::controller_utils::Error,
    },

    #[snafu(display("failed to resolve uid"))]
    ResolveUid {
        source: stackable_operator::v2::controller_utils::Error,
    },

    #[snafu(display("failed to validate the config for role group {role_group}"))]
    ValidateConfig {
        source: fragment::ValidationError,
        role_group: RoleGroupName,
    },

    #[snafu(display("invalid environment variable override name in role group {role_group}"))]
    ParseEnvVarName {
        source: stackable_operator::v2::macros::attributed_string_type::Error,
        role_group: RoleGroupName,
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

    // The Vector aggregator discovery ConfigMap name. It is only required when the Vector agent is
    // enabled for a role group; that check happens in `validate_logging`.
    let vector_aggregator_config_map_name = superset
        .spec
        .cluster_config
        .vector_aggregator_config_map_name
        .clone();

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
                group_listener_name: superset.group_listener_name(&role).map(|name| {
                    name.parse()
                        .expect("the group listener name is a valid ListenerName")
                }),
            },
        );

        let default_config = SupersetConfig::default_config(&superset.name_any(), &role);

        let mut group_configs = BTreeMap::new();
        for (rolegroup_name, rolegroup) in &resolved_role.role_groups {
            let role_group_name = RoleGroupName::from_str(rolegroup_name).with_context(|_| {
                ParseRoleGroupNameSnafu {
                    role_group: rolegroup_name.clone(),
                }
            })?;
            let validated_rg = validate_role_group_config(
                &role_group_name,
                rolegroup,
                resolved_role,
                &default_config,
                &vector_aggregator_config_map_name,
            )?;
            group_configs.insert(role_group_name, validated_rg);
        }

        role_groups.insert(role, group_configs);
    }

    let cluster_config = &superset.spec.cluster_config;

    let cluster_name = get_cluster_name(superset).context(ResolveClusterNameSnafu)?;
    let namespace = get_namespace(superset).context(ResolveNamespaceSnafu)?;
    let uid = get_uid(superset).context(ResolveUidSnafu)?;

    Ok(ValidatedCluster::new(
        cluster_name,
        namespace,
        uid,
        resolved_product_image,
        ValidatedClusterConfig {
            authentication_config,
            opa_config,
            credentials_secret_name: cluster_config.credentials_secret.clone(),
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

/// Merges and validates one role group into a [`SupersetRoleGroupConfig`].
fn validate_role_group_config(
    role_group_name: &RoleGroupName,
    role_group: &SupersetRoleGroupType,
    role: &SupersetRoleType,
    default_config: &SupersetConfigFragment,
    vector_aggregator_config_map_name: &Option<ConfigMapName>,
) -> Result<SupersetRoleGroupConfig, Error> {
    let merged = with_validated_config::<
        SupersetConfig,
        GenericCommonConfig,
        SupersetConfigFragment,
        SupersetRoleConfig,
        SupersetConfigOverrides,
    >(role_group, role, default_config)
    .with_context(|_| ValidateConfigSnafu {
        role_group: role_group_name.clone(),
    })?;

    let mut env_overrides = EnvVarSet::new();
    for (env_var_name, env_var_value) in merged.config.env_overrides {
        env_overrides = env_overrides.with_value(
            &EnvVarName::from_str(&env_var_name).with_context(|_| ParseEnvVarNameSnafu {
                role_group: role_group_name.clone(),
            })?,
            env_var_value,
        );
    }

    let logging = validate_logging(
        &merged.config.config.logging,
        vector_aggregator_config_map_name,
    )?;

    Ok(SupersetRoleGroupConfig {
        replicas: merged.replicas,
        config: ValidatedSupersetConfig::from_merged(merged.config.config, logging),
        config_overrides: merged.config.config_overrides,
        env_overrides,
        cli_overrides: merged.config.cli_overrides,
        pod_overrides: merged.config.pod_overrides,
        product_specific_common_config: merged.config.product_specific_common_config,
    })
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use stackable_operator::{
        product_logging::spec::{
            AutomaticContainerLogConfig, ContainerLogConfig, ContainerLogConfigChoice, Logging,
        },
        utils::yaml_from_str_singleton_map,
        v2::types::kubernetes::ConfigMapName,
    };

    use super::{Error, validate_cluster, validate_logging};
    use crate::{
        controller::test_support::default_dereferenced,
        crd::{SupersetRole, v1alpha1},
    };

    /// Builds a [`Logging`] with automatic log configuration for the Superset and Vector containers.
    fn automatic_logging(enable_vector_agent: bool) -> Logging<v1alpha1::Container> {
        let automatic = || ContainerLogConfig {
            choice: Some(ContainerLogConfigChoice::Automatic(
                AutomaticContainerLogConfig::default(),
            )),
        };
        Logging {
            enable_vector_agent,
            containers: [
                (v1alpha1::Container::Superset, automatic()),
                (v1alpha1::Container::Vector, automatic()),
            ]
            .into(),
        }
    }

    /// The Vector aggregator discovery ConfigMap name is required exactly when the Vector agent is
    /// enabled, and a Vector container is configured only in that case.
    #[test]
    fn validate_logging_requires_vector_aggregator_only_when_vector_enabled() {
        // Vector enabled without an aggregator ConfigMap name fails validation up-front.
        assert!(matches!(
            validate_logging(&automatic_logging(true), &None),
            Err(Error::MissingVectorAggregatorConfigMapName)
        ));

        // Vector enabled with an aggregator name configures a Vector container.
        let aggregator = Some(
            ConfigMapName::from_str("vector-aggregator-discovery").expect("valid ConfigMap name"),
        );
        let validated = validate_logging(&automatic_logging(true), &aggregator)
            .expect("logging should validate");
        assert!(validated.enable_vector_agent);
        assert!(validated.vector_container.is_some());

        // Vector disabled needs no aggregator name and configures no Vector container.
        let validated =
            validate_logging(&automatic_logging(false), &None).expect("logging should validate");
        assert!(!validated.enable_vector_agent);
        assert!(validated.vector_container.is_none());
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
          namespace: default
          uid: 01234567-89ab-cdef-0123-456789abcdef
        spec:
          image:
            productVersion: 4.1.4
          clusterConfig:
            credentialsSecret: superset-admin-credentials
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
          namespace: default
          uid: 01234567-89ab-cdef-0123-456789abcdef
        spec:
          image:
            productVersion: 4.1.4
          clusterConfig:
            credentialsSecret: superset-admin-credentials
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
