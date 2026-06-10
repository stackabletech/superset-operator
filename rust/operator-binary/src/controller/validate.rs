//! The validate step in the SupersetCluster controller.
//!
//! Synchronously validates inputs that don't require a Kubernetes client. Produces
//! [`ValidatedSupersetCluster`], consumed by the rest of `reconcile_superset`.

use std::collections::{BTreeMap, HashMap};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    commons::product_image_selection,
    config::fragment,
    kube::ResourceExt,
    role_utils::{GenericRoleConfig, RoleGroup},
    v2::role_utils::{GenericCommonConfig, with_validated_config},
};
use strum::IntoEnumIterator;

use crate::{
    built_info::PKG_VERSION,
    controller::{
        CONTAINER_IMAGE_BASE_NAME, ValidatedRoleConfig, ValidatedRoleGroupConfig,
        ValidatedSupersetCluster, dereference::DereferencedObjects,
    },
    crd::{
        SupersetConfigOptions, SupersetRole,
        v1alpha1::{SupersetCluster, SupersetConfig, SupersetConfigFragment, SupersetRoleConfig},
    },
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: product_image_selection::Error,
    },

    #[snafu(display("failed to resolve and merge config for role group {role_group}"))]
    FailedToResolveConfig {
        source: fragment::ValidationError,
        role_group: String,
    },
}

pub fn validate_cluster(
    superset: &SupersetCluster,
    dereferenced: DereferencedObjects,
    image_repository: &str,
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

    let mut role_groups = HashMap::new();
    let mut role_configs = HashMap::new();

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

            let (config_file_properties, env_overrides) =
                collect_role_group_config(superset, &role, &validated_rg);

            group_configs.insert(
                rolegroup_name.clone(),
                ValidatedRoleGroupConfig {
                    merged_config: validated_rg.config.config,
                    config_file_properties,
                    env_overrides,
                },
            );
        }

        role_groups.insert(role, group_configs);
    }

    Ok(ValidatedSupersetCluster {
        image: resolved_product_image,
        role_groups,
        role_configs,
        authentication_config,
        opa_config,
    })
}

// DESIGN DECISION: `with_validated_config` (operator-rs) performs the config-fragment
// merge+validate and the role<-role-group `Merge` of config/env overrides (role-group wins
// on conflicting keys). This function layers superset's product-specific values on top to
// produce the COMPLETE superset_config.py map (operator recommended values + config-derived
// values + the merged user overrides), which the statefulset reads back.
fn collect_role_group_config(
    superset: &SupersetCluster,
    role: &SupersetRole,
    validated_rg: &RoleGroup<
        SupersetConfig,
        GenericCommonConfig,
        crate::crd::v1alpha1::SupersetConfigOverrides,
    >,
) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let merged_config = &validated_rg.config.config;

    // --- config_file_properties ---
    let mut config_file_properties: BTreeMap<String, String> = BTreeMap::new();

    // Step 1: Operator recommended values — Node role only (matches the old properties.yaml
    // role-scoping). ROW_LIMIT and SUPERSET_WEBSERVER_TIMEOUT; the latter because Superset's
    // 60s default is too low for "big data" queries.
    if *role == SupersetRole::Node {
        config_file_properties.insert(
            SupersetConfigOptions::RowLimit.to_string(),
            "50000".to_string(),
        );
        config_file_properties.insert(
            SupersetConfigOptions::SupersetWebserverTimeout.to_string(),
            "300".to_string(),
        );
    }

    // Step 2: Config-derived values (all roles) — user-set typed CRD fields override the
    // recommended values above.
    if let Some(v) = merged_config.row_limit {
        config_file_properties.insert(SupersetConfigOptions::RowLimit.to_string(), v.to_string());
    }
    if let Some(v) = merged_config.webserver_timeout {
        config_file_properties.insert(
            SupersetConfigOptions::SupersetWebserverTimeout.to_string(),
            v.to_string(),
        );
    }

    // Step 3: User configOverrides — plain string key/values, already merged role<-role-group
    // (role-group wins) by `with_validated_config`. operator-rs #1219 removed the nullable
    // `Option<String>` values, so there is no `null`/unset concept anymore.
    config_file_properties.extend(
        validated_rg
            .config
            .config_overrides
            .superset_config_py
            .overrides
            .clone(),
    );

    // --- env_overrides ---
    // The MAPBOX secret is injected first, then the merged user envOverrides extend on top so a
    // user-set key wins — the same precedence as before. Collected into a BTreeMap for a
    // deterministic order.
    let mut env_overrides: BTreeMap<String, String> = BTreeMap::new();
    if let Some(mapbox_secret) = &superset.spec.cluster_config.mapbox_secret {
        env_overrides.insert(
            SupersetConfig::MAPBOX_SECRET_PROPERTY.to_string(),
            mapbox_secret.clone(),
        );
    }
    env_overrides.extend(
        validated_rg
            .config
            .env_overrides
            .iter()
            .map(|(k, v)| (k.clone(), v.clone())),
    );

    (config_file_properties, env_overrides)
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
            .and_then(|groups| groups.get("default"))
            .expect("node default rolegroup");

        assert_eq!(
            node.config_file_properties.get("ROLE_ONLY"),
            Some(&"role".to_string())
        );
        assert_eq!(
            node.config_file_properties.get("GROUP_ONLY"),
            Some(&"group".to_string())
        );
        assert_eq!(
            node.config_file_properties.get("SHARED"),
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
