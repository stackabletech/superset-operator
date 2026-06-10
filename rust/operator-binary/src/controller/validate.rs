//! The validate step in the SupersetCluster controller.
//!
//! Synchronously validates inputs that don't require a Kubernetes client. Produces
//! [`ValidatedSupersetCluster`], consumed by the rest of `reconcile_superset`.

use std::collections::{BTreeMap, HashMap};

use snafu::{ResultExt, Snafu};
use stackable_operator::{commons::product_image_selection, role_utils::GenericRoleConfig};
use strum::IntoEnumIterator;

use crate::{
    built_info::PKG_VERSION,
    controller::{
        CONTAINER_IMAGE_BASE_NAME, ValidatedRoleConfig, ValidatedRoleGroupConfig,
        ValidatedSupersetCluster, dereference::DereferencedObjects,
    },
    crd::{
        SupersetConfigOptions, SupersetRole, SupersetRoleType,
        v1alpha1::{SupersetCluster, SupersetConfig},
    },
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: product_image_selection::Error,
    },

    #[snafu(display("failed to resolve and merge config for role and role group"))]
    FailedToResolveConfig { source: crate::crd::Error },
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

        let mut group_configs = BTreeMap::new();
        for rolegroup_name in resolved_role.role_groups.keys() {
            let rolegroup_ref = superset.rolegroup_ref(&role, rolegroup_name);
            let merged_config = superset
                .merged_config(&role, &rolegroup_ref)
                .context(FailedToResolveConfigSnafu)?;

            let (config_file_properties, env_overrides) = collect_role_group_config(
                superset,
                &role,
                resolved_role,
                rolegroup_name,
                &merged_config,
            );

            group_configs.insert(
                rolegroup_name.clone(),
                ValidatedRoleGroupConfig {
                    merged_config,
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

// DESIGN DECISION: the per-rolegroup file map and env map are assembled here, in
// validation, reproducing the old product-config precedence exactly:
//   user configOverrides > config-derived values > operator recommended values.
// Alternative: a generic with_validated_config-style merge. The upstream
// stackable_operator::v2::role_utils::with_validated_config is published on the
// smooth-operator branch but not consumed by any operator yet; trino-operator uses
// its own vendored, deliberately simplified variant (framework::role_utils) because
// its JavaCommonConfig cannot implement Merge. Neither variant covers the
// recommended-value injection and the statefulset's file read-back that superset
// needs, so the merge is assembled explicitly here.
fn collect_role_group_config(
    superset: &SupersetCluster,
    role: &SupersetRole,
    resolved_role: &SupersetRoleType,
    rolegroup_name: &str,
    merged_config: &SupersetConfig,
) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    // --- config_file_properties (superset_config.py key/value map) ---

    let mut config_file_properties: BTreeMap<String, String> = BTreeMap::new();

    // Step 1: Operator recommended values — Node role only, matching the old
    // properties.yaml role-scoping (worker/beat never received these).
    if *role == SupersetRole::Node {
        // Operator recommended values, formerly injected by product-config from
        // deploy/config-spec/properties.yaml (role-scoped to the node role).
        // ROW_LIMIT: row limit when requesting chart data.
        // SUPERSET_WEBSERVER_TIMEOUT: the default timeout of Superset is 60s which is way
        // too low when querying "big data" systems. Especially Trino queries often take
        // longer. See https://superset.apache.org/docs/frequently-asked-questions#why-are-my-queries-timing-out
        config_file_properties.insert(
            SupersetConfigOptions::RowLimit.to_string(),
            "50000".to_string(),
        );
        config_file_properties.insert(
            SupersetConfigOptions::SupersetWebserverTimeout.to_string(),
            "300".to_string(),
        );
    }

    // Step 2: Config-derived values (all roles) — mirror old compute_files logic.
    // row_limit and webserver_timeout are Option<_> on the validated SupersetConfig;
    // when set by the user they override the recommended values above.
    if let Some(v) = merged_config.row_limit {
        config_file_properties.insert(SupersetConfigOptions::RowLimit.to_string(), v.to_string());
    }
    if let Some(v) = merged_config.webserver_timeout {
        config_file_properties.insert(
            SupersetConfigOptions::SupersetWebserverTimeout.to_string(),
            v.to_string(),
        );
    }

    // Step 3: User configOverrides — role level first, then rolegroup extends on top
    // (rolegroup wins). None values in the v2 map are dropped (deletion semantics).
    let role_overrides: BTreeMap<String, Option<String>> = resolved_role
        .config
        .config_overrides
        .superset_config_py
        .overrides
        .clone();
    let rg_overrides: BTreeMap<String, Option<String>> = resolved_role
        .role_groups
        .get(rolegroup_name)
        .map(|rg| {
            rg.config
                .config_overrides
                .superset_config_py
                .overrides
                .clone()
        })
        .unwrap_or_default();
    let mut merged_overrides = role_overrides;
    merged_overrides.extend(rg_overrides);
    config_file_properties.extend(
        merged_overrides
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v))),
    );

    // --- env_overrides ---

    // DESIGN DECISION: the MAPBOX secret property is injected first (moved here from
    // crd Configuration::compute_env), then user envOverrides (role then rolegroup)
    // extend on top so a user-set key wins — the same precedence product-config used.
    // Alternative: inject after user overrides (operator wins) — rejected to preserve
    // the previous precedence.
    let mut env_overrides: BTreeMap<String, String> = BTreeMap::new();

    if let Some(mapbox_secret) = &superset.spec.cluster_config.mapbox_secret {
        env_overrides.insert(
            SupersetConfig::MAPBOX_SECRET_PROPERTY.to_string(),
            mapbox_secret.clone(),
        );
    }

    env_overrides.extend(
        resolved_role
            .config
            .env_overrides
            .iter()
            .map(|(k, v)| (k.clone(), v.clone())),
    );
    if let Some(rg) = resolved_role.role_groups.get(rolegroup_name) {
        env_overrides.extend(
            rg.config
                .env_overrides
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
    }

    (config_file_properties, env_overrides)
}

#[cfg(test)]
mod tests {
    use stackable_operator::utils::yaml_from_str_singleton_map;

    use super::collect_role_group_config;
    use crate::crd::{SupersetRole, v1alpha1};

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
        let role = SupersetRole::Node;
        let resolved_role = superset.get_role(&role).expect("node role");
        let merged_config = superset
            .merged_config(&role, &superset.rolegroup_ref(&role, "default"))
            .expect("merged config");

        let (config_file_properties, _env_overrides) =
            collect_role_group_config(&superset, &role, resolved_role, "default", &merged_config);

        assert_eq!(
            config_file_properties.get("ROLE_ONLY"),
            Some(&"role".to_string())
        );
        assert_eq!(
            config_file_properties.get("GROUP_ONLY"),
            Some(&"group".to_string())
        );
        assert_eq!(
            config_file_properties.get("SHARED"),
            Some(&"group".to_string()),
            "role-group override should win over the role-level value"
        );
    }
}
