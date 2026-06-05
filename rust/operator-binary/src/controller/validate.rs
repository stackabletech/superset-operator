//! The validate step in the SupersetCluster controller.
//!
//! Synchronously validates inputs that don't require a Kubernetes client. Produces
//! [`ValidatedSupersetCluster`], consumed by the rest of `reconcile_superset`.

use std::collections::{BTreeMap, HashMap};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    commons::product_image_selection::{self, ResolvedProductImage},
    role_utils::GenericRoleConfig,
};
use strum::IntoEnumIterator;

use crate::{
    authorization::opa::SupersetOpaConfigResolved,
    built_info::PKG_VERSION,
    controller::{CONTAINER_IMAGE_BASE_NAME, dereference::DereferencedObjects},
    crd::{
        SupersetConfigOptions, SupersetRole, SupersetRoleType,
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

    #[snafu(display("failed to resolve and merge config for role and role group"))]
    FailedToResolveConfig { source: crate::crd::Error },
}

/// Per-role configuration extracted during validation.
#[derive(Clone, Debug)]
pub struct ValidatedRoleConfig {
    pub pdb: Option<stackable_operator::commons::pdb::PdbConfig>,
    pub listener_class: Option<String>,
    pub group_listener_name: Option<String>,
}

/// Per-rolegroup configuration: the merged CRD config plus the assembled property maps.
#[derive(Clone, Debug)]
pub struct ValidatedRoleGroupConfig {
    pub merged_config: SupersetConfig,
    // DESIGN DECISION: this is the COMPLETE superset_config.py key/value map (operator
    // recommended values + config-derived values + user configOverrides), not just the
    // user overrides. Superset differs from airflow/kafka here: the old product-config
    // path injected role-scoped recommended values (ROW_LIMIT, SUPERSET_WEBSERVER_TIMEOUT
    // from properties.yaml) and config-derived values (compute_files), and the
    // statefulset reads SUPERSET_WEBSERVER_TIMEOUT back out of this map. Alternative:
    // store only the user overrides and re-derive the rest at each consumer — rejected,
    // it would duplicate the precedence logic and break the statefulset's read-back.
    pub config_file_properties: BTreeMap<String, String>,
    pub env_overrides: BTreeMap<String, String>,
}

/// The validated cluster: proves that config merging succeeded for every role and role group
/// before any Kubernetes resources are created. Carries the dereferenced external objects so
/// downstream code has a single "ready to use" view of the cluster.
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

            let (config_file_properties, env_overrides) =
                collect_role_group_config(superset, &role, resolved_role, rolegroup_name, &merged_config);

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
        .as_ref()
        .map(|o| o.overrides.clone())
        .unwrap_or_default();
    let rg_overrides: BTreeMap<String, Option<String>> = resolved_role
        .role_groups
        .get(rolegroup_name)
        .and_then(|rg| rg.config.config_overrides.superset_config_py.as_ref())
        .map(|o| o.overrides.clone())
        .unwrap_or_default();
    let mut merged_overrides = role_overrides;
    merged_overrides.extend(rg_overrides);
    config_file_properties.extend(merged_overrides.into_iter().filter_map(|(k, v)| v.map(|v| (k, v))));

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
