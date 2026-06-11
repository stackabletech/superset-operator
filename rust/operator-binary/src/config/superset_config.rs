//! Builds the `superset_config.py` configuration file from the resolved
//! authentication/OPA config plus the per-rolegroup config-file properties.

use std::{collections::BTreeMap, io::Write};

use snafu::{ResultExt, Snafu};
use stackable_operator::v2::flask_config_writer;

use super::superset::{self, PYTHON_IMPORTS, add_superset_config, append_celery_connection_config};
use crate::{
    authorization::opa::OPA_IMPORTS,
    controller::ValidatedCluster,
    crd::{
        SupersetConfigOptions, SupersetRole,
        v1alpha1::{SupersetConfig, SupersetConfigOverrides},
    },
};

/// Marks arbitrary Python code to prepend verbatim to the generated file.
const CONFIG_OVERRIDE_FILE_HEADER_KEY: &str = "FILE_HEADER";
/// Marks arbitrary Python code to append verbatim to the generated file.
const CONFIG_OVERRIDE_FILE_FOOTER_KEY: &str = "FILE_FOOTER";

/// Operator default for `SUPERSET_WEBSERVER_TIMEOUT` (seconds), applied to the `Node` role.
/// Superset's own 60s default is too low for "big data" queries.
pub const DEFAULT_WEBSERVER_TIMEOUT: u32 = 300;
/// Operator default for `ROW_LIMIT`, applied to the `Node` role.
pub const DEFAULT_ROW_LIMIT: i32 = 50000;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to add Superset config settings"))]
    AddSupersetConfig { source: superset::Error },

    #[snafu(display("failed to write the superset config file"))]
    WriteConfigFile {
        source: flask_config_writer::FlaskAppConfigWriterError,
    },

    #[snafu(display("failed to write the header/footer to the superset config file"))]
    WriteHeaderFooter { source: std::io::Error },
}

/// Renders the `superset_config.py` contents: operator defaults (derived from the
/// resolved authentication/OPA config) with the per-rolegroup config-file properties
/// applied last, wrapped by the optional `FILE_HEADER`/`FILE_FOOTER` Python blocks.
pub fn build(
    validated: &ValidatedCluster,
    role: &SupersetRole,
    merged_config: &SupersetConfig,
    config_overrides: &SupersetConfigOverrides,
) -> Result<String, Error> {
    let mut config_properties = BTreeMap::new();
    let mut imports = PYTHON_IMPORTS.to_vec();
    // TODO: this is true per default for versions 3.0.0 and up.
    //    We deactivate it here to keep existing functionality.
    //    However this is a security issue and should be configured properly
    //    Issue: https://github.com/stackabletech/superset-operator/issues/416
    config_properties.insert("TALISMAN_ENABLED".to_string(), "False".to_string());

    add_superset_config(
        &mut config_properties,
        &validated.cluster_config.metadata_database,
        &validated.cluster_config.authentication_config,
    )
    .context(AddSupersetConfigSnafu)?;

    // Adding opa configuration properties to config_properties.
    // This will be injected as key/value pair in superset_config.py
    if let Some(opa_config) = &validated.cluster_config.opa_config {
        // If opa role mapping is configured, insert CustomOpaSecurityManager import
        imports.extend(OPA_IMPORTS);

        config_properties.extend(opa_config.as_config());
    }

    // The order here should be kept in order to preserve overrides.
    // No properties should be added after this extend.
    config_properties.extend(superset_config_properties(
        role,
        merged_config,
        config_overrides,
    ));

    let mut config_file = Vec::new();

    // By removing the keys from `config_properties`, we avoid pasting the Python code into a Python variable as well
    // (which would be bad)
    if let Some(header) = config_properties.remove(CONFIG_OVERRIDE_FILE_HEADER_KEY) {
        writeln!(config_file, "{header}").context(WriteHeaderFooterSnafu)?;
    }
    let temp_file_footer = config_properties.remove(CONFIG_OVERRIDE_FILE_FOOTER_KEY);

    flask_config_writer::write::<SupersetConfigOptions, _, _>(
        &mut config_file,
        config_properties.iter(),
        &imports,
    )
    .context(WriteConfigFileSnafu)?;

    // We have to add a python class (no key) and cannot use the superset::config machinery.
    append_celery_connection_config(
        &mut config_file,
        validated.cluster_config.celery_results_backend.as_ref(),
        validated.cluster_config.celery_broker.as_ref(),
    );

    if let Some(footer) = temp_file_footer {
        writeln!(config_file, "{footer}").context(WriteHeaderFooterSnafu)?;
    }

    Ok(String::from_utf8(config_file).expect("the Flask config writer only emits valid UTF-8"))
}

/// Assembles the product-specific `superset_config.py` key/value properties for a role group.
///
/// Layered in precedence order (each step may override the previous one):
/// 1. Operator recommended values — `Node` role only
///    role-scoping): `ROW_LIMIT` and `SUPERSET_WEBSERVER_TIMEOUT` (Superset's 60s default is too
///    low for "big data" queries).
/// 2. Config-derived values (all roles) — user-set typed CRD fields override the recommended
///    values above.
/// 3. User `configOverrides` — plain string key/values, already merged role<-role-group
///    (role-group wins) by `with_validated_config`.
fn superset_config_properties(
    role: &SupersetRole,
    merged_config: &SupersetConfig,
    config_overrides: &SupersetConfigOverrides,
) -> BTreeMap<String, String> {
    let mut properties: BTreeMap<String, String> = BTreeMap::new();

    if *role == SupersetRole::Node {
        properties.insert(
            SupersetConfigOptions::RowLimit.to_string(),
            DEFAULT_ROW_LIMIT.to_string(),
        );
        properties.insert(
            SupersetConfigOptions::SupersetWebserverTimeout.to_string(),
            DEFAULT_WEBSERVER_TIMEOUT.to_string(),
        );
    }

    if let Some(v) = merged_config.row_limit {
        properties.insert(SupersetConfigOptions::RowLimit.to_string(), v.to_string());
    }
    if let Some(v) = merged_config.webserver_timeout {
        properties.insert(
            SupersetConfigOptions::SupersetWebserverTimeout.to_string(),
            v.to_string(),
        );
    }

    properties.extend(config_overrides.superset_config_py.overrides.clone());

    properties
}
