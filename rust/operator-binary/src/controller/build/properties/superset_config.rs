//! Builds the `superset_config.py` configuration file from the resolved
//! authentication/OPA config plus the per-rolegroup config-file properties.

use std::{collections::BTreeMap, io::Write};

use indoc::formatdoc;
use snafu::{ResultExt, Snafu};
use stackable_operator::v2::flask_config_writer;

use crate::{
    controller::{
        ValidatedCluster,
        build::properties::{authentication, authorization},
    },
    crd::{
        SupersetConfigOptions, SupersetRole,
        databases::{
            CeleryBrokerConnection, CeleryResultsBackendConnection, MetadataDatabaseConnection,
        },
        v1alpha1::{SupersetConfig, SupersetConfigOverrides},
    },
    resources::{
        celery_broker_connection_details, celery_results_backend_connection_details,
        metadata_database_connection_details,
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

const PYTHON_IMPORTS: &[&str] = &[
    "import os",
    "from superset.stats_logger import StatsdStatsLogger",
    "from flask_appbuilder.security.manager import (AUTH_DB, AUTH_LDAP, AUTH_OAUTH, AUTH_REMOTE_USER)",
    "from log_config import StackableLoggingConfigurator",
];

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to add authentication config settings"))]
    AddAuthenticationConfig { source: authentication::Error },

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

    config_properties.extend(core_config_properties(
        &validated.cluster_config.metadata_database,
        &validated.cluster_config.authentication_config,
    )?);

    // Adding opa configuration properties to config_properties.
    // This will be injected as key/value pair in superset_config.py
    if let Some(opa_config) = &validated.cluster_config.opa_config {
        // If opa role mapping is configured, insert CustomOpaSecurityManager import
        imports.extend(authorization::OPA_IMPORTS);

        config_properties.extend(authorization::opa_properties(opa_config));
    }

    // The order here should be kept in order to preserve overrides.
    // No properties should be added after this extend.
    config_properties.extend(rolegroup_properties(role, merged_config, config_overrides));

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
    if let Some(celery_config) = celery_connection_config(
        validated.cluster_config.celery_results_backend.as_ref(),
        validated.cluster_config.celery_broker.as_ref(),
    ) {
        writeln!(config_file, "{celery_config}").expect("Writing to vec always works.");
    }

    if let Some(footer) = temp_file_footer {
        writeln!(config_file, "{footer}").context(WriteHeaderFooterSnafu)?;
    }

    Ok(String::from_utf8(config_file).expect("the Flask config writer only emits valid UTF-8"))
}

/// Renders the core operator-managed `superset_config.py` properties (database connection,
/// logging configurator, recaptcha, …) including the resolved authentication properties.
fn core_config_properties(
    metadata_database: &MetadataDatabaseConnection,
    authentication_config: &crate::crd::authentication::SupersetClientAuthenticationDetailsResolved,
) -> Result<BTreeMap<String, String>, Error> {
    let metadata_database_url_template =
        metadata_database_connection_details(metadata_database).url_template;

    let mut config = BTreeMap::new();

    config.insert(
        SupersetConfigOptions::SecretKey.to_string(),
        "os.environ.get('SECRET_KEY')".to_owned(),
    );
    config.insert(
        SupersetConfigOptions::SqlalchemyDatabaseUri.to_string(),
        format!("os.path.expandvars('{metadata_database_url_template}')"),
    );
    config.insert(
        SupersetConfigOptions::StatsLogger.to_string(),
        "StatsdStatsLogger(host='0.0.0.0', port=9125)".to_owned(),
    );
    config.insert(
        SupersetConfigOptions::MapboxApiKey.to_string(),
        "os.environ.get('MAPBOX_API_KEY', '')".to_owned(),
    );
    config.insert(
        SupersetConfigOptions::LoggingConfigurator.to_string(),
        "StackableLoggingConfigurator()".to_owned(),
    );
    // Flask AppBuilder requires this to be set, otherwise the web ui cannot be used.
    // We chose to make it an expression in case the user wants to override it through
    // configurationOverrides (though it would require other settings like the private key too).
    config.insert(
        SupersetConfigOptions::RecaptchaPublicKey.to_string(),
        "''".to_owned(),
    );

    config.extend(
        authentication::authentication_properties(authentication_config)
            .context(AddAuthenticationConfigSnafu)?,
    );

    Ok(config)
}

/// Renders the Celery async config (a bare Python class, hence rendered separately from the
/// key/value properties). Returns `None` when no Celery results backend or broker is configured.
fn celery_connection_config(
    celery_results_backend: Option<&CeleryResultsBackendConnection>,
    celery_broker: Option<&CeleryBrokerConnection>,
) -> Option<String> {
    let (
        Some(additional_celery_results_backend_connection_details),
        Some(celery_results_backend_connection_details),
    ) = celery_results_backend_connection_details(celery_results_backend)
    else {
        return None;
    };

    let celery_broker_connection_details = celery_broker_connection_details(celery_broker)?;

    let result_backend_username_env = celery_results_backend_connection_details
        .username_env
        .map(|env| env.name)
        .unwrap_or("".to_string());
    let result_backend_password_env = celery_results_backend_connection_details
        .password_env
        .map(|env| env.name)
        .unwrap_or("".to_string());
    let result_backend_url_template = celery_results_backend_connection_details.url_template;
    let result_backend_host = additional_celery_results_backend_connection_details.host;
    let result_backend_port = additional_celery_results_backend_connection_details.port;
    let result_backend_db = additional_celery_results_backend_connection_details.database_id;
    let broker_url_template = celery_broker_connection_details.url_template;

    Some(formatdoc!(
        r#"
        # CELERY ASYNC
        from flask_caching.backends.rediscache import RedisCache
        RESULTS_BACKEND = RedisCache(host='{result_backend_host}', port={result_backend_port}, db={result_backend_db}, key_prefix='superset_results', username=os.path.expandvars('${{{result_backend_username_env}}}'), password=os.path.expandvars('${{{result_backend_password_env}}}'))
        class CeleryConfig(object):
          broker_url = os.path.expandvars('{broker_url_template}')
          imports = (
            "superset.sql_lab",
            "superset.tasks.scheduler",
          )
          result_backend = os.path.expandvars('{result_backend_url_template}')
          worker_prefetch_multiplier = 10
          task_acks_late = True
          task_annotations = {{
            "sql_lab.get_sql_results": {{
              "rate_limit": "100/s",
            }},
          }}

        CELERY_CONFIG = CeleryConfig
    "#,
    ))
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
fn rolegroup_properties(
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
