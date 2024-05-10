use std::fmt::{Display, Write};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::configmap::ConfigMapBuilder,
    client::Client,
    k8s_openapi::api::core::v1::ConfigMap,
    kube::Resource,
    product_logging::{
        self,
        spec::{
            AutomaticContainerLogConfig, ContainerLogConfig, ContainerLogConfigChoice, Logging,
        },
    },
    role_utils::RoleGroupRef,
};
use stackable_superset_crd::STACKABLE_LOG_DIR;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object has no namespace"))]
    ObjectHasNoNamespace,
    #[snafu(display("failed to retrieve the ConfigMap [{cm_name}]"))]
    ConfigMapNotFound {
        source: stackable_operator::client::Error,
        cm_name: String,
    },
    #[snafu(display("failed to retrieve the entry [{entry}] for ConfigMap [{cm_name}]"))]
    MissingConfigMapEntry {
        entry: &'static str,
        cm_name: String,
    },
    #[snafu(display("vectorAggregatorConfigMapName must be set"))]
    MissingVectorAggregatorAddress,
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub const LOG_CONFIG_FILE: &str = "log_config.py";

const VECTOR_AGGREGATOR_CM_ENTRY: &str = "ADDRESS";
const LOG_FILE: &str = "superset.py.json";

/// Return the address of the Vector aggregator if the corresponding ConfigMap name is given in the
/// cluster spec
pub async fn resolve_vector_aggregator_address<T: Resource>(
    client: &Client,
    cluster: &T,
    vector_aggregator_config_map_name: Option<&str>,
) -> Result<Option<String>> {
    let vector_aggregator_address =
        if let Some(vector_aggregator_config_map_name) = vector_aggregator_config_map_name {
            let namespace = cluster
                .meta()
                .namespace
                .as_deref()
                .context(ObjectHasNoNamespaceSnafu)?;
            let vector_aggregator_address = client
                .get::<ConfigMap>(vector_aggregator_config_map_name, namespace)
                .await
                .context(ConfigMapNotFoundSnafu {
                    cm_name: vector_aggregator_config_map_name.to_string(),
                })?
                .data
                .and_then(|mut data| data.remove(VECTOR_AGGREGATOR_CM_ENTRY))
                .context(MissingConfigMapEntrySnafu {
                    entry: VECTOR_AGGREGATOR_CM_ENTRY,
                    cm_name: vector_aggregator_config_map_name.to_string(),
                })?;
            Some(vector_aggregator_address)
        } else {
            None
        };
    Ok(vector_aggregator_address)
}

/// Extend the ConfigMap with logging and Vector configurations
pub fn extend_config_map_with_log_config<C, K>(
    rolegroup: &RoleGroupRef<K>,
    vector_aggregator_address: Option<&str>,
    logging: &Logging<C>,
    main_container: &C,
    vector_container: &C,
    cm_builder: &mut ConfigMapBuilder,
) -> Result<()>
where
    C: Clone + Ord + Display,
    K: Resource,
{
    if let Some(ContainerLogConfig {
        choice: Some(ContainerLogConfigChoice::Automatic(log_config)),
    }) = logging.containers.get(main_container)
    {
        let log_dir = format!("{STACKABLE_LOG_DIR}/{main_container}");
        cm_builder.add_data(
            LOG_CONFIG_FILE,
            create_superset_config(log_config, &log_dir),
        );
    }

    let vector_log_config = if let Some(ContainerLogConfig {
        choice: Some(ContainerLogConfigChoice::Automatic(log_config)),
    }) = logging.containers.get(vector_container)
    {
        Some(log_config)
    } else {
        None
    };

    if logging.enable_vector_agent {
        cm_builder.add_data(
            product_logging::framework::VECTOR_CONFIG_FILE,
            product_logging::framework::create_vector_config(
                rolegroup,
                vector_aggregator_address.context(MissingVectorAggregatorAddressSnafu)?,
                vector_log_config,
            ),
        );
    }

    Ok(())
}

fn create_superset_config(log_config: &AutomaticContainerLogConfig, log_dir: &str) -> String {
    let mut loggers_config = String::new();
    log_config
        .loggers
        .iter()
        .filter(|(name, _)| name.as_str() != AutomaticContainerLogConfig::ROOT_LOGGER)
        .for_each(|(name, config)| {
            // String formatting is an infallible operation, see https://doc.rust-lang.org/stable/std/fmt/index.html#formatting-traits
            let _ = writeln!(
                loggers_config,
                "        logging.getLogger('{name}').setLevel({level})",
                level = config.level.to_python_expression()
            );
        });

    format!(
        "\
import flask.config
import logging
import os
from superset.utils.logging_configurator import LoggingConfigurator
from pythonjsonlogger import jsonlogger

os.makedirs('{log_dir}', exist_ok=True)

class StackableLoggingConfigurator(LoggingConfigurator):
    def configure_logging(self, app_config: flask.config.Config, debug_mode: bool):
        logFormat = '%(asctime)s:%(levelname)s:%(name)s:%(message)s'

        plainTextFormatter = logging.Formatter(logFormat)
        jsonFormatter = jsonlogger.JsonFormatter(logFormat)

        consoleHandler = logging.StreamHandler()
        consoleHandler.setLevel({console_log_level})
        consoleHandler.setFormatter(plainTextFormatter)

        fileHandler = logging.handlers.RotatingFileHandler(
            '{log_dir}/{LOG_FILE}',
            maxBytes=1048576,
            backupCount=1,
        )
        fileHandler.setLevel({file_log_level})
        fileHandler.setFormatter(jsonFormatter)

        rootLogger = logging.getLogger()
        rootLogger.setLevel({root_log_level})
        rootLogger.addHandler(consoleHandler)
        rootLogger.addHandler(fileHandler)

{loggers_config}",
        root_log_level = log_config.root_log_level().to_python_expression(),
        console_log_level = log_config
            .console
            .as_ref()
            .and_then(|console| console.level)
            .unwrap_or_default()
            .to_python_expression(),
        file_log_level = log_config
            .file
            .as_ref()
            .and_then(|file| file.level)
            .unwrap_or_default()
            .to_python_expression(),
    )
}
