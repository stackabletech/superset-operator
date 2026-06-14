//! Renders the logging config files (`log_config.py` and the Vector agent config)
//! assembled into the rolegroup `ConfigMap`.

use std::fmt::Write;

use indoc::formatdoc;
use stackable_operator::{
    product_logging::{
        self,
        spec::{
            AutomaticContainerLogConfig, ContainerLogConfig, ContainerLogConfigChoice, Logging,
        },
    },
    v2::types::operator::RoleGroupName,
};

use crate::{
    controller::ValidatedCluster,
    crd::{STACKABLE_LOG_DIR, SupersetRole, v1alpha1::Container},
};

/// The rotating log file the generated `log_config.py` writes to (consumed by the Vector agent).
const LOG_FILE: &str = "superset.py.json";

/// Renders `log_config.py` for the Superset container.
///
/// Returns `None` when the Superset container does not use the operator's automatic logging
/// configuration (e.g. a custom log ConfigMap is referenced instead), in which case no
/// `log_config.py` should be added to the rolegroup `ConfigMap`.
pub fn build_log_config(logging: &Logging<Container>) -> Option<String> {
    match logging.containers.get(&Container::Superset) {
        Some(ContainerLogConfig {
            choice: Some(ContainerLogConfigChoice::Automatic(log_config)),
        }) => {
            let log_dir = format!(
                "{STACKABLE_LOG_DIR}/{container}",
                container = Container::Superset
            );
            Some(create_superset_config(log_config, &log_dir))
        }
        _ => None,
    }
}

/// Renders the Vector agent config (`vector.yaml`).
///
/// Returns `None` when the Vector agent is disabled for this role group.
pub fn build_vector_config(
    validated: &ValidatedCluster,
    superset_role: &SupersetRole,
    role_group_name: &RoleGroupName,
    logging: &Logging<Container>,
) -> Option<String> {
    if !logging.enable_vector_agent {
        return None;
    }

    let vector_log_config = match logging.containers.get(&Container::Vector) {
        Some(ContainerLogConfig {
            choice: Some(ContainerLogConfigChoice::Automatic(log_config)),
        }) => Some(log_config),
        _ => None,
    };

    // `create_vector_config` ignores the role-group ref (it only globs `STACKABLE_LOG_DIR`), but the
    // upstream signature still requires one. Constructed here so callers stay on typed names.
    let rolegroup_ref = validated.rolegroup_ref(superset_role, role_group_name);
    Some(product_logging::framework::create_vector_config(
        &rolegroup_ref,
        vector_log_config,
    ))
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

    formatdoc!(
        "
        import flask.config
        import logging
        import os
        from superset.utils.logging_configurator import LoggingConfigurator
        from pythonjsonlogger import jsonlogger
        from celery.signals import setup_logging

        os.makedirs('{log_dir}', exist_ok=True)

        _LOGGING_CONFIGURED = False


        def _configure_root_logger():
            global _LOGGING_CONFIGURED
            if _LOGGING_CONFIGURED:
                return
            _LOGGING_CONFIGURED = True

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
            # Clear any handlers Celery/Flask/etc. already attached
            rootLogger.handlers.clear()
            rootLogger.setLevel({root_log_level})
            rootLogger.addHandler(consoleHandler)
            rootLogger.addHandler(fileHandler)


        @setup_logging.connect
        def configure_celery_logging(**kwargs):
            _configure_root_logger()


        class StackableLoggingConfigurator(LoggingConfigurator):
            def configure_logging(self, app_config: flask.config.Config, debug_mode: bool):
                _configure_root_logger()

        {loggers_config}
        ",
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
