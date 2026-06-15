//! Renders the logging config files (`log_config.py` and the Vector agent config)
//! assembled into the rolegroup `ConfigMap`.

use std::fmt::Write;

use indoc::formatdoc;
use stackable_operator::product_logging::spec::{
    AutomaticContainerLogConfig, ContainerLogConfig, ContainerLogConfigChoice, Logging,
};

use crate::crd::{STACKABLE_LOG_DIR, v1alpha1::Container};

/// The rotating log file the generated `log_config.py` writes to (consumed by the Vector agent).
const LOG_FILE: &str = "superset.py.json";

/// The Vector agent configuration (`vector.yaml`).
const VECTOR_CONFIG: &str = include_str!("vector.yaml");

/// Returns the Vector agent config (`vector.yaml`) content.
pub fn vector_config_file_content() -> String {
    VECTOR_CONFIG.to_owned()
}

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
/// Returns `None` when the Vector agent is disabled for this role group. The returned config is the
/// vendored, env-var-parameterized `vector.yaml`.
pub fn build_vector_config(logging: &Logging<Container>) -> Option<String> {
    logging.enable_vector_agent.then(vector_config_file_content)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The vendored `vector.yaml` keeps only the sources Superset produces and drops the ones it
    /// does not (log4j/log4j2/airlift/opa/tracing). Guards against accidental drift.
    #[test]
    fn test_vector_config_file_content() {
        let content = vector_config_file_content();
        assert!(!content.is_empty());
        // Superset logs JSON to `superset.py.json`, so the Python-JSON source must be present.
        assert!(content.contains("files_py"));
        assert!(content.contains("*.py.json"));
        // Sources Superset does not emit must have been trimmed out.
        for dropped in [
            "files_log4j",
            "files_log4j2",
            "files_airlift",
            "files_opa_json",
            "files_tracing_rs",
        ] {
            assert!(
                !content.contains(dropped),
                "vendored vector.yaml should not contain the dropped source {dropped}"
            );
        }
        // The config is env-var-parameterized (resolved at runtime by the Vector container), not
        // baked, so the role-group identity must appear as placeholders.
        assert!(content.contains("${ROLE_NAME}"));
        assert!(content.contains("${VECTOR_AGGREGATOR_ADDRESS}"));
    }
}
