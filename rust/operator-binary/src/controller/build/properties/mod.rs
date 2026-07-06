//! Per-file builders for the Superset config files.

pub mod authentication;
pub mod authorization;
pub mod product_logging;
pub mod superset_config;

/// The names of the Superset config files assembled into the rolegroup `ConfigMap`.
///
/// This is the single source of truth for the on-disk file names; nothing else should
/// hard-code them (the Vector agent config is the exception — its name comes from the
/// `product_logging::framework::VECTOR_CONFIG_FILE` constant).
#[derive(Clone, Copy, Debug, strum::Display)]
pub enum ConfigFileName {
    #[strum(serialize = "superset_config.py")]
    SupersetConfig,
    #[strum(serialize = "log_config.py")]
    LogConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_match_the_superset_on_disk_names() {
        assert_eq!(
            ConfigFileName::SupersetConfig.to_string(),
            "superset_config.py"
        );
        assert_eq!(ConfigFileName::LogConfig.to_string(), "log_config.py");
    }
}
