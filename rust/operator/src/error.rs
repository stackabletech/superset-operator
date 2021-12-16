use stackable_operator::kube;
use stackable_operator::product_config;
use std::num::ParseIntError;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Kubernetes reported error: {source}")]
    KubeError {
        #[from]
        source: kube::Error,
    },

    #[error("Error from Operator framework: {source}")]
    OperatorError {
        #[from]
        source: stackable_operator::error::Error,
    },

    #[error("Error from serde_json: {source}")]
    SerdeError {
        #[from]
        source: serde_json::Error,
    },

    #[error("Pod contains invalid id: {source}")]
    InvalidId {
        #[from]
        source: ParseIntError,
    },

    #[error("Error creating properties file")]
    PropertiesError(#[from] product_config::writer::PropertiesWriterError),

    #[error("ProductConfig Framework reported error: {source}")]
    ProductConfigError {
        #[from]
        source: product_config::error::Error,
    },

    #[error("Operator Framework reported config error: {source}")]
    OperatorConfigError {
        #[from]
        source: stackable_operator::product_config_utils::ConfigError,
    },
}