use indoc::formatdoc;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::pod::{
        container::ContainerBuilder, resources::ResourceRequirementsBuilder, volume::VolumeBuilder,
    },
    commons::product_image_selection::ResolvedProductImage,
    database_connections::{
        TemplatingMechanism,
        drivers::{
            celery::CeleryDatabaseConnectionDetails,
            sqlalchemy::SqlAlchemyDatabaseConnectionDetails,
        },
    },
    k8s_openapi::api::core::v1::{
        ConfigMapVolumeSource, Container as K8sContainer, EmptyDirVolumeSource, Volume,
    },
    product_logging::{
        self,
        spec::{
            ConfigMapLogConfig, ContainerLogConfig, ContainerLogConfigChoice,
            CustomContainerLogConfig, Logging,
        },
    },
    utils::COMMON_BASH_TRAP_FUNCTIONS,
};

use crate::{
    controller::ValidatedCluster,
    crd::{
        MAX_LOG_FILES_SIZE, METRICS_PORT, METRICS_PORT_NAME,
        databases::{
            CeleryBrokerConnection, CeleryResultsBackendConnection,
            CeleryResultsBackendConnectionDetails, MetadataDatabaseConnection,
        },
        v1alpha1::Container,
    },
};

pub mod config_map;
pub mod deployment;
pub mod listener;
pub mod pdb;
pub mod service;
pub mod statefulset;

pub const CONFIG_VOLUME_NAME: &str = "config";
pub const LOG_CONFIG_VOLUME_NAME: &str = "log-config";
pub const LOG_VOLUME_NAME: &str = "log";

/// Errors shared by the sidecar-container builders below.
#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("invalid container name"))]
    InvalidContainerName {
        source: stackable_operator::builder::pod::container::Error,
    },

    #[snafu(display("vector agent is enabled but vector aggregator ConfigMap is missing"))]
    VectorAggregatorConfigMapMissing,

    #[snafu(display("failed to configure logging"))]
    ConfigureLogging {
        source: product_logging::framework::LoggingError,
    },
}

pub(crate) fn create_volumes(
    config_map_name: &str,
    log_config: Option<&ContainerLogConfig>,
) -> Vec<Volume> {
    let mut volumes = Vec::new();

    volumes.push(
        VolumeBuilder::new(CONFIG_VOLUME_NAME)
            .with_config_map(config_map_name)
            .build(),
    );
    volumes.push(Volume {
        name: LOG_VOLUME_NAME.into(),
        empty_dir: Some(EmptyDirVolumeSource {
            medium: None,
            size_limit: Some(product_logging::framework::calculate_log_volume_size_limit(
                &[MAX_LOG_FILES_SIZE],
            )),
        }),
        ..Volume::default()
    });

    if let Some(ContainerLogConfig {
        choice:
            Some(ContainerLogConfigChoice::Custom(CustomContainerLogConfig {
                custom: ConfigMapLogConfig { config_map },
            })),
    }) = log_config
    {
        volumes.push(Volume {
            name: LOG_CONFIG_VOLUME_NAME.into(),
            config_map: Some(ConfigMapVolumeSource {
                name: config_map.into(),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        });
    } else {
        volumes.push(Volume {
            name: LOG_CONFIG_VOLUME_NAME.into(),
            config_map: Some(ConfigMapVolumeSource {
                name: config_map_name.into(),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        });
    }

    volumes
}

/// Builds the `metrics` (statsd exporter) sidecar container, shared by the StatefulSet and
/// Deployment rolegroup builders.
pub(crate) fn build_metrics_container(
    resolved_product_image: &ResolvedProductImage,
) -> Result<K8sContainer, Error> {
    Ok(ContainerBuilder::new("metrics")
        .context(InvalidContainerNameSnafu)?
        .image_from_product_image(resolved_product_image)
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
        ])
        .args(vec![formatdoc! {"
            {COMMON_BASH_TRAP_FUNCTIONS}
            prepare_signal_handlers
            /stackable/statsd_exporter &
            wait_for_termination $!
        "}])
        .add_container_port(METRICS_PORT_NAME, METRICS_PORT.into())
        .resources(
            ResourceRequirementsBuilder::new()
                .with_cpu_request("100m")
                .with_cpu_limit("200m")
                .with_memory_request("64Mi")
                .with_memory_limit("64Mi")
                .build(),
        )
        .build())
}

/// Builds the Vector agent sidecar container for the rolegroup, or `None` if vector logging is
/// disabled. Shared by the StatefulSet and Deployment rolegroup builders.
pub(crate) fn build_vector_container(
    validated: &ValidatedCluster,
    logging: &Logging<Container>,
) -> Result<Option<K8sContainer>, Error> {
    if !logging.enable_vector_agent {
        return Ok(None);
    }

    let vector_aggregator_config_map_name = validated
        .cluster_config
        .vector_aggregator_config_map_name
        .as_ref()
        .context(VectorAggregatorConfigMapMissingSnafu)?;

    let container = product_logging::framework::vector_container(
        &validated.image,
        CONFIG_VOLUME_NAME,
        LOG_VOLUME_NAME,
        logging.containers.get(&Container::Vector),
        ResourceRequirementsBuilder::new()
            .with_cpu_request("250m")
            .with_cpu_limit("500m")
            .with_memory_request("128Mi")
            .with_memory_limit("128Mi")
            .build(),
        vector_aggregator_config_map_name,
    )
    .context(ConfigureLoggingSnafu)?;

    Ok(Some(container))
}

pub(crate) fn metadata_database_connection_details(
    metadata_database: &MetadataDatabaseConnection,
) -> SqlAlchemyDatabaseConnectionDetails {
    metadata_database.sqlalchemy_connection_details_with_templating(
        "METADATA",
        &TemplatingMechanism::BashEnvSubstitution,
    )
}

pub(crate) fn celery_results_backend_connection_details(
    celery_results_backend: Option<&CeleryResultsBackendConnection>,
) -> (
    Option<CeleryResultsBackendConnectionDetails>,
    Option<CeleryDatabaseConnectionDetails>,
) {
    (
        celery_results_backend.map(|backend| backend.as_python_parameters()),
        celery_results_backend.map(|backend| {
            backend.celery_connection_details_with_templating(
                "CELERY_RESULTS_BACKEND",
                &TemplatingMechanism::BashEnvSubstitution,
            )
        }),
    )
}

pub(crate) fn celery_broker_connection_details(
    celery_broker: Option<&CeleryBrokerConnection>,
) -> Option<CeleryDatabaseConnectionDetails> {
    celery_broker.map(|broker| {
        broker.celery_connection_details_with_templating(
            "CELERY_BROKER",
            &TemplatingMechanism::BashEnvSubstitution,
        )
    })
}
