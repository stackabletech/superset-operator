use stackable_operator::{
    builder::pod::volume::VolumeBuilder,
    database_connections::{
        TemplatingMechanism,
        drivers::{
            celery::CeleryDatabaseConnectionDetails,
            sqlalchemy::SqlAlchemyDatabaseConnectionDetails,
        },
    },
    k8s_openapi::api::core::v1::{ConfigMapVolumeSource, EmptyDirVolumeSource, Volume},
    kvp::ObjectLabels,
    product_logging::{
        self,
        spec::{
            ConfigMapLogConfig, ContainerLogConfig, ContainerLogConfigChoice,
            CustomContainerLogConfig,
        },
    },
};

use crate::{
    OPERATOR_NAME,
    crd::{APP_NAME, databases::CeleryResultsBackendConnectionDetails},
    v1alpha1::SupersetCluster,
};

pub mod configmap;
pub mod deployment;
pub mod listener;
pub mod rbac;
pub mod service;
pub mod statefulset;

use crate::crd::MAX_LOG_FILES_SIZE;

pub const CONFIG_VOLUME_NAME: &str = "config";
pub const LOG_CONFIG_VOLUME_NAME: &str = "log-config";
pub const LOG_VOLUME_NAME: &str = "log";

/// Creates recommended `ObjectLabels` to be used in deployed resources
pub fn build_recommended_labels<'a, T>(
    owner: &'a T,
    controller_name: &'a str,
    app_version: &'a str,
    role: &'a str,
    role_group: &'a str,
) -> ObjectLabels<'a, T> {
    ObjectLabels {
        owner,
        app_name: APP_NAME,
        app_version,
        operator_name: OPERATOR_NAME,
        controller_name,
        role,
        role_group,
    }
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

pub(crate) fn metadata_database_connection_details(
    superset: &SupersetCluster,
) -> SqlAlchemyDatabaseConnectionDetails {
    superset
        .spec
        .cluster_config
        .metadata_database
        .sqlalchemy_connection_details_with_templating(
            "METADATA",
            &TemplatingMechanism::BashEnvSubstitution,
        )
}

pub(crate) fn celery_result_backend_connection_details(
    superset: &SupersetCluster,
) -> (
    Option<CeleryResultsBackendConnectionDetails>,
    Option<CeleryDatabaseConnectionDetails>,
) {
    (
        superset
            .spec
            .cluster_config
            .celery_result_backend
            .as_ref()
            .map(|backend| backend.as_python_parameters()),
        superset
            .spec
            .cluster_config
            .celery_result_backend
            .as_ref()
            .map(|backend| {
                backend.celery_connection_details_with_templating(
                    "CELERY_RESULT_BACKEND",
                    &TemplatingMechanism::BashEnvSubstitution,
                )
            }),
    )
}

pub(crate) fn celery_broker_connection_details(
    superset: &SupersetCluster,
) -> Option<CeleryDatabaseConnectionDetails> {
    superset
        .spec
        .cluster_config
        .celery_broker
        .as_ref()
        .map(|broker| {
            broker.celery_connection_details_with_templating(
                "CELERY_BROKER",
                &TemplatingMechanism::BashEnvSubstitution,
            )
        })
}
