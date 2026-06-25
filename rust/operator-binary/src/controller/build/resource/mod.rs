use std::str::FromStr;

use indoc::formatdoc;
use snafu::{ResultExt, Snafu};
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
    product_logging,
    utils::COMMON_BASH_TRAP_FUNCTIONS,
    v2::{
        builder::pod::container::{EnvVarSet, new_container_builder},
        product_logging::framework::{
            STACKABLE_LOG_DIR, ValidatedContainerLogConfigChoice, vector_container,
        },
        types::{
            kubernetes::{ContainerName, PersistentVolumeClaimName, VolumeName},
            operator::RoleGroupName,
        },
    },
};

use crate::{
    controller::{SupersetRoleGroupConfig, ValidatedCluster},
    crd::{
        APP_PORT, APP_PORT_NAME, INTERNAL_SECRET_SECRET_KEY, MAPBOX_API_KEY_ENV,
        MAX_LOG_FILES_SIZE, METADATA_DATABASE_ENV_PREFIX, METRICS_PORT, METRICS_PORT_NAME,
        STACKABLE_CONFIG_DIR, STACKABLE_LOG_CONFIG_DIR, SupersetRole,
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

stackable_operator::constant!(CONFIG_VOLUME_NAME: VolumeName = "config");
stackable_operator::constant!(LOG_CONFIG_VOLUME_NAME: VolumeName = "log-config");
stackable_operator::constant!(LOG_VOLUME_NAME: VolumeName = "log");

/// Directory the `SSL_CERT_DIR` env var points the Superset container at for trusted CA certs.
const STACKABLE_CERTS_DIR: &str = "/stackable/certs/";
/// Path of the statsd-exporter binary launched by the `metrics` sidecar.
const STATSD_EXPORTER_BINARY: &str = "/stackable/statsd_exporter";

stackable_operator::constant!(METRICS_CONTAINER_NAME: ContainerName = "metrics");

// Name of the listener volume. It is a PVC, so the same name is used as the volume/mount name and
// as the PVC name.
stackable_operator::constant!(pub(crate) LISTENER_VOLUME_NAME_PVC: PersistentVolumeClaimName = "listener");

/// The only network protocol used by the Superset service and listener ports.
pub(crate) const PROTOCOL_TCP: &str = "TCP";

/// The `fsGroup` the Pods run as, required by secret-operator-provided volumes.
pub(crate) const SECRET_OPERATOR_FS_GROUP: i64 = 1000;

/// Errors shared by the container builders below.
#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to add needed volumeMount"))]
    AddVolumeMount {
        source: stackable_operator::builder::pod::container::Error,
    },
}

/// The shell wrapper used to launch the long-running product containers
/// (`/bin/bash -x -euo pipefail -c <args>`).
pub(crate) fn bash_wrapper_command() -> Vec<String> {
    vec![
        "/bin/bash".to_string(),
        "-x".to_string(),
        "-euo".to_string(),
        "pipefail".to_string(),
        "-c".to_string(),
    ]
}

pub(crate) fn create_volumes(
    config_map_name: &str,
    log_config: &ValidatedContainerLogConfigChoice,
) -> Vec<Volume> {
    let mut volumes = Vec::new();

    volumes.push(
        VolumeBuilder::new(CONFIG_VOLUME_NAME.as_ref())
            .with_config_map(config_map_name)
            .build(),
    );
    volumes.push(Volume {
        name: LOG_VOLUME_NAME.to_string(),
        empty_dir: Some(EmptyDirVolumeSource {
            medium: None,
            size_limit: Some(product_logging::framework::calculate_log_volume_size_limit(
                &[MAX_LOG_FILES_SIZE],
            )),
        }),
        ..Volume::default()
    });

    // A custom log config references its own ConfigMap; automatic logging uses the rolegroup
    // ConfigMap (which carries the operator-generated `log_config.py`).
    let log_config_map = match log_config {
        ValidatedContainerLogConfigChoice::Custom(custom_config_map) => {
            custom_config_map.to_string()
        }
        ValidatedContainerLogConfigChoice::Automatic(_) => config_map_name.to_owned(),
    };
    volumes.push(Volume {
        name: LOG_CONFIG_VOLUME_NAME.to_string(),
        config_map: Some(ConfigMapVolumeSource {
            name: log_config_map,
            ..ConfigMapVolumeSource::default()
        }),
        ..Volume::default()
    });

    volumes
}

/// Builds the `superset` main container builder with the configuration shared by every role:
/// database/celery connection details, env overrides, the optional Mapbox key, the Flask
/// `SECRET_KEY`, the product image, the HTTP port, the config/log volume mounts, the
/// admin-credential env vars and the `containerdebug`/SSL env vars.
///
/// The returned builder is finished by the caller with the role-specific command, args and probes
/// (and, for the `Node` role, the authentication volumes/mounts and listener volume mount).
pub(crate) fn build_superset_container_builder(
    validated: &ValidatedCluster,
    rolegroup_config: &SupersetRoleGroupConfig,
) -> Result<ContainerBuilder, Error> {
    let mut superset_cb = new_container_builder(&Container::Superset.to_container_name());

    metadata_database_connection_details(&validated.cluster_config.metadata_database)
        .add_to_container(&mut superset_cb);
    let celery_results_backend_connection_details = celery_results_backend_connection_details(
        validated.cluster_config.celery_results_backend.as_ref(),
    );
    if let (_, Some(celery_results_backend_connection_details)) =
        &celery_results_backend_connection_details
    {
        celery_results_backend_connection_details.add_to_container(&mut superset_cb);
    }
    if let Some(celery_broker_connection_details) =
        celery_broker_connection_details(validated.cluster_config.celery_broker.as_ref())
    {
        celery_broker_connection_details.add_to_container(&mut superset_cb);
    }

    superset_cb.add_env_vars(rolegroup_config.env_overrides.clone());
    if let Some(mapbox_secret) = &validated.cluster_config.mapbox_secret {
        superset_cb.add_env_var_from_secret(
            MAPBOX_API_KEY_ENV,
            mapbox_secret,
            "connections.mapboxApiKey",
        );
    }

    // The Flask `SECRET_KEY` env var is sourced from the auto-generated Secret. Superset requires the
    // env var name to equal the Secret data key, so both use `INTERNAL_SECRET_SECRET_KEY`.
    superset_cb.add_env_var_from_secret(
        INTERNAL_SECRET_SECRET_KEY,
        validated.cluster_config.secret_key_secret_name.clone(),
        INTERNAL_SECRET_SECRET_KEY,
    );

    let secret = &validated.cluster_config.credentials_secret_name;
    superset_cb
        .image_from_product_image(&validated.image)
        .add_container_port(APP_PORT_NAME, APP_PORT.into())
        .add_volume_mount(CONFIG_VOLUME_NAME.as_ref(), STACKABLE_CONFIG_DIR)
        .context(AddVolumeMountSnafu)?
        .add_volume_mount(LOG_CONFIG_VOLUME_NAME.as_ref(), STACKABLE_LOG_CONFIG_DIR)
        .context(AddVolumeMountSnafu)?
        .add_volume_mount(LOG_VOLUME_NAME.as_ref(), STACKABLE_LOG_DIR)
        .context(AddVolumeMountSnafu)?
        .add_env_var_from_secret("ADMIN_USERNAME", secret, "adminUser.username")
        .add_env_var_from_secret("ADMIN_FIRSTNAME", secret, "adminUser.firstname")
        .add_env_var_from_secret("ADMIN_LASTNAME", secret, "adminUser.lastname")
        .add_env_var_from_secret("ADMIN_EMAIL", secret, "adminUser.email")
        .add_env_var_from_secret("ADMIN_PASSWORD", secret, "adminUser.password")
        // Needed by the `containerdebug` process to log it's tracing information to.
        .add_env_var(
            "CONTAINERDEBUG_LOG_DIRECTORY",
            format!("{STACKABLE_LOG_DIR}/containerdebug"),
        )
        .add_env_var("SSL_CERT_DIR", STACKABLE_CERTS_DIR);

    Ok(superset_cb)
}

/// Builds the `metrics` (statsd exporter) sidecar container, shared by the StatefulSet and
/// Deployment rolegroup builders.
pub(crate) fn build_metrics_container(
    resolved_product_image: &ResolvedProductImage,
) -> K8sContainer {
    new_container_builder(&METRICS_CONTAINER_NAME)
        .image_from_product_image(resolved_product_image)
        .command(bash_wrapper_command())
        .args(vec![formatdoc! {"
            {COMMON_BASH_TRAP_FUNCTIONS}
            prepare_signal_handlers
            {STATSD_EXPORTER_BINARY} &
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
        .build()
}

/// Builds the Vector agent sidecar container for the rolegroup, or `None` if vector logging is
/// disabled. Shared by the StatefulSet and Deployment rolegroup builders.
pub(crate) fn build_vector_container(
    validated: &ValidatedCluster,
    superset_role: &SupersetRole,
    role_group_name: &RoleGroupName,
    rolegroup_config: &SupersetRoleGroupConfig,
) -> Option<K8sContainer> {
    rolegroup_config
        .config
        .logging
        .vector_container
        .as_ref()
        .map(|vector_log_config| {
            vector_container(
                &Container::Vector.to_container_name(),
                &validated.image,
                vector_log_config,
                &validated.resource_names(superset_role, role_group_name),
                &CONFIG_VOLUME_NAME,
                &LOG_VOLUME_NAME,
                EnvVarSet::new(),
            )
        })
}

pub(crate) fn metadata_database_connection_details(
    metadata_database: &MetadataDatabaseConnection,
) -> SqlAlchemyDatabaseConnectionDetails {
    metadata_database.sqlalchemy_connection_details_with_templating(
        METADATA_DATABASE_ENV_PREFIX,
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
