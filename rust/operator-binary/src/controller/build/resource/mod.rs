use std::str::FromStr;

use indoc::formatdoc;
use stackable_operator::{
    builder::pod::{
        container::ContainerBuilder, resources::ResourceRequirementsBuilder, volume::VolumeBuilder,
    },
    commons::product_image_selection::ResolvedProductImage,
    constant,
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
        builder::pod::container::{EnvVarName, EnvVarSet, new_container_builder},
        product_logging::framework::{
            STACKABLE_LOG_DIR, ValidatedContainerLogConfigChoice, vector_container,
        },
        types::{
            kubernetes::{ContainerName, PersistentVolumeClaimName, SecretKey, VolumeName},
            operator::RoleGroupName,
        },
    },
};

use crate::{
    controller::{SupersetRoleGroupConfig, ValidatedCluster},
    crd::{
        INTERNAL_SECRET_SECRET_KEY, MAPBOX_API_KEY_ENV, MAPBOX_API_KEY_SECRET_KEY,
        MAX_LOG_FILES_SIZE, METADATA_DATABASE_ENV_PREFIX, METRICS_PORT, METRICS_PORT_NAME,
        SECRET_KEY_ENV, STACKABLE_CONFIG_DIR, STACKABLE_LOG_CONFIG_DIR, SupersetRole,
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
pub mod rbac;
pub mod service;
pub mod statefulset;

constant!(CONFIG_VOLUME_NAME: VolumeName = "config");
constant!(LOG_CONFIG_VOLUME_NAME: VolumeName = "log-config");
constant!(LOG_VOLUME_NAME: VolumeName = "log");

// Env vars holding the admin user credentials, read by the `superset fab create-admin` start
// command, and the keys under which the user-provided credentials Secret holds them.
constant!(ADMIN_USERNAME: EnvVarName = "ADMIN_USERNAME");
constant!(ADMIN_FIRSTNAME: EnvVarName = "ADMIN_FIRSTNAME");
constant!(ADMIN_LASTNAME: EnvVarName = "ADMIN_LASTNAME");
constant!(ADMIN_EMAIL: EnvVarName = "ADMIN_EMAIL");
constant!(ADMIN_PASSWORD: EnvVarName = "ADMIN_PASSWORD");
constant!(ADMIN_USERNAME_SECRET_KEY: SecretKey = "adminUser.username");
constant!(ADMIN_FIRSTNAME_SECRET_KEY: SecretKey = "adminUser.firstname");
constant!(ADMIN_LASTNAME_SECRET_KEY: SecretKey = "adminUser.lastname");
constant!(ADMIN_EMAIL_SECRET_KEY: SecretKey = "adminUser.email");
constant!(ADMIN_PASSWORD_SECRET_KEY: SecretKey = "adminUser.password");

// Env var the `containerdebug` process logs its tracing information to.
constant!(CONTAINERDEBUG_LOG_DIRECTORY: EnvVarName = "CONTAINERDEBUG_LOG_DIRECTORY");
// Env var pointing the Superset container at the directory holding trusted CA certs.
constant!(SSL_CERT_DIR: EnvVarName = "SSL_CERT_DIR");

/// Directory the `SSL_CERT_DIR` env var points the Superset container at for trusted CA certs.
const STACKABLE_CERTS_DIR: &str = "/stackable/certs/";
/// Path of the statsd-exporter binary launched by the `metrics` sidecar.
const STATSD_EXPORTER_BINARY: &str = "/stackable/statsd_exporter";

// The metrics container has no logging configuration, so it is not a `Container` variant and
// carries its name directly.
constant!(METRICS_CONTAINER_NAME: ContainerName = "metrics");

// Name of the listener volume. It is a PVC, so the same name is used as the volume/mount name and
// as the PVC name.
constant!(pub(crate) LISTENER_VOLUME_NAME_PVC: PersistentVolumeClaimName = "listener");

/// The only network protocol used by the Superset service and listener ports.
pub(crate) const PROTOCOL_TCP: &str = "TCP";

/// The `fsGroup` the Pods run as, required by secret-operator-provided volumes.
pub(crate) const SECRET_OPERATOR_FS_GROUP: i64 = 1000;

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

/// Assembles the env vars for the `superset` container in a name-keyed [`EnvVarSet`], so every
/// name occurs exactly once: database/celery connection details, the optional Mapbox key, the
/// Flask `SECRET_KEY`, the admin-credential env vars, the `containerdebug`/SSL env vars and the
/// `role_specific_env_vars` of the caller.
///
/// The user-supplied `envOverrides` are merged in last, so that they override any operator-set
/// environment variable.
fn build_env_vars(
    validated: &ValidatedCluster,
    rolegroup_config: &SupersetRoleGroupConfig,
    role_specific_env_vars: EnvVarSet,
) -> EnvVarSet {
    let mut env_vars = EnvVarSet::new();

    let metadata_database_connection_details =
        metadata_database_connection_details(&validated.cluster_config.metadata_database);
    let (_, celery_results_backend_connection_details) = celery_results_backend_connection_details(
        validated.cluster_config.celery_results_backend.as_ref(),
    );
    let celery_broker_connection_details =
        celery_broker_connection_details(validated.cluster_config.celery_broker.as_ref());

    for env_var in metadata_database_connection_details
        .env_vars()
        .chain(
            celery_results_backend_connection_details
                .iter()
                .flat_map(|details| details.env_vars()),
        )
        .chain(
            celery_broker_connection_details
                .iter()
                .flat_map(|details| details.env_vars()),
        )
    {
        env_vars = env_vars.with_env_var(env_var.clone()).expect(
            "the database connection env var names are generated by operator-rs from the unique \
             database name and are therefore valid",
        );
    }

    if let Some(mapbox_secret) = &validated.cluster_config.mapbox_secret {
        env_vars = env_vars.with_secret_key_ref(
            &MAPBOX_API_KEY_ENV,
            mapbox_secret,
            &MAPBOX_API_KEY_SECRET_KEY,
        );
    }

    let credentials_secret = &validated.cluster_config.credentials_secret_name;
    env_vars = env_vars
        // The Flask `SECRET_KEY` env var is sourced from the auto-generated Secret.
        .with_secret_key_ref(
            &SECRET_KEY_ENV,
            &validated.cluster_config.secret_key_secret_name,
            &INTERNAL_SECRET_SECRET_KEY,
        )
        .with_secret_key_ref(
            &ADMIN_USERNAME,
            credentials_secret,
            &ADMIN_USERNAME_SECRET_KEY,
        )
        .with_secret_key_ref(
            &ADMIN_FIRSTNAME,
            credentials_secret,
            &ADMIN_FIRSTNAME_SECRET_KEY,
        )
        .with_secret_key_ref(
            &ADMIN_LASTNAME,
            credentials_secret,
            &ADMIN_LASTNAME_SECRET_KEY,
        )
        .with_secret_key_ref(&ADMIN_EMAIL, credentials_secret, &ADMIN_EMAIL_SECRET_KEY)
        .with_secret_key_ref(
            &ADMIN_PASSWORD,
            credentials_secret,
            &ADMIN_PASSWORD_SECRET_KEY,
        )
        .with_value(
            &CONTAINERDEBUG_LOG_DIRECTORY,
            format!("{STACKABLE_LOG_DIR}/containerdebug"),
        )
        .with_value(&SSL_CERT_DIR, STACKABLE_CERTS_DIR);

    // Environment variable overrides (highest precedence), merged from role and role group.
    // They are merged in last so that they override any operator-set environment variable.
    env_vars
        .merge(role_specific_env_vars)
        .merge(rolegroup_config.env_overrides.clone())
}

/// Builds the `superset` main container builder with the configuration shared by every role: the
/// product image, the config/log volume mounts and the env vars built by [`build_env_vars`]
/// (which merges the user-supplied `envOverrides` in last, so they take precedence over every
/// operator-set environment variable).
///
/// `role_specific_env_vars` carries additional operator-set env vars of the caller's role (the
/// `Node` role passes its authentication env vars) so that they participate in the same
/// name-keyed set instead of being appended separately.
///
/// The returned builder is finished by the caller with the role-specific command, args and probes.
/// Only the `Node` role serves the Superset web UI, so the caller additionally adds the HTTP
/// container port, the authentication volumes/mounts and the listener volume mount; the
/// `Worker`/`Beat` Celery roles do not serve HTTP and so declare no HTTP port.
pub(crate) fn build_superset_container_builder(
    validated: &ValidatedCluster,
    rolegroup_config: &SupersetRoleGroupConfig,
    role_specific_env_vars: EnvVarSet,
) -> ContainerBuilder {
    let mut superset_cb = new_container_builder(Container::Superset.name());

    superset_cb
        .image_from_product_image(&validated.image)
        .add_volume_mount(CONFIG_VOLUME_NAME.as_ref(), STACKABLE_CONFIG_DIR)
        .expect("The mount paths are statically defined and there should be no duplicates.")
        .add_volume_mount(LOG_CONFIG_VOLUME_NAME.as_ref(), STACKABLE_LOG_CONFIG_DIR)
        .expect("The mount paths are statically defined and there should be no duplicates.")
        .add_volume_mount(LOG_VOLUME_NAME.as_ref(), STACKABLE_LOG_DIR)
        .expect("The mount paths are statically defined and there should be no duplicates.")
        .add_env_vars(build_env_vars(
            validated,
            rolegroup_config,
            role_specific_env_vars,
        ));

    superset_cb
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
                Container::Vector.name(),
                &validated.image,
                vector_log_config,
                &validated.role_group_resource_names(superset_role, role_group_name),
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

#[cfg(test)]
mod tests {
    use super::{
        ADMIN_EMAIL, ADMIN_EMAIL_SECRET_KEY, ADMIN_FIRSTNAME, ADMIN_FIRSTNAME_SECRET_KEY,
        ADMIN_LASTNAME, ADMIN_LASTNAME_SECRET_KEY, ADMIN_PASSWORD, ADMIN_PASSWORD_SECRET_KEY,
        ADMIN_USERNAME, ADMIN_USERNAME_SECRET_KEY, CONFIG_VOLUME_NAME,
        CONTAINERDEBUG_LOG_DIRECTORY, LISTENER_VOLUME_NAME_PVC, LOG_CONFIG_VOLUME_NAME,
        LOG_VOLUME_NAME, METRICS_CONTAINER_NAME, SSL_CERT_DIR,
    };

    #[test]
    fn test_constants() {
        // Test that dereferencing the constants does not panic.
        let _ = *CONFIG_VOLUME_NAME;
        let _ = *LOG_CONFIG_VOLUME_NAME;
        let _ = *LOG_VOLUME_NAME;
        let _ = *ADMIN_USERNAME;
        let _ = *ADMIN_FIRSTNAME;
        let _ = *ADMIN_LASTNAME;
        let _ = *ADMIN_EMAIL;
        let _ = *ADMIN_PASSWORD;
        let _ = *ADMIN_USERNAME_SECRET_KEY;
        let _ = *ADMIN_FIRSTNAME_SECRET_KEY;
        let _ = *ADMIN_LASTNAME_SECRET_KEY;
        let _ = *ADMIN_EMAIL_SECRET_KEY;
        let _ = *ADMIN_PASSWORD_SECRET_KEY;
        let _ = *CONTAINERDEBUG_LOG_DIRECTORY;
        let _ = *SSL_CERT_DIR;
        let _ = *METRICS_CONTAINER_NAME;
        let _ = *LISTENER_VOLUME_NAME_PVC;
    }
}
