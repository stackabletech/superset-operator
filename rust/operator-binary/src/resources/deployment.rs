use std::collections::{BTreeMap, HashMap};

use indoc::formatdoc;
use product_config::types::PropertyNameKind;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{
            PodBuilder, container::ContainerBuilder, resources::ResourceRequirementsBuilder,
            security::PodSecurityContextBuilder,
        },
    },
    commons::product_image_selection::ResolvedProductImage,
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{Deployment, DeploymentSpec},
            core::v1::{ExecAction, Probe},
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    kvp::{Label, Labels},
    product_logging::{
        self,
        framework::{create_vector_shutdown_file_command, remove_vector_shutdown_file_command},
    },
    role_utils::RoleGroupRef,
    utils::COMMON_BASH_TRAP_FUNCTIONS,
};

use crate::{
    config::product_logging::LOG_CONFIG_FILE,
    crd::{
        APP_NAME, APP_PORT, METRICS_PORT, METRICS_PORT_NAME, PYTHONPATH, STACKABLE_CONFIG_DIR,
        STACKABLE_LOG_CONFIG_DIR, STACKABLE_LOG_DIR, SUPERSET_CONFIG_FILENAME,
        SupersetConfigOptions, SupersetRole,
        v1alpha1::{Container, SupersetCluster, SupersetConfig},
    },
    operations::graceful_shutdown::add_graceful_shutdown_config,
    resources::{
        CONFIG_VOLUME_NAME, LOG_CONFIG_VOLUME_NAME, LOG_VOLUME_NAME, build_recommended_labels,
    },
    superset_controller::SUPERSET_CONTROLLER_NAME,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object defines no '{role}' role"))]
    MissingRole { role: String },

    #[snafu(display("object defines no '{role}' rolegroup"))]
    MissingRoleGroup { role: String },

    #[snafu(display("invalid container name"))]
    InvalidContainerName {
        source: stackable_operator::builder::pod::container::Error,
    },

    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("vector agent is enabled but vector aggregator ConfigMap is missing"))]
    VectorAggregatorConfigMapMissing,

    #[snafu(display("failed to configure graceful shutdown"))]
    GracefulShutdown {
        source: crate::operations::graceful_shutdown::Error,
    },

    #[snafu(display("failed to build Labels"))]
    LabelBuild {
        source: stackable_operator::kvp::LabelError,
    },

    #[snafu(display("failed to build Metadata"))]
    MetadataBuild {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display(
        "failed to get the {SUPERSET_CONFIG_FILENAME} file from node or product config"
    ))]
    MissingSupersetConfigInNodeConfig,

    #[snafu(display("failed to get {timeout} from {SUPERSET_CONFIG_FILENAME} file. It should be set in the product config or by user input", timeout = SupersetConfigOptions::SupersetWebserverTimeout))]
    MissingWebServerTimeoutInSupersetConfig,

    #[snafu(display("failed to configure logging"))]
    ConfigureLogging {
        source: product_logging::framework::LoggingError,
    },

    #[snafu(display("failed to add needed volume"))]
    AddVolume {
        source: stackable_operator::builder::pod::Error,
    },

    #[snafu(display("failed to add needed volumeMount"))]
    AddVolumeMount {
        source: stackable_operator::builder::pod::container::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// The rolegroup [`Deployment`] runs the rolegroup, as configured by the administrator.
pub fn build_worker_rolegroup_deployment(
    superset: &SupersetCluster,
    resolved_product_image: &ResolvedProductImage,
    superset_role: &SupersetRole,
    rolegroup_ref: &RoleGroupRef<SupersetCluster>,
    node_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    sa_name: &str,
    merged_config: &SupersetConfig,
) -> Result<Deployment> {
    let role = superset
        .get_role(superset_role)
        .with_context(|| MissingRoleSnafu {
            role: superset_role.to_string(),
        })?;
    let role_group = role
        .role_groups
        .get(&rolegroup_ref.role_group)
        .with_context(|| MissingRoleGroupSnafu {
            role: superset_role.to_string(),
        })?;

    let recommended_object_labels = build_recommended_labels(
        superset,
        SUPERSET_CONTROLLER_NAME,
        &resolved_product_image.app_version_label_value,
        &rolegroup_ref.role,
        &rolegroup_ref.role_group,
    );

    let metadata = ObjectMetaBuilder::new()
        .with_recommended_labels(&recommended_object_labels)
        .context(MetadataBuildSnafu)?
        .build();

    let mut pb = &mut PodBuilder::new();

    pb = pb
        .metadata(metadata)
        .image_pull_secrets_from_product_image(resolved_product_image)
        .security_context(
            PodSecurityContextBuilder::new()
                .fs_group(1000) // Needed for secret-operator
                .build(),
        )
        .affinity(&merged_config.affinity)
        .service_account_name(sa_name);

    let mut superset_cb = ContainerBuilder::new(&Container::Superset.to_string())
        .context(InvalidContainerNameSnafu)?;

    let metadata_database_connection_details =
        super::metadata_database_connection_details(superset);
    let celery_results_backend_connection_details =
        super::celery_results_backend_connection_details(superset);
    let celery_broker_connection_details = super::celery_broker_connection_details(superset);

    metadata_database_connection_details.add_to_container(&mut superset_cb);
    if let (_, Some(celery_results_backend_connection_details)) =
        &celery_results_backend_connection_details
    {
        celery_results_backend_connection_details.add_to_container(&mut superset_cb);
    }
    if let Some(celery_broker_connection_details) = celery_broker_connection_details {
        celery_broker_connection_details.add_to_container(&mut superset_cb);
    }

    for (name, value) in node_config
        .get(&PropertyNameKind::Env)
        .cloned()
        .unwrap_or_default()
    {
        if name == SupersetConfig::MAPBOX_SECRET_PROPERTY {
            superset_cb.add_env_var_from_secret(
                "MAPBOX_API_KEY",
                &value,
                "connections.mapboxApiKey",
            );
        } else {
            superset_cb.add_env_var(name, value);
        };
    }

    // SECRET_KEY from auto-generated secret
    superset_cb.add_env_var_from_secret(
        "SECRET_KEY",
        superset.shared_secret_key_secret_name(),
        crate::crd::INTERNAL_SECRET_SECRET_KEY,
    );

    let secret = &superset.spec.cluster_config.credentials_secret_name;

    superset_cb
        .image_from_product_image(resolved_product_image)
        .add_container_port("http", APP_PORT.into())
        .add_volume_mount(CONFIG_VOLUME_NAME, STACKABLE_CONFIG_DIR)
        .context(AddVolumeMountSnafu)?
        .add_volume_mount(LOG_CONFIG_VOLUME_NAME, STACKABLE_LOG_CONFIG_DIR)
        .context(AddVolumeMountSnafu)?
        .add_volume_mount(LOG_VOLUME_NAME, STACKABLE_LOG_DIR)
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
        .add_env_var("SSL_CERT_DIR", "/stackable/certs/")
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
        ])
        // TODO: Without --loglevel=INFO, the worker does not log anyhing.
        //       This should be investigated and configurable.
        .args(vec![formatdoc! {"
            {COMMON_BASH_TRAP_FUNCTIONS}

            mkdir --parents {PYTHONPATH}
            cp {STACKABLE_CONFIG_DIR}/* {PYTHONPATH}
            cp {STACKABLE_LOG_CONFIG_DIR}/{LOG_CONFIG_FILE} {PYTHONPATH}

            {remove_vector_shutdown_file_command}
            prepare_signal_handlers
            containerdebug --output={STACKABLE_LOG_DIR}/containerdebug-state.json --loop &

            celery --app=superset.tasks.celery_app:app worker --task-events &

            wait_for_termination $!
            {create_vector_shutdown_file_command}
        ",
            remove_vector_shutdown_file_command =
                remove_vector_shutdown_file_command(STACKABLE_LOG_DIR),
            create_vector_shutdown_file_command =
                create_vector_shutdown_file_command(STACKABLE_LOG_DIR),
        }])
        .liveness_probe(Probe {
            exec: Some(ExecAction {
                command: Some(vec![
                    "celery --app=superset.tasks.celery_app:app inspect ping -d celery@$HOSTNAME"
                        .to_string(),
                ]),
            }),
            initial_delay_seconds: Some(30),
            period_seconds: Some(30),
            timeout_seconds: Some(30),
            failure_threshold: Some(3),
            ..Default::default()
        })
        .resources(merged_config.resources.clone().into());

    pb.add_container(superset_cb.build());
    add_graceful_shutdown_config(merged_config, pb).context(GracefulShutdownSnafu)?;

    let metrics_container = ContainerBuilder::new("metrics")
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
        .build();

    pb.add_volumes(crate::resources::create_volumes(
        &rolegroup_ref.object_name(),
        merged_config.logging.containers.get(&Container::Superset),
    ))
    .context(AddVolumeSnafu)?;
    pb.add_container(metrics_container);

    if merged_config.logging.enable_vector_agent {
        match &superset
            .spec
            .cluster_config
            .vector_aggregator_config_map_name
        {
            Some(vector_aggregator_config_map_name) => {
                pb.add_container(
                    product_logging::framework::vector_container(
                        resolved_product_image,
                        CONFIG_VOLUME_NAME,
                        LOG_VOLUME_NAME,
                        merged_config.logging.containers.get(&Container::Vector),
                        ResourceRequirementsBuilder::new()
                            .with_cpu_request("250m")
                            .with_cpu_limit("500m")
                            .with_memory_request("128Mi")
                            .with_memory_limit("128Mi")
                            .build(),
                        vector_aggregator_config_map_name,
                    )
                    .context(ConfigureLoggingSnafu)?,
                );
            }
            None => {
                VectorAggregatorConfigMapMissingSnafu.fail()?;
            }
        }
    }

    let mut pod_template = pb.build_template();
    pod_template.merge_from(role.config.pod_overrides.clone());
    pod_template.merge_from(role_group.config.pod_overrides.clone());

    Ok(Deployment {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(superset)
            .name(rolegroup_ref.object_name())
            .ownerreference_from_resource(superset, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(&recommended_object_labels)
            .context(MetadataBuildSnafu)?
            .with_label(
                Label::try_from(("restarter.stackable.tech/enabled", "true"))
                    .context(LabelBuildSnafu)?,
            )
            .build(),
        spec: Some(DeploymentSpec {
            replicas: role_group.replicas.map(i32::from),
            selector: LabelSelector {
                match_labels: Some(
                    Labels::role_group_selector(
                        superset,
                        APP_NAME,
                        &rolegroup_ref.role,
                        &rolegroup_ref.role_group,
                    )
                    .context(LabelBuildSnafu)?
                    .into(),
                ),
                ..LabelSelector::default()
            },
            template: pod_template,
            ..DeploymentSpec::default()
        }),
        status: None,
    })
}

/// The rolegroup [`Deployment`] runs the rolegroup, as configured by the administrator.
pub fn build_beat_rolegroup_deployment(
    superset: &SupersetCluster,
    resolved_product_image: &ResolvedProductImage,
    superset_role: &SupersetRole,
    rolegroup_ref: &RoleGroupRef<SupersetCluster>,
    node_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    sa_name: &str,
    merged_config: &SupersetConfig,
) -> Result<Deployment> {
    let role = superset
        .get_role(superset_role)
        .with_context(|| MissingRoleSnafu {
            role: superset_role.to_string(),
        })?;
    let role_group = role
        .role_groups
        .get(&rolegroup_ref.role_group)
        .with_context(|| MissingRoleGroupSnafu {
            role: superset_role.to_string(),
        })?;

    let recommended_object_labels = build_recommended_labels(
        superset,
        SUPERSET_CONTROLLER_NAME,
        &resolved_product_image.app_version_label_value,
        &rolegroup_ref.role,
        &rolegroup_ref.role_group,
    );

    let metadata = ObjectMetaBuilder::new()
        .with_recommended_labels(&recommended_object_labels)
        .context(MetadataBuildSnafu)?
        .build();

    let mut pb = &mut PodBuilder::new();

    pb = pb
        .metadata(metadata)
        .image_pull_secrets_from_product_image(resolved_product_image)
        .security_context(
            PodSecurityContextBuilder::new()
                .fs_group(1000) // Needed for secret-operator
                .build(),
        )
        .affinity(&merged_config.affinity)
        .service_account_name(sa_name);

    let mut superset_cb = ContainerBuilder::new(&Container::Superset.to_string())
        .context(InvalidContainerNameSnafu)?;

    let metadata_database_connection_details =
        super::metadata_database_connection_details(superset);
    let celery_results_backend_connection_details =
        super::celery_results_backend_connection_details(superset);
    let celery_broker_connection_details = super::celery_broker_connection_details(superset);

    metadata_database_connection_details.add_to_container(&mut superset_cb);
    if let (_, Some(celery_results_backend_connection_details)) =
        &celery_results_backend_connection_details
    {
        celery_results_backend_connection_details.add_to_container(&mut superset_cb);
    }
    if let Some(celery_broker_connection_details) = celery_broker_connection_details {
        celery_broker_connection_details.add_to_container(&mut superset_cb);
    }

    for (name, value) in node_config
        .get(&PropertyNameKind::Env)
        .cloned()
        .unwrap_or_default()
    {
        if name == SupersetConfig::MAPBOX_SECRET_PROPERTY {
            superset_cb.add_env_var_from_secret(
                "MAPBOX_API_KEY",
                &value,
                "connections.mapboxApiKey",
            );
        } else {
            superset_cb.add_env_var(name, value);
        };
    }

    // SECRET_KEY from auto-generated secret
    superset_cb.add_env_var_from_secret(
        "SECRET_KEY",
        superset.shared_secret_key_secret_name(),
        crate::crd::INTERNAL_SECRET_SECRET_KEY,
    );

    let secret = &superset.spec.cluster_config.credentials_secret_name;

    superset_cb
        .image_from_product_image(resolved_product_image)
        .add_container_port("http", APP_PORT.into())
        .add_volume_mount(CONFIG_VOLUME_NAME, STACKABLE_CONFIG_DIR)
        .context(AddVolumeMountSnafu)?
        .add_volume_mount(LOG_CONFIG_VOLUME_NAME, STACKABLE_LOG_CONFIG_DIR)
        .context(AddVolumeMountSnafu)?
        .add_volume_mount(LOG_VOLUME_NAME, STACKABLE_LOG_DIR)
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
        .add_env_var("SSL_CERT_DIR", "/stackable/certs/")
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
        ])
        // TODO: Without --loglevel=INFO, the beat does not log anyhing.
        //       This should be investigated and configurable.
        .args(vec![formatdoc! {"
            {COMMON_BASH_TRAP_FUNCTIONS}

            mkdir --parents {PYTHONPATH}
            cp {STACKABLE_CONFIG_DIR}/* {PYTHONPATH}
            cp {STACKABLE_LOG_CONFIG_DIR}/{LOG_CONFIG_FILE} {PYTHONPATH}

            {remove_vector_shutdown_file_command}
            prepare_signal_handlers
            containerdebug --output={STACKABLE_LOG_DIR}/containerdebug-state.json --loop &

            celery --app=superset.tasks.celery_app:app beat --pidfile /tmp/celerybeat.pid &

            wait_for_termination $!
            {create_vector_shutdown_file_command}
        ",
            remove_vector_shutdown_file_command =
                remove_vector_shutdown_file_command(STACKABLE_LOG_DIR),
            create_vector_shutdown_file_command =
                create_vector_shutdown_file_command(STACKABLE_LOG_DIR),
        }])
        .liveness_probe(Probe {
            exec: Some(ExecAction {
                command: Some(vec![
                    "[ -f /tmp/celerybeat.pid ] && kill -0 $(cat /tmp/celerybeat.pid)".to_string(),
                ]),
            }),
            initial_delay_seconds: Some(30),
            period_seconds: Some(30),
            timeout_seconds: Some(30),
            failure_threshold: Some(3),
            ..Default::default()
        })
        .resources(merged_config.resources.clone().into());

    pb.add_container(superset_cb.build());
    add_graceful_shutdown_config(merged_config, pb).context(GracefulShutdownSnafu)?;

    let metrics_container = ContainerBuilder::new("metrics")
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
        .build();

    pb.add_volumes(crate::resources::create_volumes(
        &rolegroup_ref.object_name(),
        merged_config.logging.containers.get(&Container::Superset),
    ))
    .context(AddVolumeSnafu)?;
    pb.add_container(metrics_container);

    if merged_config.logging.enable_vector_agent {
        match &superset
            .spec
            .cluster_config
            .vector_aggregator_config_map_name
        {
            Some(vector_aggregator_config_map_name) => {
                pb.add_container(
                    product_logging::framework::vector_container(
                        resolved_product_image,
                        CONFIG_VOLUME_NAME,
                        LOG_VOLUME_NAME,
                        merged_config.logging.containers.get(&Container::Vector),
                        ResourceRequirementsBuilder::new()
                            .with_cpu_request("250m")
                            .with_cpu_limit("500m")
                            .with_memory_request("128Mi")
                            .with_memory_limit("128Mi")
                            .build(),
                        vector_aggregator_config_map_name,
                    )
                    .context(ConfigureLoggingSnafu)?,
                );
            }
            None => {
                VectorAggregatorConfigMapMissingSnafu.fail()?;
            }
        }
    }

    let mut pod_template = pb.build_template();
    pod_template.merge_from(role.config.pod_overrides.clone());
    pod_template.merge_from(role_group.config.pod_overrides.clone());

    Ok(Deployment {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(superset)
            .name(rolegroup_ref.object_name())
            .ownerreference_from_resource(superset, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(&recommended_object_labels)
            .context(MetadataBuildSnafu)?
            .with_label(
                Label::try_from(("restarter.stackable.tech/enabled", "true"))
                    .context(LabelBuildSnafu)?,
            )
            .build(),
        spec: Some(DeploymentSpec {
            // Beat should always only be one Beat instance at a time.
            // We ignore values > 1, 0 is a possible value still.
            replicas: role_group
                .replicas
                .map(i32::from)
                .map(|r| if r >= 1 { 1 } else { 0 }),
            selector: LabelSelector {
                match_labels: Some(
                    Labels::role_group_selector(
                        superset,
                        APP_NAME,
                        &rolegroup_ref.role,
                        &rolegroup_ref.role_group,
                    )
                    .context(LabelBuildSnafu)?
                    .into(),
                ),
                ..LabelSelector::default()
            },
            template: pod_template,
            ..DeploymentSpec::default()
        }),
        status: None,
    })
}
