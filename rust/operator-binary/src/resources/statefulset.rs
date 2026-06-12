use std::collections::BTreeSet;

use indoc::formatdoc;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{
            PodBuilder,
            container::ContainerBuilder,
            probe::ProbeBuilder,
            resources::ResourceRequirementsBuilder,
            security::PodSecurityContextBuilder,
            volume::{
                ListenerOperatorVolumeSourceBuilder, ListenerOperatorVolumeSourceBuilderError,
                ListenerReference,
            },
        },
    },
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::EnvVar,
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    kvp::{Label, Labels},
    product_logging::{
        self,
        framework::{create_vector_shutdown_file_command, remove_vector_shutdown_file_command},
    },
    role_utils::RoleGroupRef,
    shared::time::Duration,
    utils::COMMON_BASH_TRAP_FUNCTIONS,
    v2::builder::meta::ownerreference_from_resource,
};

use crate::{
    controller::{
        SUPERSET_CONTROLLER_NAME, SupersetRoleGroupConfig, ValidatedCluster,
        build::{
            command::add_cert_to_python_certifi_command,
            properties::{ConfigFileName, superset_config::DEFAULT_WEBSERVER_TIMEOUT},
        },
    },
    crd::{
        APP_NAME, APP_PORT, METRICS_PORT, METRICS_PORT_NAME, PYTHONPATH, STACKABLE_CONFIG_DIR,
        STACKABLE_LOG_CONFIG_DIR, STACKABLE_LOG_DIR, SupersetRole,
        authentication::{
            SupersetAuthenticationClassResolved, SupersetClientAuthenticationDetailsResolved,
        },
        v1alpha1::{Container, SupersetCluster},
    },
    operations::graceful_shutdown::add_graceful_shutdown_config,
    resources::{
        CONFIG_VOLUME_NAME, LOG_CONFIG_VOLUME_NAME, LOG_VOLUME_NAME, build_recommended_labels,
        listener::{LISTENER_VOLUME_DIR, LISTENER_VOLUME_NAME},
    },
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("invalid container name"))]
    InvalidContainerName {
        source: stackable_operator::builder::pod::container::Error,
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

    #[snafu(display("failed to configure logging"))]
    ConfigureLogging {
        source: product_logging::framework::LoggingError,
    },

    #[snafu(display("failed to add LDAP Volumes and VolumeMounts"))]
    AddLdapVolumesAndVolumeMounts {
        source: stackable_operator::crd::authentication::ldap::v1alpha1::Error,
    },

    #[snafu(display("failed to add TLS Volumes and VolumeMounts"))]
    AddTlsVolumesAndVolumeMounts {
        source: stackable_operator::commons::tls_verification::TlsClientDetailsError,
    },

    #[snafu(display("failed to add needed volume"))]
    AddVolume {
        source: stackable_operator::builder::pod::Error,
    },

    #[snafu(display("failed to add needed volumeMount"))]
    AddVolumeMount {
        source: stackable_operator::builder::pod::container::Error,
    },

    #[snafu(display("failed to build listener volume"))]
    BuildListenerVolume {
        source: ListenerOperatorVolumeSourceBuilderError,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// The rolegroup [`StatefulSet`] runs the rolegroup, as configured by the administrator.
pub fn build_server_rolegroup_statefulset(
    validated: &ValidatedCluster,
    superset_role: &SupersetRole,
    rolegroup_ref: &RoleGroupRef<SupersetCluster>,
    rolegroup_config: &SupersetRoleGroupConfig,
    sa_name: &str,
) -> Result<StatefulSet> {
    let merged_config = &rolegroup_config.config;
    let env_overrides = &rolegroup_config.env_overrides;

    let recommended_object_labels = build_recommended_labels(
        validated,
        SUPERSET_CONTROLLER_NAME,
        &validated.image.app_version_label_value,
        &rolegroup_ref.role,
        &rolegroup_ref.role_group,
    );
    // Used for PVC templates that cannot be modified once they are deployed
    let unversioned_recommended_labels = Labels::recommended(&build_recommended_labels(
        validated,
        SUPERSET_CONTROLLER_NAME,
        // A version value is required, and we do want to use the "recommended" format for the other desired labels
        "none",
        &rolegroup_ref.role,
        &rolegroup_ref.role_group,
    ))
    .context(LabelBuildSnafu)?;

    let metadata = ObjectMetaBuilder::new()
        .with_recommended_labels(&recommended_object_labels)
        .context(MetadataBuildSnafu)?
        .build();

    let mut pb = &mut PodBuilder::new();

    pb = pb
        .metadata(metadata)
        .image_pull_secrets_from_product_image(&validated.image)
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
        super::metadata_database_connection_details(&validated.cluster_config.metadata_database);
    let celery_results_backend_connection_details =
        super::celery_results_backend_connection_details(
            validated.cluster_config.celery_results_backend.as_ref(),
        );
    let celery_broker_connection_details =
        super::celery_broker_connection_details(validated.cluster_config.celery_broker.as_ref());

    metadata_database_connection_details.add_to_container(&mut superset_cb);
    if let (_, Some(celery_results_backend_connection_details)) =
        &celery_results_backend_connection_details
    {
        celery_results_backend_connection_details.add_to_container(&mut superset_cb);
    }
    if let Some(celery_broker_connection_details) = celery_broker_connection_details {
        celery_broker_connection_details.add_to_container(&mut superset_cb);
    }

    superset_cb.add_env_vars(env_overrides.clone());
    if let Some(mapbox_secret) = &validated.cluster_config.mapbox_secret {
        superset_cb.add_env_var_from_secret(
            "MAPBOX_API_KEY",
            mapbox_secret,
            "connections.mapboxApiKey",
        );
    }

    // SECRET_KEY from auto-generated secret
    superset_cb.add_env_var_from_secret(
        "SECRET_KEY",
        validated.cluster_config.secret_key_secret_name.clone(),
        crate::crd::INTERNAL_SECRET_SECRET_KEY,
    );

    add_authentication_volumes_and_volume_mounts(
        &validated.cluster_config.authentication_config,
        &mut superset_cb,
        pb,
    )?;

    // The gunicorn worker timeout mirrors the `SUPERSET_WEBSERVER_TIMEOUT` written into
    // `superset_config.py` (see `controller::build::properties::superset_config`).
    let webserver_timeout = merged_config
        .webserver_timeout
        .unwrap_or(DEFAULT_WEBSERVER_TIMEOUT);

    let secret = &validated.cluster_config.credentials_secret_name;

    superset_cb
        .image_from_product_image(&validated.image)
        .add_container_port("http", APP_PORT.into())
        .add_volume_mount(CONFIG_VOLUME_NAME, STACKABLE_CONFIG_DIR).context(AddVolumeMountSnafu)?
        .add_volume_mount(LOG_CONFIG_VOLUME_NAME, STACKABLE_LOG_CONFIG_DIR).context(AddVolumeMountSnafu)?
        .add_volume_mount(LOG_VOLUME_NAME, STACKABLE_LOG_DIR).context(AddVolumeMountSnafu)?
        .add_env_var_from_secret("ADMIN_USERNAME", secret, "adminUser.username")
        .add_env_var_from_secret("ADMIN_FIRSTNAME", secret, "adminUser.firstname")
        .add_env_var_from_secret("ADMIN_LASTNAME", secret, "adminUser.lastname")
        .add_env_var_from_secret("ADMIN_EMAIL", secret, "adminUser.email")
        .add_env_var_from_secret("ADMIN_PASSWORD", secret, "adminUser.password")
        // Needed by the `containerdebug` process to log it's tracing information to.
        .add_env_var("CONTAINERDEBUG_LOG_DIRECTORY", format!("{STACKABLE_LOG_DIR}/containerdebug"))
        .add_env_var("SSL_CERT_DIR", "/stackable/certs/")
        .add_env_vars(authentication_env_vars(&validated.cluster_config.authentication_config))
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
        ])
        .args(vec![formatdoc! {"
            {COMMON_BASH_TRAP_FUNCTIONS}

            mkdir --parents {PYTHONPATH}
            cp {STACKABLE_CONFIG_DIR}/* {PYTHONPATH}
            cp {STACKABLE_LOG_CONFIG_DIR}/{log_config_file} {PYTHONPATH}

            {auth_commands}

            superset db upgrade
            set +x
            echo 'Running \"superset fab create-admin [...]\", which is not shown as it leaks the Superset admin credentials'
            superset fab create-admin --username \"$ADMIN_USERNAME\" --firstname \"$ADMIN_FIRSTNAME\" --lastname \"$ADMIN_LASTNAME\" --email \"$ADMIN_EMAIL\" --password \"$ADMIN_PASSWORD\"
            set -x
            superset init

            {remove_vector_shutdown_file_command}
            prepare_signal_handlers
            containerdebug --output={STACKABLE_LOG_DIR}/containerdebug-state.json --loop &
            gunicorn --bind 0.0.0.0:${{SUPERSET_PORT}} --worker-class gthread --threads 20 --timeout {webserver_timeout} --limit-request-line 0 --limit-request-field_size 0 'superset.app:create_app()' &
            wait_for_termination $!

            {create_vector_shutdown_file_command}
        ",
            log_config_file = ConfigFileName::LogConfig,
            auth_commands = authentication_start_commands(&validated.cluster_config.authentication_config),
            remove_vector_shutdown_file_command =
                remove_vector_shutdown_file_command(STACKABLE_LOG_DIR),
            create_vector_shutdown_file_command =
                create_vector_shutdown_file_command(STACKABLE_LOG_DIR),
        }])
        .resources(merged_config.resources.clone().into());
    add_superset_container_probes(&mut superset_cb);

    // listener endpoints will use persistent volumes
    // so that load balancers can hard-code the target addresses and
    // that it is possible to connect to a consistent address
    let pvcs = if let Some(group_listener_name) = validated
        .role_configs
        .get(superset_role)
        .and_then(|role_config| role_config.group_listener_name.clone())
    {
        let pvc = ListenerOperatorVolumeSourceBuilder::new(
            &ListenerReference::ListenerName(group_listener_name),
            &unversioned_recommended_labels,
        )
        .build_pvc(LISTENER_VOLUME_NAME.to_owned())
        .context(BuildListenerVolumeSnafu)?;
        Some(vec![pvc])
    } else {
        None
    };

    superset_cb
        .add_volume_mount(LISTENER_VOLUME_NAME, LISTENER_VOLUME_DIR)
        .context(AddVolumeMountSnafu)?;

    pb.add_container(superset_cb.build());
    add_graceful_shutdown_config(merged_config, pb).context(GracefulShutdownSnafu)?;

    let metrics_container = ContainerBuilder::new("metrics")
        .context(InvalidContainerNameSnafu)?
        .image_from_product_image(&validated.image)
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
        match &validated.cluster_config.vector_aggregator_config_map_name {
            Some(vector_aggregator_config_map_name) => {
                pb.add_container(
                    product_logging::framework::vector_container(
                        &validated.image,
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
    pod_template.merge_from(rolegroup_config.pod_overrides.clone());

    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(validated)
            .name(rolegroup_ref.object_name())
            .ownerreference(ownerreference_from_resource(validated, None, Some(true)))
            .with_recommended_labels(&recommended_object_labels)
            .context(MetadataBuildSnafu)?
            .with_label(
                Label::try_from(("restarter.stackable.tech/enabled", "true"))
                    .context(LabelBuildSnafu)?,
            )
            .build(),
        spec: Some(StatefulSetSpec {
            // Set to `OrderedReady`, to make sure Pods start after another and the init commands don't run in parallel
            pod_management_policy: Some("OrderedReady".to_string()),
            replicas: Some(i32::from(rolegroup_config.replicas)),
            selector: LabelSelector {
                match_labels: Some(
                    Labels::role_group_selector(
                        validated,
                        APP_NAME,
                        &rolegroup_ref.role,
                        &rolegroup_ref.role_group,
                    )
                    .context(LabelBuildSnafu)?
                    .into(),
                ),
                ..LabelSelector::default()
            },
            service_name: Some(rolegroup_ref.rolegroup_headless_service_name()),
            template: pod_template,
            volume_claim_templates: pvcs,
            ..StatefulSetSpec::default()
        }),
        status: None,
    })
}

fn add_superset_container_probes(superset_cb: &mut ContainerBuilder) {
    let common =
        ProbeBuilder::http_get_port_scheme_path(APP_PORT, None, Some("/health".to_owned()))
            .with_period(Duration::from_secs(5));

    superset_cb.startup_probe(
        common
            .clone()
            .with_failure_threshold_duration(Duration::from_minutes_unchecked(10))
            .expect("const period is non-zero")
            .build()
            .expect("const duration does not overflow"),
    );

    // Remove it from the Service immediately
    superset_cb.readiness_probe(
        common
            .clone()
            .build()
            .expect("const duration does not overflow"),
    );
    // But only restart it after 3 failures
    superset_cb.liveness_probe(
        common
            .with_failure_threshold(3)
            .build()
            .expect("const duration does not overflow"),
    );
}

fn add_authentication_volumes_and_volume_mounts(
    auth_config: &SupersetClientAuthenticationDetailsResolved,
    cb: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) -> Result<()> {
    // Different authentication entries can reference the same secret
    // class or TLS certificate. It must be ensured that the volumes
    // and volume mounts are only added once in such a case.

    let mut ldap_authentication_providers = BTreeSet::new();
    let mut tls_client_credentials = BTreeSet::new();

    for auth_class_resolved in &auth_config.authentication_classes_resolved {
        match auth_class_resolved {
            SupersetAuthenticationClassResolved::Ldap { provider } => {
                ldap_authentication_providers.insert(provider);
            }
            SupersetAuthenticationClassResolved::Oidc { provider, .. } => {
                tls_client_credentials.insert(&provider.tls);
            }
        }
    }

    for provider in ldap_authentication_providers {
        provider
            .add_volumes_and_mounts(pb, vec![cb])
            .context(AddLdapVolumesAndVolumeMountsSnafu)?;
    }

    for tls in tls_client_credentials {
        tls.add_volumes_and_mounts(pb, vec![cb])
            .context(AddTlsVolumesAndVolumeMountsSnafu)?;
    }

    Ok(())
}

fn authentication_env_vars(
    auth_config: &SupersetClientAuthenticationDetailsResolved,
) -> Vec<EnvVar> {
    // Different OIDC authentication entries can reference the same
    // client secret. It must be ensured that the env variables are only
    // added once in such a case.

    let mut oidc_client_credentials_secrets = BTreeSet::new();

    for auth_class_resolved in &auth_config.authentication_classes_resolved {
        match auth_class_resolved {
            SupersetAuthenticationClassResolved::Ldap { .. } => {}
            SupersetAuthenticationClassResolved::Oidc {
                client_auth_options: oidc,
                ..
            } => {
                oidc_client_credentials_secrets
                    .insert(oidc.client_credentials_secret_ref.to_owned());
            }
        }
    }

    oidc_client_credentials_secrets
        .iter()
        .cloned()
        .flat_map(stackable_operator::crd::authentication::oidc::v1alpha1::AuthenticationProvider::client_credentials_env_var_mounts)
        .collect()
}

fn authentication_start_commands(
    auth_config: &SupersetClientAuthenticationDetailsResolved,
) -> String {
    let mut commands = Vec::new();

    let mut tls_client_credentials = BTreeSet::new();

    for auth_class_resolved in &auth_config.authentication_classes_resolved {
        match auth_class_resolved {
            SupersetAuthenticationClassResolved::Oidc { provider, .. } => {
                tls_client_credentials.insert(&provider.tls);

                // WebPKI will be handled implicitly
            }
            SupersetAuthenticationClassResolved::Ldap { .. } => {}
        }
    }

    for tls in tls_client_credentials {
        commands.push(tls.tls_ca_cert_mount_path().map(|tls_ca_cert_mount_path| {
            add_cert_to_python_certifi_command(&tls_ca_cert_mount_path)
        }));
    }

    commands
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}
