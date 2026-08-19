use std::collections::BTreeSet;

use indoc::formatdoc;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{
            PodBuilder, container::ContainerBuilder, probe::ProbeBuilder,
            security::PodSecurityContextBuilder,
        },
    },
    constants::RESTART_CONTROLLER_ENABLED_LABEL,
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::Probe,
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    product_logging::framework::{
        create_vector_shutdown_file_command, remove_vector_shutdown_file_command,
    },
    shared::time::Duration,
    utils::COMMON_BASH_TRAP_FUNCTIONS,
    v2::{
        builder::pod::{
            container::EnvVarSet,
            volume::{ListenerReference, listener_operator_volume_source_builder_build_pvc},
        },
        product_logging::framework::STACKABLE_LOG_DIR,
        types::operator::RoleGroupName,
    },
};

use crate::{
    controller::{
        SupersetRoleGroupConfig, ValidatedCluster,
        build::{
            command::add_cert_to_python_certifi_command,
            object_meta,
            properties::{ConfigFileName, superset_config},
            recommended_labels_for_role_group_resources,
            recommended_labels_for_unversioned_role_group_resources,
            resource::listener::LISTENER_VOLUME_DIR,
            role_group_selector,
        },
    },
    crd::{
        APP_PORT, APP_PORT_NAME, PYTHONPATH, STACKABLE_CONFIG_DIR, STACKABLE_LOG_CONFIG_DIR,
        SupersetRole,
        authentication::{
            SupersetAuthenticationClassResolved, SupersetClientAuthenticationDetailsResolved,
        },
    },
};

/// `StatefulSet` pod management policy: start Pods one after another so the init commands don't run
/// in parallel.
const POD_MANAGEMENT_POLICY_ORDERED_READY: &str = "OrderedReady";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to build container"))]
    BuildContainer { source: super::Error },

    #[snafu(display("failed to set termination grace period for graceful shutdown"))]
    GracefulShutdown {
        source: stackable_operator::builder::pod::Error,
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
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// The rolegroup [`StatefulSet`] runs the rolegroup, as configured by the administrator.
pub fn build_node_rolegroup_statefulset(
    validated: &ValidatedCluster,
    superset_role: &SupersetRole,
    role_group_name: &RoleGroupName,
    rolegroup_config: &SupersetRoleGroupConfig,
) -> Result<StatefulSet> {
    let merged_config = &rolegroup_config.config;

    let resource_names = validated.role_group_resource_names(superset_role, role_group_name);
    let recommended_object_labels =
        recommended_labels_for_role_group_resources(validated, superset_role, role_group_name);
    // Used for PVC templates that cannot be modified once they are deployed (a constant "none"
    // version keeps the labels stable across version upgrades).
    let unversioned_recommended_labels = recommended_labels_for_unversioned_role_group_resources(
        validated,
        superset_role,
        role_group_name,
    );

    let metadata = ObjectMetaBuilder::new()
        .with_labels(recommended_object_labels)
        .build();

    let mut pb = PodBuilder::new();
    pb.metadata(metadata)
        .image_pull_secrets_from_product_image(&validated.image)
        .security_context(
            PodSecurityContextBuilder::with_stackable_defaults()
                .fs_group(super::SECRET_OPERATOR_FS_GROUP) // Needed for secret-operator
                .build(),
        )
        .affinity(&merged_config.affinity)
        .service_account_name(
            validated
                .cluster_resource_names()
                .service_account_name()
                .to_string(),
        );

    // The `Node` role serves the Superset web UI, so it additionally passes the authentication
    // env vars into the shared container builder (which merges the user `envOverrides` in last,
    // so they keep the highest precedence) and mounts the authentication volumes. These mounts
    // are added after the common config volume mounts (volume mount order is not significant).
    let mut superset_cb = super::build_superset_container_builder(
        validated,
        rolegroup_config,
        authentication_env_vars(&validated.cluster_config.authentication_config),
    )
    .context(BuildContainerSnafu)?;

    add_authentication_volumes_and_volume_mounts(
        &validated.cluster_config.authentication_config,
        &mut superset_cb,
        &mut pb,
    )?;

    // The gunicorn worker timeout mirrors the `SUPERSET_WEBSERVER_TIMEOUT` written into
    // `superset_config.py`: read from the same assembled property map (default ← typed field ←
    // configOverrides) so the flag and the file never disagree, even under a user override.
    let webserver_timeout = superset_config::webserver_timeout(
        superset_role,
        merged_config,
        &rolegroup_config.config_overrides,
    )
    .unwrap_or_else(|| superset_config::DEFAULT_WEBSERVER_TIMEOUT.to_string());

    superset_cb
        .command(super::bash_wrapper_command())
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
    // Only the `Node` role serves the Superset web UI, so the HTTP container port is added here
    // rather than in the shared container builder.
    let (startup_probe, readiness_probe, liveness_probe) = superset_container_probes();
    superset_cb
        .add_container_port(APP_PORT_NAME, APP_PORT.into())
        .startup_probe(startup_probe)
        .readiness_probe(readiness_probe)
        .liveness_probe(liveness_probe);

    // listener endpoints will use persistent volumes
    // so that load balancers can hard-code the target addresses and
    // that it is possible to connect to a consistent address
    let pvcs = if let Some(group_listener_name) = validated
        .role_configs
        .get(superset_role)
        .and_then(|role_config| role_config.group_listener_name.clone())
    {
        let pvc = listener_operator_volume_source_builder_build_pvc(
            &ListenerReference::Listener(group_listener_name),
            &unversioned_recommended_labels,
            &super::LISTENER_VOLUME_NAME_PVC,
        );
        Some(vec![pvc])
    } else {
        None
    };

    superset_cb
        .add_volume_mount(
            super::LISTENER_VOLUME_NAME_PVC.as_ref(),
            LISTENER_VOLUME_DIR,
        )
        .context(AddVolumeMountSnafu)?;

    pb.add_container(superset_cb.build());
    if let Some(termination_grace_period) = merged_config.graceful_shutdown_timeout {
        pb.termination_grace_period(&termination_grace_period)
            .context(GracefulShutdownSnafu)?;
    }

    pb.add_volumes(super::create_volumes(
        resource_names.role_group_config_map().as_ref(),
        &rolegroup_config.config.logging.superset_container,
    ))
    .context(AddVolumeSnafu)?;
    pb.add_container(super::build_metrics_container(&validated.image));

    if let Some(vector_container) =
        super::build_vector_container(validated, superset_role, role_group_name, rolegroup_config)
    {
        pb.add_container(vector_container);
    }

    let mut pod_template = pb.build_template();
    pod_template.merge_from(rolegroup_config.pod_overrides.clone());

    Ok(StatefulSet {
        metadata: object_meta(
            validated,
            resource_names.stateful_set_name().to_string(),
            superset_role,
            role_group_name,
        )
        .with_label(RESTART_CONTROLLER_ENABLED_LABEL.to_owned())
        .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some(POD_MANAGEMENT_POLICY_ORDERED_READY.to_string()),
            replicas: rolegroup_config.replicas.map(i32::from),
            selector: LabelSelector {
                match_labels: Some(
                    role_group_selector(validated, superset_role, role_group_name).into(),
                ),
                ..LabelSelector::default()
            },
            service_name: Some(resource_names.headless_service_name().to_string()),
            template: pod_template,
            volume_claim_templates: pvcs,
            ..StatefulSetSpec::default()
        }),
        status: None,
    })
}

/// Builds the startup, readiness and liveness probes for the `superset` container, all derived from
/// a common HTTP `/health` check. Returned (rather than applied to a builder) so the caller owns the
/// container assembly.
fn superset_container_probes() -> (Probe, Probe, Probe) {
    let common =
        ProbeBuilder::http_get_port_scheme_path(APP_PORT.0, None, Some("/health".to_owned()))
            .with_period(Duration::from_secs(5));

    let startup_probe = common
        .clone()
        .with_failure_threshold_duration(Duration::from_minutes_unchecked(10))
        .expect("const period is non-zero")
        .build()
        .expect("const duration does not overflow");

    // Remove it from the Service immediately
    let readiness_probe = common
        .clone()
        .build()
        .expect("const duration does not overflow");

    // But only restart it after 3 failures
    let liveness_probe = common
        .with_failure_threshold(3)
        .build()
        .expect("const duration does not overflow");

    (startup_probe, readiness_probe, liveness_probe)
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

fn authentication_env_vars(auth_config: &SupersetClientAuthenticationDetailsResolved) -> EnvVarSet {
    // Different OIDC authentication entries can reference the same
    // client secret. The name-keyed EnvVarSet ensures that the env
    // variables are only added once in such a case.

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

    let mut env_vars = EnvVarSet::new();
    for env_var in oidc_client_credentials_secrets
        .iter()
        .cloned()
        .flat_map(stackable_operator::crd::authentication::oidc::v1alpha1::AuthenticationProvider::client_credentials_env_var_mounts)
    {
        env_vars = env_vars.with_env_var(env_var).expect(
            "the OIDC client credentials env var names are generated by operator-rs and are \
             therefore valid",
        );
    }
    env_vars
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use stackable_operator::v2::{
        builder::pod::container::{EnvVarName, EnvVarSet},
        types::operator::RoleGroupName,
    };

    use super::build_node_rolegroup_statefulset;
    use crate::{controller::build::test_support::validated_cluster, crd::SupersetRole};

    /// The user-supplied `envOverrides` must be merged in after all operator-set environment
    /// variables, so that they can override any of them. `CONTAINERDEBUG_LOG_DIRECTORY` is used
    /// as the example here because it is set unconditionally by the operator.
    #[test]
    fn env_overrides_override_operator_set_env_vars() {
        let cluster = validated_cluster();
        let role_group_name = RoleGroupName::from_str("default").expect("valid role group name");
        let mut rg = cluster
            .role_groups
            .get(&SupersetRole::Node)
            .and_then(|groups| groups.get(&role_group_name))
            .expect("node default role group")
            .clone();
        rg.env_overrides = EnvVarSet::new().with_value(
            &EnvVarName::from_str("CONTAINERDEBUG_LOG_DIRECTORY").expect("valid env var name"),
            "/stackable/log/user-override",
        );

        let stateful_set =
            build_node_rolegroup_statefulset(&cluster, &SupersetRole::Node, &role_group_name, &rg)
                .expect("statefulset built");

        let containers = stateful_set
            .spec
            .expect("statefulset spec")
            .template
            .spec
            .expect("pod spec")
            .containers;
        let superset_container = containers
            .iter()
            .find(|container| container.name == "superset")
            .expect("superset container");
        let matching_env_vars: Vec<_> = superset_container
            .env
            .iter()
            .flatten()
            .filter(|env_var| env_var.name == "CONTAINERDEBUG_LOG_DIRECTORY")
            .collect();
        assert_eq!(
            matching_env_vars.len(),
            1,
            "the env override must result in exactly one env var entry, \
             not rely on kubelet duplicate-name handling"
        );
        assert_eq!(
            matching_env_vars[0].value.as_deref(),
            Some("/stackable/log/user-override"),
            "the user-supplied env override must win over the operator-set value"
        );
    }
}
