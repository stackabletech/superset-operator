use indoc::formatdoc;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{PodBuilder, security::PodSecurityContextBuilder},
    },
    constants::RESTART_CONTROLLER_ENABLED_LABEL,
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{Deployment, DeploymentSpec},
            core::v1::{ExecAction, Probe},
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    product_logging::framework::{
        create_vector_shutdown_file_command, remove_vector_shutdown_file_command,
    },
    utils::COMMON_BASH_TRAP_FUNCTIONS,
    v2::{product_logging::framework::STACKABLE_LOG_DIR, types::operator::RoleGroupName},
};

use crate::{
    controller::{SupersetRoleGroupConfig, ValidatedCluster, build::properties::ConfigFileName},
    crd::{PYTHONPATH, STACKABLE_CONFIG_DIR, STACKABLE_LOG_CONFIG_DIR, SupersetRole},
};

/// PID file written by the Celery `beat` process; its liveness probe checks the same path, so both
/// must agree.
const CELERY_BEAT_PIDFILE: &str = "/tmp/celerybeat.pid";

/// Base Celery CLI invocation shared by the worker/beat commands and the worker liveness probe.
const CELERY_APP_INVOCATION: &str = "celery --app=superset.tasks.celery_app:app";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to build container"))]
    BuildContainer { source: super::Error },

    #[snafu(display("failed to set termination grace period for graceful shutdown"))]
    GracefulShutdown {
        source: stackable_operator::builder::pod::Error,
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

/// The rolegroup [`Deployment`] runs a Celery `worker` or `beat` rolegroup, as configured by the
/// administrator. The `Node` role is deployed as a
/// [`StatefulSet`](super::statefulset::build_node_rolegroup_statefulset) instead.
pub fn build_rolegroup_deployment(
    validated: &ValidatedCluster,
    superset_role: &SupersetRole,
    role_group_name: &RoleGroupName,
    rolegroup_config: &SupersetRoleGroupConfig,
    sa_name: &str,
) -> Result<Deployment> {
    let merged_config = &rolegroup_config.config;

    let resource_names = validated.resource_names(superset_role, role_group_name);
    let recommended_object_labels = validated.recommended_labels(superset_role, role_group_name);

    // The Celery process command, liveness probe and replica policy are the only differences
    // between the `worker` and `beat` rolegroups.
    let (celery_command, liveness_probe, replicas) = match superset_role {
        SupersetRole::Worker => (
            format!("{CELERY_APP_INVOCATION} worker --task-events"),
            worker_liveness_probe(),
            rolegroup_config.replicas,
        ),
        SupersetRole::Beat => (
            format!("{CELERY_APP_INVOCATION} beat --pidfile {CELERY_BEAT_PIDFILE}"),
            beat_liveness_probe(),
            beat_replicas(rolegroup_config.replicas),
        ),
        SupersetRole::Node => {
            unreachable!("the `Node` role is deployed as a StatefulSet, not a Deployment")
        }
    };

    let metadata = ObjectMetaBuilder::new()
        .with_labels(recommended_object_labels)
        .build();

    let mut pb = PodBuilder::new();
    pb.metadata(metadata)
        .image_pull_secrets_from_product_image(&validated.image)
        .security_context(
            PodSecurityContextBuilder::new()
                .fs_group(super::SECRET_OPERATOR_FS_GROUP) // Needed for secret-operator
                .build(),
        )
        .affinity(&merged_config.affinity)
        .service_account_name(sa_name);

    let mut superset_cb = super::build_superset_container_builder(validated, rolegroup_config)
        .context(BuildContainerSnafu)?;

    superset_cb
        .command(super::bash_wrapper_command())
        .args(vec![formatdoc! {"
            {COMMON_BASH_TRAP_FUNCTIONS}

            mkdir --parents {PYTHONPATH}
            cp {STACKABLE_CONFIG_DIR}/* {PYTHONPATH}
            cp {STACKABLE_LOG_CONFIG_DIR}/{log_config_file} {PYTHONPATH}

            {remove_vector_shutdown_file_command}
            prepare_signal_handlers
            containerdebug --output={STACKABLE_LOG_DIR}/containerdebug-state.json --loop &

            {celery_command} &

            wait_for_termination $!
            {create_vector_shutdown_file_command}
        ",
            log_config_file = ConfigFileName::LogConfig,
            remove_vector_shutdown_file_command =
                remove_vector_shutdown_file_command(STACKABLE_LOG_DIR),
            create_vector_shutdown_file_command =
                create_vector_shutdown_file_command(STACKABLE_LOG_DIR),
        }])
        .liveness_probe(liveness_probe)
        .resources(merged_config.resources.clone().into());

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

    Ok(Deployment {
        metadata: validated
            .object_meta(
                resource_names.deployment_name().to_string(),
                superset_role,
                role_group_name,
            )
            .with_label(RESTART_CONTROLLER_ENABLED_LABEL.to_owned())
            .build(),
        spec: Some(DeploymentSpec {
            replicas: replicas.map(i32::from),
            selector: LabelSelector {
                match_labels: Some(
                    validated
                        .role_group_selector(superset_role, role_group_name)
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

/// Liveness probe for the Celery `worker` process.
fn worker_liveness_probe() -> Probe {
    Probe {
        exec: Some(ExecAction {
            command: Some(vec![format!(
                "{CELERY_APP_INVOCATION} inspect ping -d celery@$HOSTNAME"
            )]),
        }),
        initial_delay_seconds: Some(30),
        period_seconds: Some(30),
        timeout_seconds: Some(30),
        failure_threshold: Some(3),
        ..Default::default()
    }
}

/// Liveness probe for the Celery `beat` process.
fn beat_liveness_probe() -> Probe {
    Probe {
        exec: Some(ExecAction {
            command: Some(vec![format!(
                "[ -f {CELERY_BEAT_PIDFILE} ] && kill -0 $(cat {CELERY_BEAT_PIDFILE})"
            )]),
        }),
        initial_delay_seconds: Some(30),
        period_seconds: Some(30),
        timeout_seconds: Some(30),
        failure_threshold: Some(3),
        ..Default::default()
    }
}

/// Computes the replica count for the Celery `beat` role.
///
/// Beat is a singleton scheduler, so it must never run more than one instance: an explicit `0` is
/// honoured (to stop Beat), any value `> 1` is clamped to `1` (with a warning), and an unset value
/// defaults to `1`. The result is always `Some`, so no HorizontalPodAutoscaler can own the count.
fn beat_replicas(requested: Option<u16>) -> Option<u16> {
    match requested {
        Some(0) => Some(0),
        Some(replicas) if replicas > 1 => {
            tracing::warn!(
                "replicas for role `beat` set to greater `1`. Multiple beat instances are not allowed. Setting to `1` replica."
            );
            Some(1)
        }
        _ => Some(1),
    }
}

#[cfg(test)]
mod tests {
    use super::beat_replicas;

    #[test]
    fn beat_replicas_clamps_to_a_single_instance() {
        // An unset replica count defaults to a single instance.
        assert_eq!(beat_replicas(None), Some(1));
        // An explicit `0` is honoured so Beat can be stopped.
        assert_eq!(beat_replicas(Some(0)), Some(0));
        // A single instance is kept as-is.
        assert_eq!(beat_replicas(Some(1)), Some(1));
        // Anything greater than one is clamped down to a single instance.
        assert_eq!(beat_replicas(Some(2)), Some(1));
        assert_eq!(beat_replicas(Some(100)), Some(1));
    }
}
