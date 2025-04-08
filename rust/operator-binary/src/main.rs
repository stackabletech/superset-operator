use std::{ops::Deref as _, sync::Arc};

use clap::Parser;
use futures::{StreamExt, pin_mut};
use stackable_operator::{
    YamlSchema,
    cli::{Command, ProductOperatorRun, RollingPeriod},
    commons::authentication::AuthenticationClass,
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        batch::v1::Job,
        core::v1::{ConfigMap, Service},
    },
    kube::{
        ResourceExt,
        core::DeserializeGuard,
        runtime::{
            Controller,
            events::{Recorder, Reporter},
            reflector::ObjectRef,
            watcher,
        },
    },
    logging::controller::report_controller_reconciled,
    shared::yaml::SerializeOptions,
};
use stackable_telemetry::{Tracing, tracing::settings::Settings};
use tracing::level_filters::LevelFilter;

use crate::{
    crd::{
        APP_NAME, SupersetCluster,
        druidconnection::{self, DruidConnection},
        v1alpha1,
    },
    druid_connection_controller::DRUID_CONNECTION_FULL_CONTROLLER_NAME,
    superset_controller::SUPERSET_FULL_CONTROLLER_NAME,
};

mod authorization;
mod commands;
mod config;
mod controller_commons;
mod crd;
mod druid_connection_controller;
mod operations;
mod product_logging;
mod rbac;
mod superset_controller;
mod util;

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub const APP_PORT: u16 = 8088;
pub const OPERATOR_NAME: &str = "superset.stackable.tech";

// TODO (@NickLarsenNZ): Change the variable to `CONSOLE_LOG`
pub const ENV_VAR_CONSOLE_LOG: &str = "SUPERSET_OPERATOR_LOG";

#[derive(Parser)]
#[clap(about, author)]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        Command::Crd => {
            SupersetCluster::merged_crd(SupersetCluster::V1Alpha1)?
                .print_yaml_schema(built_info::PKG_VERSION, SerializeOptions::default())?;
            DruidConnection::merged_crd(DruidConnection::V1Alpha1)?
                .print_yaml_schema(built_info::PKG_VERSION, SerializeOptions::default())?;
        }
        Command::Run(ProductOperatorRun {
            product_config,
            watch_namespace,
            telemetry_arguments,
            cluster_info_opts,
        }) => {
            let _tracing_guard = Tracing::builder()
                .service_name("superset-operator")
                .with_console_output((
                    ENV_VAR_CONSOLE_LOG,
                    LevelFilter::INFO,
                    !telemetry_arguments.no_console_output,
                ))
                // NOTE (@NickLarsenNZ): Before stackable-telemetry was used, the log directory was
                // set via an env: `SUPERSET_OPERATOR_LOG_DIRECTORY`.
                // See: https://github.com/stackabletech/operator-rs/blob/f035997fca85a54238c8de895389cc50b4d421e2/crates/stackable-operator/src/logging/mod.rs#L40
                // Now it will be `ROLLING_LOGS` (or via `--rolling-logs <DIRECTORY>`).
                .with_file_output(telemetry_arguments.rolling_logs.map(|log_directory| {
                    let rotation_period = telemetry_arguments
                        .rolling_logs_period
                        .unwrap_or(RollingPeriod::Never)
                        .deref()
                        .clone();

                    Settings::builder()
                        .with_environment_variable(ENV_VAR_CONSOLE_LOG)
                        .with_default_level(LevelFilter::INFO)
                        .file_log_settings_builder(log_directory, "tracing-rs.log")
                        .with_rotation_period(rotation_period)
                        .build()
                }))
                .with_otlp_log_exporter((
                    "OTLP_LOG",
                    LevelFilter::DEBUG,
                    telemetry_arguments.otlp_logs,
                ))
                .with_otlp_trace_exporter((
                    "OTLP_TRACE",
                    LevelFilter::DEBUG,
                    telemetry_arguments.otlp_traces,
                ))
                .build()
                .init()?;

            tracing::info!(
                built_info.pkg_version = built_info::PKG_VERSION,
                built_info.git_version = built_info::GIT_VERSION,
                built_info.target = built_info::TARGET,
                built_info.built_time_utc = built_info::BUILT_TIME_UTC,
                built_info.rustc_version = built_info::RUSTC_VERSION,
                "Starting {description}",
                description = built_info::PKG_DESCRIPTION
            );

            let product_config = product_config.load(&[
                "deploy/config-spec/properties.yaml",
                "/etc/stackable/superset-operator/config-spec/properties.yaml",
            ])?;

            let client = stackable_operator::client::initialize_operator(
                Some(OPERATOR_NAME.to_string()),
                &cluster_info_opts,
            )
            .await?;

            let superset_event_recorder =
                Arc::new(Recorder::new(client.as_kube_client(), Reporter {
                    controller: SUPERSET_FULL_CONTROLLER_NAME.to_string(),
                    instance: None,
                }));
            let superset_controller = Controller::new(
                watch_namespace.get_api::<DeserializeGuard<v1alpha1::SupersetCluster>>(&client),
                watcher::Config::default(),
            );
            let superset_store_1 = superset_controller.store();
            let superset_store_2 = superset_controller.store();
            let superset_controller = superset_controller
                .owns(
                    watch_namespace.get_api::<DeserializeGuard<Service>>(&client),
                    watcher::Config::default(),
                )
                .owns(
                    watch_namespace.get_api::<DeserializeGuard<StatefulSet>>(&client),
                    watcher::Config::default(),
                )
                .shutdown_on_signal()
                .watches(
                    client.get_api::<DeserializeGuard<AuthenticationClass>>(&()),
                    watcher::Config::default(),
                    move |authentication_class| {
                        superset_store_1
                            .state()
                            .into_iter()
                            .filter(move |superset| {
                                references_authentication_class(superset, &authentication_class)
                            })
                            .map(|superset| ObjectRef::from_obj(&*superset))
                    },
                )
                .watches(
                    watch_namespace.get_api::<DeserializeGuard<ConfigMap>>(&client),
                    watcher::Config::default(),
                    move |config_map| {
                        superset_store_2
                            .state()
                            .into_iter()
                            .filter(move |superset| references_config_map(superset, &config_map))
                            .map(|superset| ObjectRef::from_obj(&*superset))
                    },
                )
                .run(
                    superset_controller::reconcile_superset,
                    superset_controller::error_policy,
                    Arc::new(superset_controller::Ctx {
                        client: client.clone(),
                        product_config,
                    }),
                )
                // We can let the reporting happen in the background
                .for_each_concurrent(
                    16, // concurrency limit
                    |result| {
                        // The event_recorder needs to be shared across all invocations, so that
                        // events are correctly aggregated
                        let event_recorder = superset_event_recorder.clone();
                        async move {
                            report_controller_reconciled(
                                &event_recorder,
                                SUPERSET_FULL_CONTROLLER_NAME,
                                &result,
                            )
                            .await;
                        }
                    },
                );

            let druid_connection_event_recorder =
                Arc::new(Recorder::new(client.as_kube_client(), Reporter {
                    controller: DRUID_CONNECTION_FULL_CONTROLLER_NAME.to_string(),
                    instance: None,
                }));
            let druid_connection_controller = Controller::new(
                watch_namespace
                    .get_api::<DeserializeGuard<druidconnection::v1alpha1::DruidConnection>>(
                        &client,
                    ),
                watcher::Config::default(),
            );
            let druid_connection_store_1 = druid_connection_controller.store();
            let druid_connection_store_2 = druid_connection_controller.store();
            let druid_connection_store_3 = druid_connection_controller.store();
            let druid_connection_controller = druid_connection_controller
                .shutdown_on_signal()
                .watches(
                    watch_namespace.get_api::<DeserializeGuard<v1alpha1::SupersetCluster>>(&client),
                    watcher::Config::default(),
                    move |superset_cluster| {
                        druid_connection_store_1
                            .state()
                            .into_iter()
                            .filter(move |druid_connection| {
                                valid_druid_connection(&superset_cluster, druid_connection)
                            })
                            .map(|druid_connection| ObjectRef::from_obj(&*druid_connection))
                    },
                )
                .watches(
                    watch_namespace.get_api::<DeserializeGuard<Job>>(&client),
                    watcher::Config::default(),
                    move |job| {
                        druid_connection_store_2
                            .state()
                            .into_iter()
                            .filter(move |druid_connection| valid_druid_job(druid_connection, &job))
                            .map(|druid_connection| ObjectRef::from_obj(&*druid_connection))
                    },
                )
                .watches(
                    watch_namespace.get_api::<DeserializeGuard<ConfigMap>>(&client),
                    watcher::Config::default(),
                    move |config_map| {
                        druid_connection_store_3
                            .state()
                            .into_iter()
                            .filter(move |druid_connection| {
                                valid_druid_connection_namespace(druid_connection, &config_map)
                            })
                            .map(|druid_connection| ObjectRef::from_obj(&*druid_connection))
                    },
                )
                .run(
                    druid_connection_controller::reconcile_druid_connection,
                    druid_connection_controller::error_policy,
                    Arc::new(druid_connection_controller::Ctx {
                        client: client.clone(),
                    }),
                )
                // We can let the reporting happen in the background
                .for_each_concurrent(
                    16, // concurrency limit
                    move |result| {
                        // The event_recorder needs to be shared across all invocations, so that
                        // events are correctly aggregated
                        let event_recorder = druid_connection_event_recorder.clone();
                        async move {
                            report_controller_reconciled(
                                &event_recorder,
                                DRUID_CONNECTION_FULL_CONTROLLER_NAME,
                                &result,
                            )
                            .await;
                        }
                    },
                );

            pin_mut!(superset_controller, druid_connection_controller);
            // kube-runtime's Controller will tokio::spawn each reconciliation, so this only concerns the internal watch machinery
            futures::future::select(superset_controller, druid_connection_controller).await;
        }
    }

    Ok(())
}

fn references_authentication_class(
    superset: &DeserializeGuard<v1alpha1::SupersetCluster>,
    authentication_class: &DeserializeGuard<AuthenticationClass>,
) -> bool {
    let Ok(superset) = &superset.0 else {
        return false;
    };

    let authentication_class_name = authentication_class.name_any();
    superset
        .spec
        .cluster_config
        .authentication
        .iter()
        .any(|c| c.common.authentication_class_name() == &authentication_class_name)
}

fn references_config_map(
    superset: &DeserializeGuard<v1alpha1::SupersetCluster>,
    config_map: &DeserializeGuard<ConfigMap>,
) -> bool {
    let Ok(superset) = &superset.0 else {
        return false;
    };

    match superset.spec.cluster_config.authorization.clone() {
        Some(superset_authorization) => {
            superset_authorization
                .role_mapping_from_opa
                .opa
                .config_map_name
                == config_map.name_any()
        }
        None => false,
    }
}

fn valid_druid_connection(
    superset_cluster: &DeserializeGuard<v1alpha1::SupersetCluster>,
    druid_connection: &DeserializeGuard<druidconnection::v1alpha1::DruidConnection>,
) -> bool {
    let Ok(druid_connection) = &druid_connection.0 else {
        return false;
    };
    druid_connection.superset_name() == superset_cluster.name_any()
        && druid_connection.superset_namespace().ok() == superset_cluster.namespace()
}

fn valid_druid_connection_namespace(
    druid_connection: &DeserializeGuard<druidconnection::v1alpha1::DruidConnection>,
    config_map: &DeserializeGuard<ConfigMap>,
) -> bool {
    let Ok(druid_connection) = &druid_connection.0 else {
        return false;
    };
    druid_connection.druid_namespace().ok() == config_map.namespace()
        && druid_connection.druid_name() == config_map.name_any()
}

fn valid_druid_job(
    druid_connection: &DeserializeGuard<druidconnection::v1alpha1::DruidConnection>,
    job: &DeserializeGuard<Job>,
) -> bool {
    let Ok(druid_connection) = &druid_connection.0 else {
        return false;
    };
    druid_connection.metadata.namespace == job.namespace()
        && druid_connection.job_name() == job.name_any()
}
