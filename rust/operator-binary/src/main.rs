use std::sync::Arc;

use clap::Parser;
use futures::{StreamExt, pin_mut};
use stackable_operator::{
    YamlSchema,
    cli::{Command, ProductOperatorRun},
    crd::authentication::core,
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
    telemetry::Tracing,
};

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

pub const OPERATOR_NAME: &str = "superset.stackable.tech";

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
            // NOTE (@NickLarsenNZ): Before stackable-telemetry was used:
            // - The console log level was set by `SUPERSET_OPERATOR_LOG`, and is now `CONSOLE_LOG` (when using Tracing::pre_configured).
            // - The file log level was set by `SUPERSET_OPERATOR_LOG`, and is now set via `FILE_LOG` (when using Tracing::pre_configured).
            // - The file log directory was set by `SUPERSET_OPERATOR_LOG_DIRECTORY`, and is now set by `ROLLING_LOGS_DIR` (or via `--rolling-logs <DIRECTORY>`).
            let _tracing_guard =
                Tracing::pre_configured(built_info::PKG_NAME, telemetry_arguments).init()?;

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
            let authentication_class_store = superset_controller.store();
            let config_map_store = superset_controller.store();
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
                    client.get_api::<DeserializeGuard<core::v1alpha1::AuthenticationClass>>(&()),
                    watcher::Config::default(),
                    move |authentication_class| {
                        authentication_class_store
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
                        config_map_store
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
            let superset_cluster_store = druid_connection_controller.store();
            let job_store = druid_connection_controller.store();
            let config_map_store = druid_connection_controller.store();
            let druid_connection_controller = druid_connection_controller
                .shutdown_on_signal()
                .watches(
                    watch_namespace.get_api::<DeserializeGuard<v1alpha1::SupersetCluster>>(&client),
                    watcher::Config::default(),
                    move |superset_cluster| {
                        superset_cluster_store
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
                        job_store
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
                        config_map_store
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
    authentication_class: &DeserializeGuard<core::v1alpha1::AuthenticationClass>,
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

    match &superset.spec.cluster_config.authorization {
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
