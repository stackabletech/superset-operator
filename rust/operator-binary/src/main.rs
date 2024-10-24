use std::sync::Arc;

use clap::{crate_description, crate_version, Parser};
use futures::StreamExt;
use stackable_operator::{
    cli::{Command, ProductOperatorRun},
    commons::authentication::AuthenticationClass,
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        batch::v1::Job,
        core::v1::{ConfigMap, Service},
    },
    kube::{
        core::DeserializeGuard,
        runtime::{reflector::ObjectRef, watcher, Controller},
        ResourceExt,
    },
    logging::controller::report_controller_reconciled,
    CustomResourceExt,
};
use stackable_superset_crd::{druidconnection::DruidConnection, SupersetCluster, APP_NAME};

use crate::druid_connection_controller::DRUID_CONNECTION_CONTROLLER_NAME;
use crate::superset_controller::SUPERSET_CONTROLLER_NAME;

mod commands;
mod config;
mod controller_commons;
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
            SupersetCluster::print_yaml_schema(built_info::PKG_VERSION)?;
            DruidConnection::print_yaml_schema(built_info::PKG_VERSION)?;
        }
        Command::Run(ProductOperatorRun {
            product_config,
            watch_namespace,
            tracing_target,
            cluster_info_opts,
        }) => {
            stackable_operator::logging::initialize_logging(
                "SUPERSET_OPERATOR_LOG",
                APP_NAME,
                tracing_target,
            );
            stackable_operator::utils::print_startup_string(
                crate_description!(),
                crate_version!(),
                built_info::GIT_VERSION,
                built_info::TARGET,
                built_info::BUILT_TIME_UTC,
                built_info::RUSTC_VERSION,
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

            let superset_controller_builder = Controller::new(
                watch_namespace.get_api::<DeserializeGuard<SupersetCluster>>(&client),
                watcher::Config::default(),
            );
            let superset_store_1 = superset_controller_builder.store();
            let superset_controller = superset_controller_builder
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
                .run(
                    superset_controller::reconcile_superset,
                    superset_controller::error_policy,
                    Arc::new(superset_controller::Ctx {
                        client: client.clone(),
                        product_config,
                    }),
                )
                .map(|res| {
                    report_controller_reconciled(
                        &client,
                        &format!("{SUPERSET_CONTROLLER_NAME}.{OPERATOR_NAME}"),
                        &res,
                    )
                });

            let druid_connection_controller_builder = Controller::new(
                watch_namespace.get_api::<DeserializeGuard<DruidConnection>>(&client),
                watcher::Config::default(),
            );
            let druid_connection_store_1 = druid_connection_controller_builder.store();
            let druid_connection_store_2 = druid_connection_controller_builder.store();
            let druid_connection_store_3 = druid_connection_controller_builder.store();
            let druid_connection_controller = druid_connection_controller_builder
                .shutdown_on_signal()
                .watches(
                    watch_namespace.get_api::<DeserializeGuard<SupersetCluster>>(&client),
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
                .map(|res| {
                    report_controller_reconciled(
                        &client,
                        &format!("{DRUID_CONNECTION_CONTROLLER_NAME}.{OPERATOR_NAME}"),
                        &res,
                    )
                });

            futures::stream::select(superset_controller, druid_connection_controller)
                .collect::<()>()
                .await;
        }
    }

    Ok(())
}

fn references_authentication_class(
    superset: &DeserializeGuard<SupersetCluster>,
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

fn valid_druid_connection(
    superset_cluster: &DeserializeGuard<SupersetCluster>,
    druid_connection: &DeserializeGuard<DruidConnection>,
) -> bool {
    let Ok(druid_connection) = &druid_connection.0 else {
        return false;
    };
    druid_connection.superset_name() == superset_cluster.name_any()
        && druid_connection.superset_namespace().ok() == superset_cluster.namespace()
}

fn valid_druid_connection_namespace(
    druid_connection: &DeserializeGuard<DruidConnection>,
    config_map: &DeserializeGuard<ConfigMap>,
) -> bool {
    let Ok(druid_connection) = &druid_connection.0 else {
        return false;
    };
    let Ok(config_map) = &config_map.0 else {
        return false;
    };
    druid_connection.druid_namespace().ok() == config_map.metadata.namespace
        && Some(druid_connection.druid_name()) == config_map.metadata.name
}

fn valid_druid_job(
    druid_connection: &DeserializeGuard<DruidConnection>,
    job: &DeserializeGuard<Job>,
) -> bool {
    let Ok(druid_connection) = &druid_connection.0 else {
        return false;
    };
    let Ok(job) = &job.0 else {
        return false;
    };

    druid_connection.metadata.namespace == job.metadata.namespace
        && Some(druid_connection.job_name()) == job.metadata.name
}
