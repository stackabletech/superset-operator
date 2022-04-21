mod config;
mod druid_connection_controller;
mod superset_controller;
mod superset_db_controller;
mod util;

use clap::Parser;
use futures::StreamExt;
use stackable_operator::{
    cli::{Command, ProductOperatorRun},
    commons::authentication::AuthenticationClass,
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        batch::v1::Job,
        core::v1::{Secret, Service},
    },
    kube::{
        api::ListParams,
        runtime::{controller::Context, reflector::ObjectRef, Controller},
        CustomResourceExt,
    },
    logging::controller::report_controller_reconciled,
};
use stackable_superset_crd::{
    druidconnection::DruidConnection, supersetdb::SupersetDB, SupersetCluster,
    SupersetClusterAuthenticationConfig,
};
use std::sync::Arc;

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub const APP_NAME: &str = "superset";
pub const APP_PORT: u16 = 8088;

#[derive(Parser)]
#[clap(about = built_info::PKG_DESCRIPTION, author = stackable_operator::cli::AUTHOR)]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        Command::Crd => println!(
            "{}{}{}",
            serde_yaml::to_string(&SupersetCluster::crd())?,
            serde_yaml::to_string(&SupersetDB::crd())?,
            serde_yaml::to_string(&DruidConnection::crd())?
        ),
        Command::Run(ProductOperatorRun {
            product_config,
            watch_namespace,
            tracing_target,
        }) => {
            stackable_operator::utils::print_startup_string(
                built_info::PKG_DESCRIPTION,
                built_info::PKG_VERSION,
                built_info::GIT_VERSION,
                built_info::TARGET,
                built_info::BUILT_TIME_UTC,
                built_info::RUSTC_VERSION,
            );
            stackable_operator::logging::initialize_logging(
                "SUPERSET_OPERATOR_LOG",
                APP_NAME,
                tracing_target,
            );

            let product_config = product_config.load(&[
                "deploy/config-spec/properties.yaml",
                "/etc/stackable/superset-operator/config-spec/properties.yaml",
            ])?;

            let client = stackable_operator::client::create_client(Some(
                "superset.stackable.tech".to_string(),
            ))
            .await?;

            let superset_controller_builder = Controller::new(
                watch_namespace.get_api::<SupersetCluster>(&client),
                ListParams::default(),
            );
            let superset_store = superset_controller_builder.store();
            let superset_controller = superset_controller_builder
                .owns(
                    watch_namespace.get_api::<Service>(&client),
                    ListParams::default(),
                )
                .owns(
                    watch_namespace.get_api::<StatefulSet>(&client),
                    ListParams::default(),
                )
                .shutdown_on_signal()
                .watches(
                    watch_namespace.get_api::<AuthenticationClass>(&client),
                    ListParams::default(),
                    move |authentication_class| {
                        superset_store
                            .state()
                            .into_iter()
                            .filter(move |superset: &Arc<SupersetCluster>| {
                                references_authentication_class(
                                    &superset.spec.authentication_config,
                                    &authentication_class,
                                )
                            })
                            .map(|superset| ObjectRef::from_obj(&*superset))
                    },
                )
                .run(
                    superset_controller::reconcile_superset,
                    superset_controller::error_policy,
                    Context::new(superset_controller::Ctx {
                        client: client.clone(),
                        product_config,
                    }),
                )
                .map(|res| {
                    report_controller_reconciled(
                        &client,
                        "supersetclusters.superset.stackable.tech",
                        &res,
                    )
                });

            let superset_db_controller_builder = Controller::new(
                watch_namespace.get_api::<SupersetDB>(&client),
                ListParams::default(),
            );
            let superset_db_store1 = superset_db_controller_builder.store();
            let superset_db_store2 = superset_db_controller_builder.store();
            let superset_db_controller = superset_db_controller_builder
                .shutdown_on_signal()
                .watches(
                    watch_namespace.get_api::<Secret>(&client),
                    ListParams::default(),
                    move |secret| {
                        superset_db_store1
                            .state()
                            .into_iter()
                            .filter(move |superset_db| {
                                if let Some(n) = &secret.metadata.name {
                                    &superset_db.spec.credentials_secret == n
                                } else {
                                    false
                                }
                            })
                            .map(|superset_db| ObjectRef::from_obj(&*superset_db))
                    },
                )
                // We have to watch jobs so we can react to finished init jobs
                // and update our status accordingly
                .watches(
                    watch_namespace.get_api::<Job>(&client),
                    ListParams::default(),
                    move |job| {
                        superset_db_store2
                            .state()
                            .into_iter()
                            .filter(move |superset_db| {
                                superset_db.metadata.namespace.as_ref().unwrap()
                                    == job.metadata.namespace.as_ref().unwrap()
                                    && &superset_db.job_name()
                                        == job.metadata.name.as_ref().unwrap()
                            })
                            .map(|superset_db| ObjectRef::from_obj(&*superset_db))
                    },
                )
                .run(
                    superset_db_controller::reconcile_superset_db,
                    superset_db_controller::error_policy,
                    Context::new(superset_db_controller::Ctx {
                        client: client.clone(),
                    }),
                )
                .map(|res| {
                    report_controller_reconciled(
                        &client,
                        "supersetdbclusters.superset.stackable.tech",
                        &res,
                    )
                });

            let druid_connection_controller_builder = Controller::new(
                watch_namespace.get_api::<DruidConnection>(&client),
                ListParams::default(),
            );
            let druid_connection_store1 = druid_connection_controller_builder.store();
            let druid_connection_store2 = druid_connection_controller_builder.store();
            let druid_connection_controller = druid_connection_controller_builder
                .shutdown_on_signal()
                .watches(
                    watch_namespace.get_api::<SupersetDB>(&client),
                    ListParams::default(),
                    move |sdb| {
                        druid_connection_store1
                            .state()
                            .into_iter()
                            .filter(move |druid_connection| {
                                &druid_connection.spec.superset.namespace
                                    == sdb.metadata.namespace.as_ref().unwrap()
                                    && &druid_connection.spec.superset.name
                                        == sdb.metadata.name.as_ref().unwrap()
                            })
                            .map(|druid_connection| ObjectRef::from_obj(&*druid_connection))
                    },
                )
                .watches(
                    watch_namespace.get_api::<Job>(&client),
                    ListParams::default(),
                    move |job| {
                        druid_connection_store2
                            .state()
                            .into_iter()
                            .filter(move |druid_connection| {
                                druid_connection.metadata.namespace.as_ref().unwrap()
                                    == job.metadata.namespace.as_ref().unwrap()
                                    && &druid_connection.job_name()
                                        == job.metadata.name.as_ref().unwrap()
                            })
                            .map(|druid_connection| ObjectRef::from_obj(&*druid_connection))
                    },
                )
                .run(
                    druid_connection_controller::reconcile_druid_connection,
                    druid_connection_controller::error_policy,
                    Context::new(druid_connection_controller::Ctx {
                        client: client.clone(),
                    }),
                )
                .map(|res| {
                    report_controller_reconciled(
                        &client,
                        "druidconnection.superset.stackable.tech",
                        &res,
                    )
                });

            futures::stream::select(
                futures::stream::select(superset_controller, superset_db_controller),
                druid_connection_controller,
            )
            .collect::<()>()
            .await;
        }
    }

    Ok(())
}

fn references_authentication_class(
    authentication_config: &Option<SupersetClusterAuthenticationConfig>,
    authentication_class: &AuthenticationClass,
) -> bool {
    match authentication_config {
        Some(authentication_config) => {
            authentication_config
                .methods
                .iter()
                .any(|authentication_method| {
                    &authentication_method.authentication_class
                        == authentication_class.metadata.name.as_ref().unwrap()
                })
        }
        None => false,
    }
}
