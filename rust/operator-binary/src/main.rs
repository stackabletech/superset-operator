mod config;
mod druid_connection_controller;
mod superset_controller;
mod superset_db_controller;
mod util;

use std::sync::Arc;

use clap::Parser;
use futures::StreamExt;
use stackable_operator::{
    cli::{Command, ProductOperatorRun},
    commons::authentication::AuthenticationClass,
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        batch::v1::Job,
        core::v1::{ConfigMap, Secret, Service},
    },
    kube::{
        api::ListParams,
        runtime::{reflector::ObjectRef, Controller},
        CustomResourceExt, ResourceExt,
    },
    logging::controller::report_controller_reconciled,
};
use stackable_superset_crd::{
    druidconnection::DruidConnection, supersetdb::SupersetDB, SupersetCluster,
    SupersetClusterAuthenticationConfig,
};

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
            stackable_operator::logging::initialize_logging(
                "SUPERSET_OPERATOR_LOG",
                APP_NAME,
                tracing_target,
            );
            stackable_operator::utils::print_startup_string(
                built_info::PKG_DESCRIPTION,
                built_info::PKG_VERSION,
                built_info::GIT_VERSION,
                built_info::TARGET,
                built_info::BUILT_TIME_UTC,
                built_info::RUSTC_VERSION,
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
            let superset_store_1 = superset_controller_builder.store();
            let superset_store_2 = superset_controller_builder.store();
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
                        superset_store_1
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
                .watches(
                    watch_namespace.get_api::<SupersetDB>(&client),
                    ListParams::default(),
                    move |superset_db| {
                        superset_store_2
                            .state()
                            .into_iter()
                            .filter(move |superset| {
                                superset_db.name() == superset.name()
                                    && superset_db.namespace() == superset.namespace()
                            })
                            .map(|druid_connection| ObjectRef::from_obj(&*druid_connection))
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
                                job.name() == superset_db.name()
                                    && job.namespace() == superset_db.namespace()
                            })
                            .map(|superset_db| ObjectRef::from_obj(&*superset_db))
                    },
                )
                .run(
                    superset_db_controller::reconcile_superset_db,
                    superset_db_controller::error_policy,
                    Arc::new(superset_db_controller::Ctx {
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
            let druid_connection_store_1 = druid_connection_controller_builder.store();
            let druid_connection_store_2 = druid_connection_controller_builder.store();
            let druid_connection_store_3 = druid_connection_controller_builder.store();
            let druid_connection_controller = druid_connection_controller_builder
                .shutdown_on_signal()
                .watches(
                    watch_namespace.get_api::<SupersetDB>(&client),
                    ListParams::default(),
                    move |superset_db| {
                        druid_connection_store_1
                            .state()
                            .into_iter()
                            .filter(move |druid_connection| {
                                druid_connection.superset_name() == superset_db.name()
                                    && druid_connection.superset_namespace().ok()
                                        == superset_db.namespace()
                            })
                            .map(|druid_connection| ObjectRef::from_obj(&*druid_connection))
                    },
                )
                .watches(
                    watch_namespace.get_api::<Job>(&client),
                    ListParams::default(),
                    move |job| {
                        druid_connection_store_2
                            .state()
                            .into_iter()
                            .filter(move |druid_connection| {
                                druid_connection.metadata.namespace == job.metadata.namespace
                                    && Some(druid_connection.job_name()) == job.metadata.name
                            })
                            .map(|druid_connection| ObjectRef::from_obj(&*druid_connection))
                    },
                )
                .watches(
                    watch_namespace.get_api::<ConfigMap>(&client),
                    ListParams::default(),
                    move |config_map| {
                        druid_connection_store_3
                            .state()
                            .into_iter()
                            .filter(move |druid_connection| {
                                druid_connection.druid_namespace().ok()
                                    == config_map.metadata.namespace
                                    && Some(druid_connection.druid_name())
                                        == config_map.metadata.name
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
    assert!(authentication_class.metadata.name.is_some());

    authentication_config
        .as_ref()
        .and_then(|c| c.authentication_class.as_ref())
        == authentication_class.metadata.name.as_ref()
}
