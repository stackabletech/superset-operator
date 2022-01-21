mod add_druid_controller;
mod init_controller;
mod superset_controller;
mod util;

use futures::StreamExt;
use stackable_operator::{
    cli::Command,
    k8s_openapi::api::{apps::v1::StatefulSet, batch::v1::Job, core::v1::Service},
    kube::{
        api::{DynamicObject, ListParams},
        runtime::{
            controller::{Context, ReconcilerAction},
            reflector::ObjectRef,
            Controller,
        },
        CustomResourceExt, Resource,
    },
};
use stackable_superset_crd::{
    commands::{DruidConnection, SupersetDB},
    SupersetCluster,
};
use structopt::StructOpt;

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub const APP_NAME: &str = "superset";
pub const APP_PORT: u16 = 8088;

#[derive(StructOpt)]
#[structopt(about = built_info::PKG_DESCRIPTION, author = stackable_operator::cli::AUTHOR)]
struct Opts {
    #[structopt(subcommand)]
    cmd: Command,
}

/// Erases the concrete types of the controller result, so that we can merge the streams of multiple controllers for different resources.
///
/// In particular, we convert `ObjectRef<K>` into `ObjectRef<DynamicObject>` (which carries `K`'s metadata at runtime instead), and
/// `E` into the trait object `anyhow::Error`.
fn erase_controller_result_type<K: Resource, E: std::error::Error + Send + Sync + 'static>(
    res: Result<(ObjectRef<K>, ReconcilerAction), E>,
) -> anyhow::Result<(ObjectRef<DynamicObject>, ReconcilerAction)> {
    let (obj_ref, action) = res?;
    Ok((obj_ref.erase(), action))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    stackable_operator::logging::initialize_logging("SUPERSET_OPERATOR_LOG");

    let opts = Opts::from_args();
    match opts.cmd {
        Command::Crd => println!(
            "{}{}",
            serde_yaml::to_string(&SupersetCluster::crd())?,
            serde_yaml::to_string(&SupersetDB::crd())?
        ),
        Command::Run { product_config } => {
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
                "zookeeper.stackable.tech".to_string(),
            ))
            .await?;
            let superset_controller = Controller::new(
                client.get_all_api::<SupersetCluster>(),
                ListParams::default(),
            )
            .owns(client.get_all_api::<Service>(), ListParams::default())
            .owns(client.get_all_api::<StatefulSet>(), ListParams::default())
            .run(
                superset_controller::reconcile_superset,
                superset_controller::error_policy,
                Context::new(superset_controller::Ctx {
                    client: client.clone(),
                    product_config,
                }),
            );

            let superset_db_controller_builder =
                Controller::new(client.get_all_api::<SupersetDB>(), ListParams::default());
            let superset_db_store = superset_db_controller_builder.store();
            let superset_db_controller = superset_db_controller_builder
                // We gotta watch jobs so we can react to finished init jobs
                // and update our status accordingly
                .watches(
                    client.get_all_api::<Job>(),
                    ListParams::default(),
                    move |job| {
                        superset_db_store
                            .state()
                            .into_iter()
                            .filter(move |superset_db| {
                                superset_db.metadata.namespace.as_ref().unwrap() == job.metadata.namespace.as_ref().unwrap()
                                    && superset_db.metadata.name.as_ref().unwrap() == job.metadata.name.as_ref().unwrap()
                            })
                            .map(|superset_db| ObjectRef::from_obj(&superset_db))
                    },
                )
                .run(
                    init_controller::reconcile_superset_db,
                    init_controller::error_policy,
                    Context::new(init_controller::Ctx {
                        client: client.clone(),
                    }),
                );

            let druid_connection_controller =
                Controller::new(client.get_all_api::<DruidConnection>(), ListParams::default()).run(
                    add_druid_controller::reconcile_druid_connection,
                    add_druid_controller::error_policy,
                    Context::new(add_druid_controller::Ctx {
                        client: client.clone(),
                    }),
                );

            futures::stream::select(
                futures::stream::select(
                    superset_controller.map(erase_controller_result_type),
                    superset_db_controller.map(erase_controller_result_type),
                ),
                druid_connection_controller.map(erase_controller_result_type),
            )
            .for_each(|res| async {
                match res {
                    Ok((obj, _)) => tracing::info!(object = %obj, "Reconciled object"),
                    Err(err) => {
                        tracing::error!(
                            error = &*err as &dyn std::error::Error,
                            "Failed to reconcile object",
                        )
                    }
                }
            })
            .await;
        }
    }

    Ok(())
}
