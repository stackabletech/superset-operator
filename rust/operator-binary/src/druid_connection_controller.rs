use std::time::Duration;

use crate::util::{env_var_from_secret, get_job_state, JobState};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::client::Client;
use stackable_operator::{
    builder::{ContainerBuilder, ObjectMetaBuilder},
    k8s_openapi::api::{
        batch::v1::{Job, JobSpec},
        core::v1::{ConfigMap, PodSpec, PodTemplateSpec},
    },
    kube::runtime::{
        controller::{Context, ReconcilerAction},
        reflector::ObjectRef,
    },
};
use stackable_superset_crd::commands::{
    DruidConnectionStatus, DruidConnectionStatusCondition, SupersetDBStatusCondition,
};
use stackable_superset_crd::{
    commands::{DruidConnection, SupersetDB},
    SupersetCluster, SupersetClusterRef,
};

const FIELD_MANAGER_SCOPE: &str = "supersetcluster";

pub struct Ctx {
    pub client: stackable_operator::client::Client,
}

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
#[snafu(context(suffix(false)))]
pub enum Error {
    #[snafu(display("failed to retrieve superset version"))]
    NoSupersetVersion { source: crate::util::Error },
    #[snafu(display("object does not refer to SupersetCluster"))]
    InvalidSupersetReference,
    #[snafu(display("could not find {}", superset))]
    FindSuperset {
        source: stackable_operator::error::Error,
        superset: ObjectRef<SupersetCluster>,
    },
    #[snafu(display("failed to find superset with name {:?} in namespace {:?}", cluster_ref.name, cluster_ref.namespace))]
    SupersetClusterNotFound {
        source: crate::util::Error,
        cluster_ref: SupersetClusterRef,
    },
    #[snafu(display("failed to apply Job for AddDruid"))] // TODO add more info here
    ApplyJob {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
    },
    #[snafu(display(
        "Failed to get Druid connection string from config map {} in namespace {:?}",
        cm_name,
        namespace
    ))]
    GetDruidConnStringConfigMap {
        source: stackable_operator::error::Error,
        cm_name: String,
        namespace: Option<String>,
    },
    #[snafu(display(
        "Failed to get Druid connection string from config map {} in namespace {:?}",
        cm_name,
        namespace
    ))]
    MissingDruidConnString {
        cm_name: String,
        namespace: Option<String>,
    },
    #[snafu(display(
        "druid connection state is 'importing' but failed to find job {}/{}",
        namespace,
        name
    ))]
    GetImportJob {
        source: stackable_operator::error::Error,
        namespace: String,
        name: String,
    },
    #[snafu(display("Failed to check if druid discovery map exists"))]
    DruidDiscoveryCheck {
        source: stackable_operator::error::Error,
    },
    SupersetDBExistsCheck {
        source: stackable_operator::error::Error,
    },
    SupersetDBRetrieval {
        source: stackable_operator::error::Error,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn reconcile_druid_connection(
    druid_connection: DruidConnection,
    ctx: Context<Ctx>,
) -> Result<ReconcilerAction> {
    tracing::info!("Starting reconciling DruidConnections");

    let client = &ctx.get_ref().client;

    if let Some(ref s) = druid_connection.status {
        match s.condition {
            DruidConnectionStatusCondition::Provisioned => {
                // Is the superset DB object there, and is its status "Ready"?
                let superset_db_ready = if client
                    .exists::<SupersetDB>(
                        &druid_connection.spec.superset_db_name,
                        Some(&druid_connection.spec.superset_db_namespace),
                    )
                    .await
                    .context(SupersetDBExistsCheck)?
                {
                    let superset_db_status = client
                        .get::<SupersetDB>(
                            &druid_connection.spec.superset_db_name,
                            Some(&druid_connection.spec.superset_db_namespace),
                        )
                        .await
                        .context(SupersetDBRetrieval)?
                        .status;
                    if let Some(s) = superset_db_status {
                        s.condition == SupersetDBStatusCondition::Ready
                    } else {
                        false
                    }
                } else {
                    false
                };
                // Is the referenced druid discovery configmap there?
                let druid_discovery_cm_exists = client
                    .exists::<ConfigMap>(
                        &druid_connection.spec.druid_cluster_name,
                        Some(&druid_connection.spec.druid_cluster_namespace),
                    )
                    .await
                    .context(DruidDiscoveryCheck)?;

                if superset_db_ready && druid_discovery_cm_exists {
                    let superset_db = client
                        .get::<SupersetDB>(
                            &druid_connection.spec.superset_db_name,
                            Some(&druid_connection.spec.superset_db_namespace),
                        )
                        .await
                        .context(SupersetDBRetrieval)?;
                    // Everything is there, retrieve all necessary info and start the job
                    let sqlalchemy_str = get_sqlalchemy_uri_for_druid_cluster(
                        &druid_connection.spec.druid_cluster_name,
                        &druid_connection.spec.druid_cluster_namespace,
                        client,
                    )
                    .await?;
                    let job =
                        build_import_job(&druid_connection, &superset_db, &sqlalchemy_str).await?;
                    client
                        .apply_patch(FIELD_MANAGER_SCOPE, &job, &job)
                        .await
                        .context(ApplyJob)?;
                    // The job is started, update status to reflect new state
                    client
                        .apply_patch_status(FIELD_MANAGER_SCOPE, &druid_connection, &s.importing())
                        .await
                        .context(ApplyStatus)?;
                }
            }
            DruidConnectionStatusCondition::Importing => {
                // In here, check the associated job that is running.
                // If it is still running, do nothing. If it completed, set status to ready, if it failed, set status to failed.
                // TODO we need to fetch the job here
                // we need namespace/name.
                let ns = druid_connection.metadata.namespace.clone().unwrap();
                let job_name = druid_connection.job_name();
                let job = client
                    .get::<Job>(&job_name, Some(&ns))
                    .await
                    .context(GetImportJob {
                        namespace: ns,
                        name: job_name,
                    })?;

                let new_status = match get_job_state(&job) {
                    JobState::Failed => Some(s.failed()),
                    JobState::Complete => Some(s.ready()),
                    JobState::InProgress => None,
                };

                if let Some(ns) = new_status {
                    client
                        .apply_patch_status(FIELD_MANAGER_SCOPE, &druid_connection, &ns)
                        .await
                        .context(ApplyStatus)?;
                }
            }
            DruidConnectionStatusCondition::Ready => (),
            DruidConnectionStatusCondition::Failed => (),
        }
    } else {
        // Status not set yet, initialize
        client
            .apply_patch_status(
                FIELD_MANAGER_SCOPE,
                &druid_connection,
                &DruidConnectionStatus::new(),
            )
            .await
            .context(ApplyStatus)?;
    }

    Ok(ReconcilerAction {
        requeue_after: None,
    })
}

/// Takes a druid cluster name and namespace and returns the SQLAlchemy connect string
async fn get_sqlalchemy_uri_for_druid_cluster(
    cluster_name: &str,
    namespace: &str,
    client: &Client,
) -> Result<String> {
    client
        .get::<ConfigMap>(cluster_name, Some(namespace))
        .await
        .context(GetDruidConnStringConfigMap {
            cm_name: cluster_name.to_string(),
            namespace: namespace.to_string(),
        })?
        .data
        .and_then(|mut data| data.remove("DRUID_SQLALCHEMY"))
        .context(MissingDruidConnString {
            cm_name: cluster_name.to_string(),
            namespace: namespace.to_string(),
        })
}

/// Returns a yaml document read to be imported with "superset import-datasources"
fn build_druid_db_yaml(druid_cluster_name: &str, sqlalchemy_str: &str) -> Result<String> {
    Ok(format!(
        "databases:\n- database_name: {}\n  sqlalchemy_uri: {}\n  tables: []\n",
        druid_cluster_name, sqlalchemy_str
    ))
}

/// The rolegroup [`StatefulSet`] runs the rolegroup, as configured by the administrator.
///
/// The [`Pod`](`stackable_operator::k8s_openapi::api::core::v1::Pod`)s are accessible through the corresponding [`Service`] (from [`build_rolegroup_service`]).
async fn build_import_job(
    druid_connection: &DruidConnection,
    superset_db: &SupersetDB,
    sqlalchemy_str: &str,
) -> Result<Job> {
    let mut commands = vec![];
    let druid_info =
        build_druid_db_yaml(&druid_connection.spec.druid_cluster_name, sqlalchemy_str)?;
    commands.push(format!("echo \"{}\" > /tmp/druids.yaml", druid_info));
    commands.push(String::from(
        "superset import_datasources -p /tmp/druids.yaml",
    ));

    let secret = &superset_db.spec.credentials_secret;

    let container = ContainerBuilder::new("superset-import-druid-connection")
        .image(format!(
            "docker.stackable.tech/stackable/superset:{}-stackable0",
            superset_db.spec.superset_version
        ))
        .command(vec!["/bin/sh".to_string()])
        .args(vec![String::from("-c"), commands.join("; ")])
        .add_env_vars(vec![
            env_var_from_secret("SECRET_KEY", secret, "connections.secretKey"),
            env_var_from_secret(
                "SQLALCHEMY_DATABASE_URI",
                secret,
                "connections.sqlalchemyDatabaseUri",
            ),
        ])
        .build();

    let pod = PodTemplateSpec {
        metadata: Some(
            ObjectMetaBuilder::new()
                .name(druid_connection.job_name())
                .build(),
        ),
        spec: Some(PodSpec {
            containers: vec![container],
            restart_policy: Some("Never".to_string()),
            ..Default::default()
        }),
    };

    let job = Job {
        metadata: ObjectMetaBuilder::new()
            .name(druid_connection.job_name())
            .namespace_opt(druid_connection.metadata.namespace.clone())
            .ownerreference_from_resource(druid_connection, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRef)?
            .build(),
        spec: Some(JobSpec {
            template: pod,
            ..Default::default()
        }),
        status: None,
    };

    Ok(job)
}

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> ReconcilerAction {
    ReconcilerAction {
        requeue_after: Some(Duration::from_secs(5)),
    }
}
