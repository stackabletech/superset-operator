use crate::util::{get_job_state, JobState};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{ContainerBuilder, ObjectMetaBuilder},
    client::Client,
    k8s_openapi::api::{
        batch::v1::{Job, JobSpec},
        core::v1::{ConfigMap, PodSpec, PodTemplateSpec},
    },
    kube::{
        core::DynamicObject,
        runtime::{
            controller::{Action, Context},
            reflector::ObjectRef,
        },
        ResourceExt,
    },
    logging::controller::ReconcilerError,
};
use stackable_superset_crd::{
    druidconnection::{DruidConnection, DruidConnectionStatus, DruidConnectionStatusCondition},
    supersetdb::{SupersetDB, SupersetDBStatusCondition},
    PYTHONPATH, SUPERSET_CONFIG_FILENAME,
};
use std::{sync::Arc, time::Duration};
use strum::{EnumDiscriminants, IntoStaticStr};

const FIELD_MANAGER_SCOPE: &str = "supersetcluster";

pub struct Ctx {
    pub client: stackable_operator::client::Client,
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to apply Job for Druid Connection"))]
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
    #[snafu(display("failed to get Druid connection string from config map {config_map}"))]
    GetDruidConnStringConfigMap {
        source: stackable_operator::error::Error,
        config_map: ObjectRef<ConfigMap>,
    },
    #[snafu(display("failed to get Druid connection string from config map"))]
    MissingDruidConnString,
    #[snafu(display("druid connection state is 'importing' but failed to find job {import_job}"))]
    GetImportJob {
        source: stackable_operator::error::Error,
        import_job: ObjectRef<Job>,
    },
    #[snafu(display("failed to check if druid discovery map exists"))]
    DruidDiscoveryCheck {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to retrieve superset db"))]
    SupersetDBRetrieval {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("namespace missing on DruidConnection {druid_connection}"))]
    DruidConnectionNoNamespace {
        source: stackable_superset_crd::druidconnection::Error,
        druid_connection: ObjectRef<DruidConnection>,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }

    fn secondary_object(&self) -> Option<ObjectRef<DynamicObject>> {
        match self {
            Error::ApplyJob { .. } => None,
            Error::ApplyStatus { .. } => None,
            Error::ObjectMissingMetadataForOwnerRef { .. } => None,
            Error::GetDruidConnStringConfigMap { config_map, .. } => {
                Some(config_map.clone().erase())
            }
            Error::MissingDruidConnString => None,
            Error::GetImportJob { import_job, .. } => Some(import_job.clone().erase()),
            Error::DruidDiscoveryCheck { .. } => None,
            Error::SupersetDBRetrieval { .. } => None,
            Error::DruidConnectionNoNamespace { druid_connection, .. } => {
                Some(druid_connection.clone().erase())
            },
        }
    }
}

pub async fn reconcile_druid_connection(
    druid_connection: Arc<DruidConnection>,
    ctx: Context<Ctx>,
) -> Result<Action> {
    tracing::info!("Starting reconciling DruidConnections");

    let client = &ctx.get_ref().client;

    if let Some(ref s) = druid_connection.status {
        match s.condition {
            DruidConnectionStatusCondition::Pending => {
                // Is the superset DB object there, and is its status "Ready"?
                let mut superset_db_ready = false;
                if let Some(status) = client
                    .get::<SupersetDB>(
                        &druid_connection.superset_name(),
                        Some(
                            &druid_connection
                                .superset_namespace()
                                .context(DruidConnectionNoNamespaceSnafu {druid_connection: ObjectRef::from_obj(&*druid_connection)})?,
                        ),
                    )
                    .await
                    .context(SupersetDBRetrievalSnafu)?
                    .status
                {
                    superset_db_ready = status.condition == SupersetDBStatusCondition::Ready;
                }
                // Is the referenced druid discovery configmap there?
                let druid_discovery_cm_exists = client
                    .exists::<ConfigMap>(
                        &druid_connection.druid_name(),
                        Some(
                            &druid_connection
                                .druid_namespace()
                                .context(DruidConnectionNoNamespaceSnafu {druid_connection: ObjectRef::from_obj(&*druid_connection)})?,
                        ),
                    )
                    .await
                    .context(DruidDiscoveryCheckSnafu)?;

                if superset_db_ready && druid_discovery_cm_exists {
                    let superset_db = client
                        .get::<SupersetDB>(
                            &druid_connection.superset_name(),
                            Some(
                                &druid_connection
                                    .superset_namespace()
                                    .context(DruidConnectionNoNamespaceSnafu {druid_connection: ObjectRef::from_obj(&*druid_connection)})?,
                            ),
                        )
                        .await
                        .context(SupersetDBRetrievalSnafu)?;
                    // Everything is there, retrieve all necessary info and start the job
                    let sqlalchemy_str = get_sqlalchemy_uri_for_druid_cluster(
                        &druid_connection.druid_name(),
                        Some(
                            &druid_connection
                                .druid_namespace()
                                .context(DruidConnectionNoNamespaceSnafu {druid_connection: ObjectRef::from_obj(&*druid_connection)})?,
                        ),
                        client,
                    )
                    .await?;
                    let job =
                        build_import_job(&druid_connection, &superset_db, &sqlalchemy_str).await?;
                    client
                        .apply_patch(FIELD_MANAGER_SCOPE, &job, &job)
                        .await
                        .context(ApplyJobSnafu)?;
                    // The job is started, update status to reflect new state
                    client
                        .apply_patch_status(FIELD_MANAGER_SCOPE, &*druid_connection, &s.importing())
                        .await
                        .context(ApplyStatusSnafu)?;
                }
            }
            DruidConnectionStatusCondition::Importing => {
                let ns = druid_connection
                    .namespace()
                    .unwrap_or_else(|| "default".to_string());
                let job_name = druid_connection.job_name();
                let job =
                    client
                        .get::<Job>(&job_name, Some(&ns))
                        .await
                        .context(GetImportJobSnafu {
                            import_job: ObjectRef::<Job>::new(&job_name).within(&ns),
                        })?;

                let new_status = match get_job_state(&job) {
                    JobState::Failed => Some(s.failed()),
                    JobState::Complete => Some(s.ready()),
                    JobState::InProgress => None,
                };

                if let Some(ns) = new_status {
                    client
                        .apply_patch_status(FIELD_MANAGER_SCOPE, &*druid_connection, &ns)
                        .await
                        .context(ApplyStatusSnafu)?;
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
                &*druid_connection,
                &DruidConnectionStatus::new(),
            )
            .await
            .context(ApplyStatusSnafu)?;
    }

    Ok(Action::await_change())
}

/// Takes a druid cluster name and namespace and returns the SQLAlchemy connect string
async fn get_sqlalchemy_uri_for_druid_cluster(
    cluster_name: &str,
    namespace: Option<&str>,
    client: &Client,
) -> Result<String> {
    client
        .get::<ConfigMap>(cluster_name, namespace)
        .await
        .context(GetDruidConnStringConfigMapSnafu {
            config_map: if let Some(ns) = namespace {
                ObjectRef::<ConfigMap>::new(cluster_name).within(ns)
            } else {
                ObjectRef::<ConfigMap>::new(cluster_name)
            },
        })?
        .data
        .and_then(|mut data| data.remove("DRUID_SQLALCHEMY"))
        .context(MissingDruidConnStringSnafu)
}

/// Returns a yaml document read to be imported with "superset import-datasources"
fn build_druid_db_yaml(druid_cluster_name: &str, sqlalchemy_str: &str) -> Result<String> {
    Ok(format!(
        "databases:\n- database_name: {}\n  sqlalchemy_uri: {}\n  tables: []\n",
        druid_cluster_name, sqlalchemy_str
    ))
}

/// Builds the import job.  When run it will import the druid connection into the database.
async fn build_import_job(
    druid_connection: &DruidConnection,
    superset_db: &SupersetDB,
    sqlalchemy_str: &str,
) -> Result<Job> {
    let mut commands = vec![];

    let config = "import os; SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URI')";
    commands.push(format!("mkdir -p {PYTHONPATH}"));
    commands.push(format!(
        "echo \"{config}\" > {PYTHONPATH}/{SUPERSET_CONFIG_FILENAME}"
    ));

    let druid_info = build_druid_db_yaml(&druid_connection.spec.druid.name, sqlalchemy_str)?;
    commands.push(format!("echo \"{}\" > /tmp/druids.yaml", druid_info));
    commands.push(String::from(
        "superset import_datasources -p /tmp/druids.yaml",
    ));

    let secret = &superset_db.spec.credentials_secret;

    let container = ContainerBuilder::new("superset-import-druid-connection")
        .image(format!(
            "docker.stackable.tech/stackable/superset:{}-stackable2",
            superset_db.spec.superset_version
        ))
        .command(vec!["/bin/sh".to_string()])
        .args(vec![String::from("-c"), commands.join("; ")])
        .add_env_var_from_secret("DATABASE_URI", secret, "connections.sqlalchemyDatabaseUri")
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
            .namespace_opt(druid_connection.namespace())
            .ownerreference_from_resource(druid_connection, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .build(),
        spec: Some(JobSpec {
            template: pod,
            ..Default::default()
        }),
        status: None,
    };

    Ok(job)
}

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(5))
}
