use std::sync::Arc;

use const_format::concatcp;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{container::ContainerBuilder, security::PodSecurityContextBuilder},
    },
    client::Client,
    commons::product_image_selection::ResolvedProductImage,
    k8s_openapi::api::{
        batch::v1::{Job, JobSpec},
        core::v1::{ConfigMap, PodSpec, PodTemplateSpec},
    },
    kube::{
        core::{error_boundary, DeserializeGuard, DynamicObject},
        runtime::{controller::Action, reflector::ObjectRef},
        ResourceExt,
    },
    logging::controller::ReconcilerError,
    status::condition::{ClusterConditionStatus, ClusterConditionType},
    time::Duration,
};
use stackable_superset_crd::{
    druidconnection::{DruidConnection, DruidConnectionStatus, DruidConnectionStatusCondition},
    SupersetCluster, PYTHONPATH, SUPERSET_CONFIG_FILENAME,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    rbac,
    superset_controller::DOCKER_IMAGE_BASE_NAME,
    util::{get_job_state, JobState},
    APP_NAME, OPERATOR_NAME,
};

pub const DRUID_CONNECTION_CONTROLLER_NAME: &str = "druid-connection";
pub const DRUID_CONNECTION_FULL_CONTROLLER_NAME: &str =
    concatcp!(DRUID_CONNECTION_CONTROLLER_NAME, '.', OPERATOR_NAME);

pub struct Ctx {
    pub client: Client,
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to apply Job for Druid Connection"))]
    ApplyJob {
        source: stackable_operator::client::Error,
    },
    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::client::Error,
    },
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },
    #[snafu(display("failed to get Druid connection string from config map {config_map}"))]
    GetDruidConnStringConfigMap {
        source: stackable_operator::client::Error,
        config_map: ObjectRef<ConfigMap>,
    },
    #[snafu(display("failed to get Druid connection string from config map"))]
    MissingDruidConnString,
    #[snafu(display("druid connection state is 'importing' but failed to find job {import_job}"))]
    GetImportJob {
        source: stackable_operator::client::Error,
        import_job: ObjectRef<Job>,
    },
    #[snafu(display("failed to check if druid discovery map exists"))]
    DruidDiscoveryCheck {
        source: stackable_operator::client::Error,
    },
    #[snafu(display("namespace missing on DruidConnection {druid_connection}"))]
    DruidConnectionNoNamespace {
        source: stackable_superset_crd::druidconnection::Error,
        druid_connection: ObjectRef<DruidConnection>,
    },
    #[snafu(display("failed to patch service account"))]
    ApplyServiceAccount {
        source: stackable_operator::client::Error,
    },
    #[snafu(display("failed to patch role binding"))]
    ApplyRoleBinding {
        source: stackable_operator::client::Error,
    },
    #[snafu(display("failed to retrieve superset cluster"))]
    SupersetClusterRetrieval {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("DruidConnection object is invalid"))]
    InvalidDruidConnection {
        source: error_boundary::InvalidObject,
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
            Error::DruidConnectionNoNamespace {
                druid_connection, ..
            } => Some(druid_connection.clone().erase()),
            Error::ApplyServiceAccount { .. } => None,
            Error::ApplyRoleBinding { .. } => None,
            Error::SupersetClusterRetrieval { .. } => None,
            Error::InvalidDruidConnection { .. } => None,
        }
    }
}

pub async fn reconcile_druid_connection(
    druid_connection: Arc<DeserializeGuard<DruidConnection>>,
    ctx: Arc<Ctx>,
) -> Result<Action> {
    tracing::info!("Starting reconciling DruidConnections");

    let druid_connection = druid_connection
        .0
        .as_ref()
        .map_err(error_boundary::InvalidObject::clone)
        .context(InvalidDruidConnectionSnafu)?;
    let client = &ctx.client;

    let (rbac_sa, rbac_rolebinding) = rbac::build_rbac_resources(druid_connection, APP_NAME);
    client
        .apply_patch(DRUID_CONNECTION_CONTROLLER_NAME, &rbac_sa, &rbac_sa)
        .await
        .context(ApplyServiceAccountSnafu)?;
    client
        .apply_patch(
            DRUID_CONNECTION_CONTROLLER_NAME,
            &rbac_rolebinding,
            &rbac_rolebinding,
        )
        .await
        .context(ApplyRoleBindingSnafu)?;

    if let Some(ref s) = druid_connection.status {
        match s.condition {
            DruidConnectionStatusCondition::Pending => {
                // Is the referenced druid discovery configmap there?
                let druid_discovery_cm_exists = client
                    .get_opt::<ConfigMap>(
                        &druid_connection.druid_name(),
                        &druid_connection.druid_namespace().context(
                            DruidConnectionNoNamespaceSnafu {
                                druid_connection: ObjectRef::from_obj(druid_connection),
                            },
                        )?,
                    )
                    .await
                    .context(DruidDiscoveryCheckSnafu)?
                    .is_some();

                let superset_cluster = client
                    .get::<SupersetCluster>(
                        &druid_connection.superset_name(),
                        &druid_connection.superset_namespace().context(
                            DruidConnectionNoNamespaceSnafu {
                                druid_connection: ObjectRef::from_obj(druid_connection),
                            },
                        )?,
                    )
                    .await
                    .context(SupersetClusterRetrievalSnafu)?;

                let superset_cluster_is_ready = superset_cluster
                    .status
                    .as_ref()
                    .and_then(|s| {
                        s.conditions.iter().find(|c| {
                            c.type_ == ClusterConditionType::Available
                                && c.status == ClusterConditionStatus::True
                        })
                    })
                    .is_some();

                if druid_discovery_cm_exists && superset_cluster_is_ready {
                    // Everything is there, retrieve all necessary info and start the job
                    let sqlalchemy_str = get_sqlalchemy_uri_for_druid_cluster(
                        &druid_connection.druid_name(),
                        &druid_connection.druid_namespace().context(
                            DruidConnectionNoNamespaceSnafu {
                                druid_connection: ObjectRef::from_obj(druid_connection),
                            },
                        )?,
                        client,
                    )
                    .await?;
                    let resolved_product_image: ResolvedProductImage = superset_cluster
                        .spec
                        .image
                        .resolve(DOCKER_IMAGE_BASE_NAME, crate::built_info::PKG_VERSION);
                    let job = build_import_job(
                        &superset_cluster,
                        druid_connection,
                        &resolved_product_image,
                        &sqlalchemy_str,
                        &rbac_sa.name_any(),
                    )
                    .await?;
                    client
                        .apply_patch(DRUID_CONNECTION_CONTROLLER_NAME, &job, &job)
                        .await
                        .context(ApplyJobSnafu)?;
                    // The job is started, update status to reflect new state
                    client
                        .apply_patch_status(
                            DRUID_CONNECTION_CONTROLLER_NAME,
                            druid_connection,
                            &s.importing(),
                        )
                        .await
                        .context(ApplyStatusSnafu)?;
                }
            }
            DruidConnectionStatusCondition::Importing => {
                let ns = druid_connection
                    .namespace()
                    .unwrap_or_else(|| "default".to_string());
                let job_name = druid_connection.job_name();
                let job = client
                    .get::<Job>(&job_name, &ns)
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
                        .apply_patch_status(DRUID_CONNECTION_CONTROLLER_NAME, druid_connection, &ns)
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
                DRUID_CONNECTION_CONTROLLER_NAME,
                druid_connection,
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
    namespace: &str,
    client: &Client,
) -> Result<String> {
    client
        .get::<ConfigMap>(cluster_name, namespace)
        .await
        .context(GetDruidConnStringConfigMapSnafu {
            config_map: ObjectRef::<ConfigMap>::new(cluster_name).within(namespace),
        })?
        .data
        .and_then(|mut data| data.remove("DRUID_SQLALCHEMY"))
        .context(MissingDruidConnStringSnafu)
}

/// Returns a yaml document read to be imported with "superset import-datasources"
fn build_druid_db_yaml(druid_cluster_name: &str, sqlalchemy_str: &str) -> Result<String> {
    Ok(format!(
        "databases:\n- database_name: {druid_cluster_name}\n  sqlalchemy_uri: {sqlalchemy_str}\n  tables: []\n"
    ))
}

/// Builds the import job.  When run it will import the druid connection into the database.
async fn build_import_job(
    superset_cluster: &SupersetCluster,
    druid_connection: &DruidConnection,
    resolved_product_image: &ResolvedProductImage,
    sqlalchemy_str: &str,
    sa_name: &str,
) -> Result<Job> {
    let mut commands = vec![];

    let config = "import os; SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URI')";
    commands.push(format!("mkdir -p {PYTHONPATH}"));
    commands.push(format!(
        "echo \"{config}\" > {PYTHONPATH}/{SUPERSET_CONFIG_FILENAME}"
    ));

    let druid_info = build_druid_db_yaml(&druid_connection.spec.druid.name, sqlalchemy_str)?;
    commands.push(format!("echo \"{druid_info}\" > /tmp/druids.yaml"));
    commands.push(String::from(
        "superset import_datasources -p /tmp/druids.yaml",
    ));

    let secret = &superset_cluster.spec.cluster_config.credentials_secret;

    let container = ContainerBuilder::new("superset-import-druid-connection")
        .expect("ContainerBuilder not created")
        .image_from_product_image(resolved_product_image)
        .command(vec!["/bin/sh".to_string()])
        .args(vec![String::from("-c"), commands.join("; ")])
        .add_env_var_from_secret("DATABASE_URI", secret, "connections.sqlalchemyDatabaseUri")
        // From 2.1.0 superset barfs if the SECRET_KEY is not set properly. This causes the import job to fail.
        // Setting the env var is enough to be picked up: https://superset.apache.org/docs/installation/configuring-superset/#configuration
        .add_env_var_from_secret("SUPERSET_SECRET_KEY", secret, "connections.secretKey")
        .build();

    let pod = PodTemplateSpec {
        metadata: Some(
            ObjectMetaBuilder::new()
                .name(druid_connection.job_name())
                .build(),
        ),
        spec: Some(PodSpec {
            containers: vec![container],
            image_pull_secrets: resolved_product_image.pull_secrets.clone(),
            restart_policy: Some("Never".to_string()),
            service_account: Some(sa_name.to_string()),
            security_context: Some(
                PodSecurityContextBuilder::new()
                    .run_as_user(1000)
                    .run_as_group(0)
                    .build(),
            ),
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

pub fn error_policy(
    _obj: Arc<DeserializeGuard<DruidConnection>>,
    error: &Error,
    _ctx: Arc<Ctx>,
) -> Action {
    match error {
        Error::InvalidDruidConnection { .. } => Action::await_change(),
        _ => Action::requeue(*Duration::from_secs(5)),
    }
}
