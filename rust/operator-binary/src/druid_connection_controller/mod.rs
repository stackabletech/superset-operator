use std::{str::FromStr, sync::Arc};

use const_format::concatcp;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        meta::ObjectMetaBuilder,
        pod::{container::ContainerBuilder, security::PodSecurityContextBuilder},
    },
    cli::OperatorEnvironmentOptions,
    client::Client,
    commons::product_image_selection::{self, ResolvedProductImage},
    constant,
    database_connections::TemplatingMechanism,
    k8s_openapi::api::{
        batch::v1::{Job, JobSpec},
        core::v1::{ConfigMap, EnvVar, EnvVarSource, PodSpec, PodTemplateSpec, SecretKeySelector},
    },
    kube::{
        Resource, ResourceExt,
        core::{DeserializeGuard, DynamicObject, error_boundary},
        runtime::{controller::Action, reflector::ObjectRef},
    },
    logging::controller::ReconcilerError,
    shared::time::Duration,
    status::condition::{ClusterConditionStatus, ClusterConditionType},
    v2::builder::pod::container::{EnvVarName, EnvVarSet},
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    APP_NAME, SUPERSET_OPERATOR_NAME,
    built_info::PKG_VERSION,
    controller::{
        CONTAINER_IMAGE_BASE_NAME,
        build::{properties::ConfigFileName, resource::bash_wrapper_command},
    },
    crd::{
        INTERNAL_SECRET_SECRET_KEY, METADATA_DATABASE_ENV_PREFIX, PYTHONPATH, druidconnection,
        v1alpha1,
    },
    druid_connection_controller::job_state::{JobState, get_job_state},
};

mod job_state;
mod rbac;

pub const DRUID_CONNECTION_CONTROLLER_NAME: &str = "druid-connection";
pub const DRUID_CONNECTION_FULL_CONTROLLER_NAME: &str = concatcp!(
    DRUID_CONNECTION_CONTROLLER_NAME,
    '.',
    SUPERSET_OPERATOR_NAME
);

pub struct Ctx {
    pub client: Client,
    pub operator_environment: OperatorEnvironmentOptions,
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
        source: crate::crd::druidconnection::Error,
        druid_connection: ObjectRef<druidconnection::v1alpha1::DruidConnection>,
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

    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: product_image_selection::Error,
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
            Error::ResolveProductImage { .. } => None,
        }
    }
}

pub async fn reconcile_druid_connection(
    druid_connection: Arc<DeserializeGuard<druidconnection::v1alpha1::DruidConnection>>,
    ctx: Arc<Ctx>,
) -> Result<Action> {
    tracing::info!("Starting reconciling DruidConnections");

    if druid_connection.meta().deletion_timestamp.is_some() {
        return Ok(Action::await_change());
    }

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
            druidconnection::v1alpha1::DruidConnectionStatusCondition::Pending => {
                // Is the referenced druid discovery configmap there?
                let druid_discovery_cm_exists = client
                    .get_opt::<ConfigMap>(
                        druid_connection.druid_name(),
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
                    .get::<v1alpha1::SupersetCluster>(
                        druid_connection.superset_name(),
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
                        druid_connection.druid_name(),
                        &druid_connection.druid_namespace().context(
                            DruidConnectionNoNamespaceSnafu {
                                druid_connection: ObjectRef::from_obj(druid_connection),
                            },
                        )?,
                        client,
                    )
                    .await?;
                    let resolved_product_image = superset_cluster
                        .spec
                        .image
                        .resolve(
                            CONTAINER_IMAGE_BASE_NAME,
                            &ctx.operator_environment.image_repository,
                            PKG_VERSION,
                        )
                        .context(ResolveProductImageSnafu)?;
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
            druidconnection::v1alpha1::DruidConnectionStatusCondition::Importing => {
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
            druidconnection::v1alpha1::DruidConnectionStatusCondition::Ready => (),
            druidconnection::v1alpha1::DruidConnectionStatusCondition::Failed => (),
        }
    } else {
        // Status not set yet, initialize
        client
            .apply_patch_status(
                DRUID_CONNECTION_CONTROLLER_NAME,
                druid_connection,
                &druidconnection::v1alpha1::DruidConnectionStatus::new(),
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

// Name of the env var (and the matching `superset_config.py` setting) holding the metadata
// database connection string for the import job.
constant!(SQLALCHEMY_DATABASE_URI_ENV: EnvVarName = "SQLALCHEMY_DATABASE_URI");

// Name of the env var holding the Flask `SECRET_KEY` for the import job.
constant!(SUPERSET_SECRET_KEY_ENV: EnvVarName = "SUPERSET_SECRET_KEY");

/// Builds the import job.  When run it will import the druid connection into the database.
async fn build_import_job(
    superset_cluster: &v1alpha1::SupersetCluster,
    druid_connection: &druidconnection::v1alpha1::DruidConnection,
    resolved_product_image: &ResolvedProductImage,
    sqlalchemy_str: &str,
    sa_name: &str,
) -> Result<Job> {
    let mut commands = vec![];

    let config = format!(
        "import os; {name} = os.path.expandvars(os.environ.get('{name}'))",
        name = SQLALCHEMY_DATABASE_URI_ENV.as_ref(),
    );
    commands.push(format!("mkdir -p {PYTHONPATH}"));
    commands.push(format!(
        "echo \"{config}\" > {PYTHONPATH}/{config_file}",
        config_file = ConfigFileName::SupersetConfig
    ));

    let druid_info = build_druid_db_yaml(&druid_connection.spec.druid.name, sqlalchemy_str)?;
    commands.push(format!("echo \"{druid_info}\" > /tmp/druids.yaml"));
    commands.push(String::from(
        "superset import_datasources -p /tmp/druids.yaml",
    ));

    // `METADATA_DATABASE_ENV_PREFIX` is the prefix for the env vars that hold the database
    // credentials (e.g. METADATA_DATABASE_USERNAME, METADATA_DATABASE_PASSWORD). It should match
    // the prefix used by the airflow-operator for consistency.
    let templating_mechanism = TemplatingMechanism::BashEnvSubstitution;
    let metadata_database_connection_details = superset_cluster
        .metadata_database()
        .sqlalchemy_connection_details_with_templating(
            METADATA_DATABASE_ENV_PREFIX,
            &templating_mechanism,
        );

    // All operator-set environment variables of the import container, collected into an
    // `EnvVarSet` so that every name occurs only once.
    let mut env_vars = EnvVarSet::new()
        .with_value(
            &SQLALCHEMY_DATABASE_URI_ENV,
            metadata_database_connection_details.url_template.clone(),
        )
        // The shared secret key Secret name is derived from the raw cluster name, which carries
        // no length bound tight enough for the typed `SecretName`, so the `EnvVar` is built by
        // hand instead of using `with_secret_key_ref`.
        .with_env_var(EnvVar {
            name: SUPERSET_SECRET_KEY_ENV.to_string(),
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    name: superset_cluster.shared_secret_key_secret_name(),
                    key: INTERNAL_SECRET_SECRET_KEY.to_string(),
                    ..SecretKeySelector::default()
                }),
                ..EnvVarSource::default()
            }),
            ..EnvVar::default()
        })
        .expect("SUPERSET_SECRET_KEY is a valid environment variable name");

    for env_var in metadata_database_connection_details.env_vars() {
        env_vars = env_vars.with_env_var(env_var.clone()).expect(
            "the database connection env var names are generated by operator-rs from the unique \
             database name and are therefore valid",
        );
    }

    let mut container_builder = ContainerBuilder::new("superset-import-druid-connection")
        .expect("ContainerBuilder not created");
    container_builder
        .image_from_product_image(resolved_product_image)
        .command(bash_wrapper_command())
        .args(vec![commands.join("; ")])
        .add_env_vars(env_vars);

    let container = container_builder.build();

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
            security_context: Some(PodSecurityContextBuilder::with_stackable_defaults().build()),
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
    _obj: Arc<DeserializeGuard<druidconnection::v1alpha1::DruidConnection>>,
    error: &Error,
    _ctx: Arc<Ctx>,
) -> Action {
    match error {
        Error::InvalidDruidConnection { .. } => Action::await_change(),
        _ => Action::requeue(*Duration::from_secs(5)),
    }
}

#[cfg(test)]
mod tests {
    use stackable_operator::{
        commons::networking::DomainName,
        kube::{Client as KubeClient, Config},
        utils::{cluster_info::KubernetesClusterInfo, yaml_from_str_singleton_map},
    };

    use super::*;

    /// The client points at a closed port, so any API call would fail the reconciliation: an `Ok`
    /// proves that a connection being deleted returns before the reconciler touches the Kubernetes
    /// API, and because the spec is invalid, before the [`DeserializeGuard`] is unwrapped.
    #[test]
    fn reconcile_exits_early_for_deleted_connection() {
        let druid_connection = serde_yaml::from_str(
            r#"
apiVersion: superset.stackable.tech/v1alpha1
kind: DruidConnection
metadata:
  name: simple-connection
  namespace: default
  deletionTimestamp: "2026-08-14T12:00:00Z"
spec: {}
"#,
        )
        .expect("YAML parses; the invalid spec is captured inside the DeserializeGuard");

        let action = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread tokio runtime")
            .block_on(async {
                let ctx = Arc::new(Ctx {
                    client: Client::new(
                        KubeClient::try_from(Config::new(
                            "http://127.0.0.1:1".parse().expect("valid static URI"),
                        ))
                        .expect("client from static config"),
                        None,
                        "default".to_owned(),
                        KubernetesClusterInfo {
                            cluster_domain: DomainName::from_str("cluster.local")
                                .expect("valid cluster domain"),
                        },
                    ),
                    operator_environment: OperatorEnvironmentOptions {
                        operator_namespace: "stackable-operators".to_owned(),
                        operator_service_name: "superset-operator".to_owned(),
                        image_repository: "oci.stackable.tech/sdp".to_owned(),
                    },
                });

                reconcile_druid_connection(Arc::new(druid_connection), ctx).await
            })
            .expect("a deleted connection reconciles without any API call");

        assert_eq!(action, Action::await_change());
    }

    #[test]
    fn test_constants() {
        // Test that dereferencing the constants does not panic.
        let _ = *SQLALCHEMY_DATABASE_URI_ENV;
        let _ = *SUPERSET_SECRET_KEY_ENV;
    }

    /// The import Job container must carry the connection URL, the Superset secret key and the
    /// database credential env vars, each exactly once.
    #[tokio::test]
    async fn import_job_env_vars_are_set_exactly_once() {
        let superset: v1alpha1::SupersetCluster = yaml_from_str_singleton_map(
            r#"
        apiVersion: superset.stackable.tech/v1alpha1
        kind: SupersetCluster
        metadata:
          name: simple-superset
          namespace: default
          uid: 01234567-89ab-cdef-0123-456789abcdef
        spec:
          image:
            productVersion: 4.1.4
          clusterConfig:
            credentialsSecret: superset-admin-credentials
            metadataDatabase:
              postgresql:
                host: superset-postgresql
                database: superset
                credentialsSecretName: superset-postgresql-credentials
          nodes:
            roleGroups:
              default:
                replicas: 1
        "#,
        )
        .expect("illegal test input");

        let druid_connection: druidconnection::v1alpha1::DruidConnection =
            yaml_from_str_singleton_map(
                r#"
        apiVersion: superset.stackable.tech/v1alpha1
        kind: DruidConnection
        metadata:
          name: simple-connection
          namespace: default
          uid: 11234567-89ab-cdef-0123-456789abcdef
        spec:
          superset:
            name: simple-superset
            namespace: default
          druid:
            name: simple-druid
            namespace: default
        "#,
            )
            .expect("illegal test input");

        let resolved_product_image = ResolvedProductImage {
            product_version: "4.1.4".to_owned(),
            app_version_label_value: "4.1.4-stackable0.0.0-dev"
                .parse()
                .expect("valid label value"),
            image: "oci.example.org/superset:4.1.4".to_owned(),
            image_pull_policy: "Always".to_owned(),
            pull_secrets: None,
        };

        let job = build_import_job(
            &superset,
            &druid_connection,
            &resolved_product_image,
            "postgresql+psycopg2://user:pass@host/db",
            "superset-sa",
        )
        .await
        .expect("the import job should build");

        let containers = job
            .spec
            .expect("the Job has a spec")
            .template
            .spec
            .expect("the pod template has a spec")
            .containers;
        assert_eq!(containers.len(), 1, "expected exactly one container");
        let env = containers
            .into_iter()
            .next()
            .expect("the import container exists")
            .env
            .expect("the import container has env vars");

        for name in [
            "SQLALCHEMY_DATABASE_URI",
            "SUPERSET_SECRET_KEY",
            "METADATA_DATABASE_USERNAME",
            "METADATA_DATABASE_PASSWORD",
        ] {
            assert_eq!(
                env.iter().filter(|env_var| env_var.name == name).count(),
                1,
                "the env var {name} should be set exactly once"
            );
        }

        let secret_key = env
            .iter()
            .find(|env_var| env_var.name == "SUPERSET_SECRET_KEY")
            .expect("SUPERSET_SECRET_KEY is set");
        assert_eq!(
            secret_key
                .value_from
                .as_ref()
                .and_then(|source| source.secret_key_ref.as_ref())
                .map(|secret_ref| secret_ref.name.as_str()),
            Some("simple-superset-secret-key")
        );
    }
}
