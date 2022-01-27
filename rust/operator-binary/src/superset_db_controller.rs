//! Ensures that `Pod`s are configured and running for each [`SupersetCluster`]

use std::time::Duration;

use crate::util::{env_var_from_secret, get_job_state, JobState};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{ContainerBuilder, ObjectMetaBuilder},
    k8s_openapi::api::{
        batch::v1::{Job, JobSpec},
        core::v1::{PodSpec, PodTemplateSpec, Secret},
    },
    kube::{
        runtime::{
            controller::{Context, ReconcilerAction},
            reflector::ObjectRef,
        },
        ResourceExt,
    },
};
use stackable_superset_crd::supersetdb::{SupersetDB, SupersetDBStatus, SupersetDBStatusCondition};

const FIELD_MANAGER_SCOPE: &str = "supersetcluster";

pub struct Ctx {
    pub client: stackable_operator::client::Client,
}

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
#[snafu(context(suffix(false)))]
pub enum Error {
    #[snafu(display("failed to apply Job for {}", superset_db))]
    ApplyJob {
        source: stackable_operator::error::Error,
        superset_db: ObjectRef<SupersetDB>,
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
        "database state is 'initializing' but failed to find job {}/{}",
        namespace,
        name
    ))]
    GetInitializationJob {
        source: stackable_operator::error::Error,
        namespace: String,
        name: String,
    },
    #[snafu(display("Failed to check whether the secret ({}) exists", secret_name))]
    SecretCheck {
        source: stackable_operator::error::Error,
        secret_name: String,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn reconcile_superset_db(
    superset_db: SupersetDB,
    ctx: Context<Ctx>,
) -> Result<ReconcilerAction> {
    tracing::info!("Starting reconcile");

    let client = &ctx.get_ref().client;

    if let Some(ref s) = superset_db.status {
        match s.condition {
            SupersetDBStatusCondition::Provisioned => {
                let secret_exists = client
                    .exists::<Secret>(
                        &superset_db.spec.credentials_secret,
                        superset_db.metadata.namespace.as_deref(),
                    )
                    .await
                    .context(SecretCheck {
                        secret_name: superset_db.spec.credentials_secret.clone(),
                    })?;
                if secret_exists {
                    let job = build_init_job(&superset_db)?;
                    client
                        .apply_patch(FIELD_MANAGER_SCOPE, &job, &job)
                        .await
                        .context(ApplyJob {
                            superset_db: ObjectRef::from_obj(&superset_db),
                        })?;
                    // The job is started, update status to reflect new state
                    client
                        .apply_patch_status(FIELD_MANAGER_SCOPE, &superset_db, &s.initializing())
                        .await
                        .context(ApplyStatus)?;
                }
            }
            SupersetDBStatusCondition::Initializing => {
                // In here, check the associated job that is running.
                // If it is still running, do nothing. If it completed, set status to ready, if it failed, set status to failed.
                // TODO we need to fetch the job here
                // we need namespace/name.
                let ns = superset_db.metadata.namespace.clone().unwrap();
                let job_name = superset_db.job_name();
                let job = client.get::<Job>(&job_name, Some(&ns)).await.context(
                    GetInitializationJob {
                        namespace: ns,
                        name: job_name,
                    },
                )?;

                let new_status = match get_job_state(&job) {
                    JobState::Complete => Some(s.ready()),
                    JobState::Failed => Some(s.failed()),
                    JobState::InProgress => None,
                };

                if let Some(ns) = new_status {
                    client
                        .apply_patch_status(FIELD_MANAGER_SCOPE, &superset_db, &ns)
                        .await
                        .context(ApplyStatus)?;
                }
            }
            SupersetDBStatusCondition::Ready => (),
            SupersetDBStatusCondition::Failed => (),
        }
    } else {
        // Status is none => initialize the status object as "Provisioned"
        let new_status = SupersetDBStatus::new();
        client
            .apply_patch_status(FIELD_MANAGER_SCOPE, &superset_db, &new_status)
            .await
            .context(ApplyStatus)?;
    }

    Ok(ReconcilerAction {
        requeue_after: None,
    })
}

fn build_init_job(superset_db: &SupersetDB) -> Result<Job> {
    let mut commands = vec![
        String::from(
            "superset fab create-admin \
                    --username \"$ADMIN_USERNAME\" \
                    --firstname \"$ADMIN_FIRSTNAME\" \
                    --lastname \"$ADMIN_LASTNAME\" \
                    --email \"$ADMIN_EMAIL\" \
                    --password \"$ADMIN_PASSWORD\"",
        ),
        String::from("superset db upgrade"),
        String::from("superset init"),
    ];
    if superset_db.spec.load_examples {
        commands.push(String::from("superset load_examples"));
    }

    let secret = &superset_db.spec.credentials_secret;

    let container = ContainerBuilder::new("superset-init-db")
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
            env_var_from_secret("ADMIN_USERNAME", secret, "adminUser.username"),
            env_var_from_secret("ADMIN_FIRSTNAME", secret, "adminUser.firstname"),
            env_var_from_secret("ADMIN_LASTNAME", secret, "adminUser.lastname"),
            env_var_from_secret("ADMIN_EMAIL", secret, "adminUser.email"),
            env_var_from_secret("ADMIN_PASSWORD", secret, "adminUser.password"),
        ])
        .build();

    let pod = PodTemplateSpec {
        metadata: Some(
            ObjectMetaBuilder::new()
                .name(format!("{}-init", superset_db.name()))
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
            .name(superset_db.metadata.name.as_ref().unwrap())
            .namespace_opt(superset_db.metadata.namespace.clone())
            .ownerreference_from_resource(superset_db, None, Some(true))
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
