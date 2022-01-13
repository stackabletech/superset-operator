//! Ensures that `Pod`s are configured and running for each [`SupersetCluster`]

use std::time::Duration;

use futures::{future, StreamExt};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{ContainerBuilder, ObjectMetaBuilder},
    k8s_openapi::{
        api::{
            batch::v1::{Job, JobSpec},
            core::v1::{EnvVar, EnvVarSource, PodSpec, PodTemplateSpec, SecretKeySelector},
        },
        apimachinery::pkg::apis::meta::v1::Time,
        chrono::Utc,
    },
    kube::{
        api::ListParams,
        runtime::{
            self,
            controller::{Context, ReconcilerAction},
            reflector::ObjectRef,
        },
        ResourceExt,
    },
};
use stackable_superset_crd::{
    commands::{CommandStatus, Init, DruidConnection},
    SupersetCluster, SupersetClusterRef,
};

const FIELD_MANAGER_SCOPE: &str = "supersetcluster";

pub struct Ctx {
    pub client: stackable_operator::client::Client,
}

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object does not refer to SupersetCluster"))]
    InvalidSupersetReference,
    #[snafu(display("could not find {}", superset))]
    FindSuperset {
        source: stackable_operator::error::Error,
        superset: ObjectRef<SupersetCluster>,
    },
    #[snafu(display("object defines no version"))]
    ObjectHasNoVersion,
    #[snafu(display("failed to apply Job for {}", superset))]
    ApplyJob {
        source: stackable_operator::error::Error,
        superset: ObjectRef<SupersetCluster>,
    },
    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn reconcile_init(init: Init, ctx: Context<Ctx>) -> Result<ReconcilerAction> {
    tracing::info!("Starting reconcile");

    let client = &ctx.get_ref().client;

    let superset = find_superset_cluster_of_init_command(client, &init).await?;

    let job = build_init_job(&init, &superset)?;
    client
        .apply_patch(FIELD_MANAGER_SCOPE, &job, &job)
        .await
        .with_context(|| ApplyJob {
            superset: ObjectRef::from_obj(&superset),
        })?;

    if init.status == None {
        let started_at = Some(Time(Utc::now()));
        client
            .apply_patch_status(
                FIELD_MANAGER_SCOPE,
                &init,
                &CommandStatus {
                    started_at: started_at.to_owned(),
                    finished_at: None,
                },
            )
            .await
            .context(ApplyStatus)?;

        wait_completed(client, &job).await;

        let finished_at = Some(Time(Utc::now()));
        client
            .apply_patch_status(
                FIELD_MANAGER_SCOPE,
                &init,
                &CommandStatus {
                    started_at,
                    finished_at,
                },
            )
            .await
            .context(ApplyStatus)?;
    }

    Ok(ReconcilerAction {
        requeue_after: None,
    })
}

fn get_sqlalchemy_uri_for_druid_cluster(cluster_name: &String) -> String {
    // TODO here we have to retrieve the configmap and get the URL
    "druid://psqls3-druid-router.default.svc.cluster.local:8888/druid/v2/sql".to_string()
}

/// Returns a yaml document read to be imported with "superset import-datasources"
fn build_druid_db_yaml(druids: &Vec<DruidConnection>) -> String {
    let druids_formatted: Vec<String> = druids.iter().map(|d| {
        let name = if let Some(name) = d.name.clone() { name } else { d.cluster.clone() };
        let uri = get_sqlalchemy_uri_for_druid_cluster(&d.cluster);
        format!("- database_name: {}\n  sqlalchemy_uri: {}\n  tables: []\n", name, uri)
    }).collect();
    format!("databases:\n{}", druids_formatted.join(""))
}

/// The rolegroup [`StatefulSet`] runs the rolegroup, as configured by the administrator.
///
/// The [`Pod`](`stackable_operator::k8s_openapi::api::core::v1::Pod`)s are accessible through the corresponding [`Service`] (from [`build_rolegroup_service`]).
fn build_init_job(init: &Init, superset: &SupersetCluster) -> Result<Job> {
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
    if init.spec.load_examples {
        commands.push(String::from("superset load_examples"));
    }
    if let Some(druids) = &init.spec.druid_connections {
        let druid_info = build_druid_db_yaml(druids);
        commands.push(String::from(format!("echo \"{}\" > /tmp/druids.yaml", druid_info)));
        commands.push(String::from("superset import_datasources -p /tmp/druids.yaml"));
    }

    let version = superset_version(superset)?;
    let secret = &init.spec.credentials_secret;

    let container = ContainerBuilder::new("superset-init-db")
        .image(format!(
            "docker.stackable.tech/stackable/superset:{}-stackable0",
            version
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
                .name(format!("{}-init", superset.name()))
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
            .name(format!("{}-init", superset.name()))
            .namespace_opt(superset.metadata.namespace.clone())
            .ownerreference_from_resource(init, None, Some(true))
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

async fn find_superset_cluster_of_init_command(
    client: &stackable_operator::client::Client,
    init: &Init,
) -> Result<SupersetCluster, Error> {
    if let SupersetClusterRef {
        name: Some(superset_name),
        namespace: maybe_superset_ns,
    } = &init.spec.cluster_ref
    {
        let superset_ns = maybe_superset_ns.as_deref().unwrap_or("default");
        client
            .get::<SupersetCluster>(superset_name, Some(superset_ns))
            .await
            .with_context(|| FindSuperset {
                superset: ObjectRef::new(superset_name).within(superset_ns),
            })
    } else {
        InvalidSupersetReference.fail()
    }
}

// Waits until the given job is completed.
async fn wait_completed(client: &stackable_operator::client::Client, job: &Job) {
    let completed = |job: &Job| {
        job.status
            .as_ref()
            .and_then(|status| status.conditions.clone())
            .unwrap_or_default()
            .into_iter()
            .any(|condition| condition.type_ == "Complete" && condition.status == "True")
    };

    let lp = ListParams::default().fields(&format!("metadata.name={}", job.name()));
    let api = client.get_api(Some(job.namespace().as_deref().unwrap_or("default")));
    let watcher = runtime::watcher(api, lp).boxed();
    runtime::utils::try_flatten_applied(watcher)
        .any(|res| future::ready(res.as_ref().map(|job| completed(job)).unwrap_or(false)))
        .await;
}

pub fn superset_version(superset: &SupersetCluster) -> Result<&str> {
    superset.spec.version.as_deref().context(ObjectHasNoVersion)
}

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> ReconcilerAction {
    ReconcilerAction {
        requeue_after: Some(Duration::from_secs(5)),
    }
}

fn env_var_from_secret(var_name: &str, secret: &str, secret_key: &str) -> EnvVar {
    EnvVar {
        name: String::from(var_name),
        value_from: Some(EnvVarSource {
            secret_key_ref: Some(SecretKeySelector {
                name: Some(String::from(secret)),
                key: String::from(secret_key),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}
