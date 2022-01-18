use std::time::Duration;

use futures::{future, StreamExt};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{ContainerBuilder, ObjectMetaBuilder},
    k8s_openapi::{
        api::{
            batch::v1::{Job, JobSpec},
            core::v1::{ConfigMap, PodSpec, PodTemplateSpec},
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
use stackable_operator::client::Client;
use stackable_superset_crd::{
    commands::{CommandStatus, AddDruids, DruidConnection},
    SupersetCluster, SupersetClusterRef,
};
use crate::util::{find_superset_cluster_by_ref, env_var_from_secret, superset_version};

const FIELD_MANAGER_SCOPE: &str = "supersetcluster";

pub struct Ctx {
    pub client: stackable_operator::client::Client,
}

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to retrieve superset version"))]
    NoSupersetVersion {
        source: crate::util::Error,
    },
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
    MissingDruidConnString { cm_name: String, namespace: Option<String> },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn reconcile_add_druids(add_druids: AddDruids, ctx: Context<Ctx>) -> Result<ReconcilerAction> {
    tracing::info!("Starting reconciling AddDruids");

    let client = &ctx.get_ref().client;

    let superset = find_superset_cluster_by_ref(client, &add_druids.spec.cluster_ref)
        .await.with_context(|| SupersetClusterNotFound {cluster_ref: add_druids.spec.cluster_ref.clone()})?;

    let job = build_add_druids_job(&add_druids, &superset, client).await?;
    client
        .apply_patch(FIELD_MANAGER_SCOPE, &job, &job)
        .await
        .with_context(|| ApplyJob {
            superset: ObjectRef::from_obj(&superset),
        })?;

    if add_druids.status == None {
        let started_at = Some(Time(Utc::now()));
        client
            .apply_patch_status(
                FIELD_MANAGER_SCOPE,
                &add_druids,
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
                &add_druids,
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

async fn get_sqlalchemy_uri_for_druid_cluster(cluster_name: &String, namespace: &String, client: &Client) -> Result<String> {
    client
        .get::<ConfigMap>(cluster_name, Some(namespace))
        .await
        .with_context(|| GetDruidConnStringConfigMap {
            cm_name: cluster_name.clone(),
            namespace: namespace.clone(),
        })?
        .data
        .and_then(|mut data| data.remove("DRUID_SQLALCHEMY"))
        .with_context(|| MissingDruidConnString {
            cm_name: cluster_name.clone(),
            namespace: namespace.clone(),
        })
}

/// Returns a yaml document read to be imported with "superset import-datasources"
async fn build_druid_db_yaml(druids: &Vec<DruidConnection>, client: &Client) -> Result<String> {
    let mut druids_formatted = Vec::new();
    for d in druids {
        let name = if let Some(name) = d.name.clone() { name } else { d.cluster.clone() };
        let namespace = if let Some(ns) = d.namespace.clone() { ns.to_string() } else { "default".to_string() };
        let uri = get_sqlalchemy_uri_for_druid_cluster(&d.cluster, &namespace, client).await?;
        druids_formatted.push(format!("- database_name: {}\n  sqlalchemy_uri: {}\n  tables: []\n", name, uri));
    }
    Ok(format!("databases:\n{}", druids_formatted.join("")))
}

/// The rolegroup [`StatefulSet`] runs the rolegroup, as configured by the administrator.
///
/// The [`Pod`](`stackable_operator::k8s_openapi::api::core::v1::Pod`)s are accessible through the corresponding [`Service`] (from [`build_rolegroup_service`]).
async fn build_add_druids_job(add_druids: &AddDruids, superset: &SupersetCluster, client: &Client) -> Result<Job> {
    let mut commands = vec![
    ];
        let druid_info = build_druid_db_yaml(&add_druids.spec.druid_connections, client).await?;
        commands.push(String::from(format!("echo \"{}\" > /tmp/druids.yaml", druid_info)));
        commands.push(String::from("superset import_datasources -p /tmp/druids.yaml"));


    let version = superset_version(superset).context(NoSupersetVersion)?;
    let secret = &add_druids.spec.credentials_secret;

    let container = ContainerBuilder::new("superset-add-druids")
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
                .name(format!("{}-adddruids", superset.name()))
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
            .name(format!("{}-adddruids", superset.name()))
            .namespace_opt(superset.metadata.namespace.clone())
            .ownerreference_from_resource(add_druids, None, Some(true))
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

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> ReconcilerAction {
    ReconcilerAction {
        requeue_after: Some(Duration::from_secs(5)),
    }
}
