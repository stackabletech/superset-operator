mod error;
use crate::error::Error;
use futures::StreamExt;
use stackable_operator::command_controller::Command;
use stackable_operator::k8s_openapi::api::batch::v1::{Job, JobSpec};
use stackable_superset_crd::commands::{Init, Restart, Start, Stop};

use async_trait::async_trait;
use stackable_operator::builder::{ObjectMetaBuilder, PodBuilder};
use stackable_operator::client::Client;
use stackable_operator::command::{clear_current_command, materialize_command};

use stackable_operator::controller::Controller;
use stackable_operator::controller::{ControllerStrategy, ReconciliationState};
use stackable_operator::error::OperatorResult;
use stackable_operator::identity::{LabeledPodIdentityFactory, PodIdentity, PodToNodeMapping};
use stackable_operator::k8s_openapi::api::core::v1::{
    Container, ContainerPort, EnvVar, EnvVarSource, Pod, PodSpec, PodTemplateSpec,
    SecretKeySelector,
};
use stackable_operator::kube::api::{ListParams, ResourceExt};
use stackable_operator::kube::{runtime, Api};
use stackable_operator::labels;
use stackable_operator::labels::{
    build_common_labels_for_all_managed_resources, get_recommended_labels,
};
use stackable_operator::name_utils;
use stackable_operator::product_config::types::PropertyNameKind;
use stackable_operator::product_config::ProductConfigManager;
use stackable_operator::product_config_utils::{
    config_for_role_and_group, transform_all_roles_to_config, validate_all_roles_and_groups_config,
    ValidatedRoleConfigByPropertyKind,
};
use stackable_operator::reconcile::{
    ContinuationStrategy, ReconcileFunctionAction, ReconcileResult, ReconciliationContext,
};
use stackable_operator::role_utils::{
    find_nodes_that_fit_selectors, get_role_and_group_labels,
    list_eligible_nodes_for_role_and_group, EligibleNodesForRoleAndGroup,
};
use stackable_operator::scheduler::{
    K8SUnboundedHistory, RoleGroupEligibleNodes, ScheduleStrategy, Scheduler, StickyScheduler,
};
use stackable_operator::status::HasClusterExecutionStatus;
use stackable_operator::status::{init_status, ClusterExecutionStatus};
use stackable_operator::versioning::{finalize_versioning, init_versioning};
use stackable_superset_crd::{
    SupersetCluster, SupersetClusterSpec, SupersetRole, SupersetVersion, APP_NAME,
    CREDENTIALS_SECRET_PROPERTY, HTTP_PORT,
};
use std::collections::{BTreeMap, HashMap};
use std::future::{self, Future};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use strum::IntoEnumIterator;
use tracing::error;
use tracing::{debug, info, trace};

/// The docker image we default to. This needs to be adapted if the operator does not work
/// with images 0.0.1, 0.1.0 etc. anymore and requires e.g. a new major version like 1(.0.0).
const DEFAULT_IMAGE_VERSION: &str = "0";
const IMAGE: &str = "docker.stackable.tech/stackable/superset";

const FINALIZER_NAME: &str = "superset.stackable.tech/cleanup";
const ID_LABEL: &str = "superset.stackable.tech/id";

const PORT: i32 = 8088;

type SupersetReconcileResult = ReconcileResult<error::Error>;

struct SupersetState {
    context: ReconciliationContext<SupersetCluster>,
    existing_pods: Vec<Pod>,
    eligible_nodes: EligibleNodesForRoleAndGroup,
    validated_role_config: ValidatedRoleConfigByPropertyKind,
}

impl SupersetState {
    /// Required labels for pods. Pods without any of these will deleted and/or replaced.
    pub fn get_required_labels(&self) -> BTreeMap<String, Option<Vec<String>>> {
        let roles = SupersetRole::iter()
            .map(|role| role.to_string())
            .collect::<Vec<_>>();
        let mut mandatory_labels = BTreeMap::new();

        mandatory_labels.insert(labels::APP_COMPONENT_LABEL.to_string(), Some(roles));
        mandatory_labels.insert(
            labels::APP_INSTANCE_LABEL.to_string(),
            Some(vec![self.context.name()]),
        );
        mandatory_labels.insert(
            labels::APP_VERSION_LABEL.to_string(),
            Some(vec![self.context.resource.spec.version.to_string()]),
        );
        mandatory_labels.insert(ID_LABEL.to_string(), None);

        mandatory_labels
    }

    /// Will initialize the status object if it's never been set.
    async fn init_status(&mut self) -> SupersetReconcileResult {
        // init status with default values if not available yet.
        self.context.resource = init_status(&self.context.client, &self.context.resource).await?;

        let spec_version = self.context.resource.spec.version.clone();

        self.context.resource =
            init_versioning(&self.context.client, &self.context.resource, spec_version).await?;

        // set the cluster status to running
        if self.context.resource.cluster_execution_status().is_none() {
            self.context
                .client
                .merge_patch_status(
                    &self.context.resource,
                    &self
                        .context
                        .resource
                        .cluster_execution_status_patch(&ClusterExecutionStatus::Running),
                )
                .await?;
        }

        Ok(ReconcileFunctionAction::Continue)
    }

    pub async fn create_missing_pods(&mut self) -> SupersetReconcileResult {
        trace!(target: "create_missing_pods","Starting `create_missing_pods`");

        // The iteration happens in two stages here, to accommodate the way our operators think
        // about roles and role groups.
        // The hierarchy is:
        // - Roles (Nodes)
        //   - Role groups (user defined)
        for role in SupersetRole::iter() {
            let role_str = &role.to_string();
            if let Some(nodes_for_role) = self.eligible_nodes.get(role_str) {
                for (role_group, eligible_nodes) in nodes_for_role {
                    debug!( target: "create_missing_pods",
                        "Identify missing pods for [{}] role and group [{}]",
                        role_str, role_group
                    );
                    trace!( target: "create_missing_pods",
                        "candidate_nodes[{}]: [{:?}]",
                        eligible_nodes.nodes.len(),
                        eligible_nodes
                            .nodes
                            .iter()
                            .map(|node| node.metadata.name.as_ref().unwrap())
                            .collect::<Vec<_>>()
                    );
                    trace!(target: "create_missing_pods",
                        "existing_pods[{}]: [{:?}]",
                        &self.existing_pods.len(),
                        &self
                            .existing_pods
                            .iter()
                            .map(|pod| pod.metadata.name.as_ref().unwrap())
                            .collect::<Vec<_>>()
                    );
                    trace!(target: "create_missing_pods",
                        "labels: [{:?}]",
                        get_role_and_group_labels(role_str, role_group)
                    );
                    let mut history = match self
                        .context
                        .resource
                        .status
                        .as_ref()
                        .and_then(|status| status.history.as_ref())
                    {
                        Some(simple_history) => {
                            // we clone here because we cannot access mut self because we need it later
                            // to create config maps and pods. The `status` history will be out of sync
                            // with the cloned `simple_history` until the next reconcile.
                            // The `status` history should not be used after this method to avoid side
                            // effects.
                            K8SUnboundedHistory::new(&self.context.client, simple_history.clone())
                        }
                        None => K8SUnboundedHistory::new(
                            &self.context.client,
                            PodToNodeMapping::default(),
                        ),
                    };

                    let mut sticky_scheduler =
                        StickyScheduler::new(&mut history, ScheduleStrategy::GroupAntiAffinity);

                    let pod_id_factory = LabeledPodIdentityFactory::new(
                        APP_NAME,
                        &self.context.name(),
                        &self.eligible_nodes,
                        ID_LABEL,
                        1,
                    );

                    trace!("pod_id_factory: {:?}", pod_id_factory.as_ref());

                    let state = sticky_scheduler.schedule(
                        &pod_id_factory,
                        &RoleGroupEligibleNodes::from(&self.eligible_nodes),
                        &self.existing_pods,
                    )?;

                    let mapping = state.remaining_mapping().filter(
                        APP_NAME,
                        &self.context.name(),
                        role_str,
                        role_group,
                    );

                    if let Some((pod_id, node_id)) = mapping.iter().next() {
                        // now we have a node that needs a pod -> get validated config
                        let validated_config = config_for_role_and_group(
                            pod_id.role(),
                            pod_id.group(),
                            &self.validated_role_config,
                        )?;

                        self.create_pod(pod_id, &node_id.name, validated_config)
                            .await?;

                        history.save(&self.context.resource).await?;

                        return Ok(ReconcileFunctionAction::Requeue(Duration::from_secs(10)));
                    }
                }
            }
        }

        // If we reach here it means all pods must be running on target_version.
        // We can now set current_version to target_version (if target_version was set) and
        // target_version to None
        finalize_versioning(&self.context.client, &self.context.resource).await?;

        Ok(ReconcileFunctionAction::Continue)
    }

    /// Creates the pod required for the superset instance.
    ///
    /// # Arguments
    ///
    /// - `pod_id` - The `PodIdentity` containing app, instance, role, group names and the id.
    /// - `node_name` - The node_name for this pod.
    /// - `validated_config` - The validated product config.
    ///
    async fn create_pod(
        &self,
        pod_id: &PodIdentity,
        node_name: &str,
        validated_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    ) -> Result<Pod, Error> {
        let version = &self.context.resource.spec.version;

        let pod_name = name_utils::build_resource_name(
            pod_id.app(),
            &self.context.name(),
            pod_id.role(),
            Some(pod_id.group()),
            Some(node_name),
            None,
        )?;

        let annotations = BTreeMap::new();

        let mut recommended_labels = get_recommended_labels(
            &self.context.resource,
            pod_id.app(),
            &version.to_string(),
            pod_id.role(),
            pod_id.group(),
        );
        recommended_labels.insert(ID_LABEL.to_string(), pod_id.id().to_string());

        let secret = validated_config
            .get(&PropertyNameKind::Env)
            .unwrap()
            .get(CREDENTIALS_SECRET_PROPERTY)
            .unwrap();

        let container = Container {
            name: String::from(APP_NAME),
            image: Some(container_image(version)),
            env: Some(vec![
                env_var_from_secret("SECRET_KEY", secret, "connections.secretKey"),
                env_var_from_secret(
                    "SQLALCHEMY_DATABASE_URI",
                    secret,
                    "connections.sqlalchemyDatabaseUri",
                ),
            ]),
            ports: Some(vec![ContainerPort {
                container_port: PORT,
                name: Some(String::from(HTTP_PORT)),
                ..Default::default()
            }]),
            ..Default::default()
        };

        let pod = PodBuilder::new()
            .metadata(
                ObjectMetaBuilder::new()
                    .generate_name(pod_name)
                    .namespace(&self.context.client.default_namespace)
                    .with_labels(recommended_labels)
                    .with_annotations(annotations)
                    .ownerreference_from_resource(&self.context.resource, Some(true), Some(true))?
                    .build()?,
            )
            .add_container(container)
            .node_name(node_name)
            .build()?;

        Ok(self.context.client.create(&pod).await?)
    }

    async fn delete_all_pods(&self) -> OperatorResult<ReconcileFunctionAction> {
        for pod in &self.existing_pods {
            self.context.client.delete(pod).await?;
        }
        Ok(ReconcileFunctionAction::Done)
    }

    pub async fn process_command(&mut self) -> SupersetReconcileResult {
        match self.context.retrieve_current_command().await? {
            // if there is no new command and the execution status is stopped we stop the
            // reconcile loop here.
            None => match self.context.resource.cluster_execution_status() {
                Some(execution_status) if execution_status == ClusterExecutionStatus::Stopped => {
                    Ok(ReconcileFunctionAction::Done)
                }
                _ => Ok(ReconcileFunctionAction::Continue),
            },
            Some(command_ref) => match command_ref.kind.as_str() {
                "Init" => {
                    info!("Initializing cluster [{:?}]", command_ref);
                    let mut init_command: Init =
                        materialize_command(&self.context.client, &command_ref).await?;
                    Ok(self.initialize_superset_database(&mut init_command).await?)
                }
                "Restart" => {
                    info!("Restarting cluster [{:?}]", command_ref);
                    let mut restart_command: Restart =
                        materialize_command(&self.context.client, &command_ref).await?;
                    Ok(self.context.default_restart(&mut restart_command).await?)
                }
                "Start" => {
                    info!("Starting cluster [{:?}]", command_ref);
                    let mut start_command: Start =
                        materialize_command(&self.context.client, &command_ref).await?;
                    Ok(self.context.default_start(&mut start_command).await?)
                }
                "Stop" => {
                    info!("Stopping cluster [{:?}]", command_ref);
                    let mut stop_command: Stop =
                        materialize_command(&self.context.client, &command_ref).await?;

                    Ok(self.context.default_stop(&mut stop_command).await?)
                }
                _ => {
                    error!("Got unknown type of command: [{:?}]", command_ref);
                    Ok(ReconcileFunctionAction::Done)
                }
            },
        }
    }

    async fn initialize_superset_database(&mut self, command: &mut Init) -> ReconcileResult<Error> {
        let client = &self.context.client;
        let resource = &mut self.context.resource;

        // set start time in command once
        if command.start_time().is_none() {
            let patch = command.start_patch();
            client.merge_patch_status(command, &patch).await?;
        }

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
        if command.spec.load_examples {
            commands.push(String::from("superset load_examples"));
        }

        let version = &resource.spec.version;
        let secret = &command.spec.credentials_secret;

        let pod = PodTemplateSpec {
            metadata: Some(
                ObjectMetaBuilder::new()
                    .generate_name("superset-init-db-")
                    .build()?,
            ),
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: String::from("superset-init-db"),
                    image: Some(container_image(version)),
                    command: Some(vec![String::from("/bin/sh")]),
                    args: Some(vec![String::from("-c"), commands.join("; ")]),
                    env: Some(vec![
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
                    ]),
                    ..Default::default()
                }],
                restart_policy: Some(String::from("Never")),
                ..Default::default()
            }),
        };

        let job = Job {
            metadata: ObjectMetaBuilder::new()
                .generate_name("superset-init-db-")
                .namespace(&self.context.client.default_namespace)
                .ownerreference_from_resource(command, None, None)?
                .build()?,
            spec: Some(JobSpec {
                template: pod,
                ..Default::default()
            }),
            status: None,
        };

        let job = client.create(&job).await?;

        wait_completed(client, &job).await;

        clear_current_command(client, resource).await?;

        let patch = command.finish_patch();
        client.merge_patch_status(command, &patch).await?;

        Ok(ReconcileFunctionAction::Done)
    }
}

fn container_image(version: &SupersetVersion) -> String {
    format!(
        // For now we hardcode the stackable image version via DEFAULT_IMAGE_VERSION
        // which represents the major image version and will fallback to the newest
        // available image e.g. if DEFAULT_IMAGE_VERSION = 0 and versions 0.0.1 and
        // 0.0.2 are available, the latter one will be selected. This may change the
        // image during restarts depending on the imagePullPolicy.
        // TODO: should be made configurable
        "{}:{}-stackable{}",
        IMAGE,
        version.to_string(),
        DEFAULT_IMAGE_VERSION
    )
}

// Waits until the given job is completed.
pub async fn wait_completed(client: &Client, job: &Job) {
    let completed = |job: &Job| {
        job.status
            .as_ref()
            .and_then(|status| status.conditions.clone())
            .unwrap_or_default()
            .into_iter()
            .any(|condition| condition.type_ == "Complete" && condition.status == "True")
    };

    let lp = ListParams::default().fields(&format!("metadata.name={}", job.name()));
    let jobs = client.get_api::<Job>(job.namespace().as_deref());
    let watcher = runtime::watcher(jobs, lp).boxed();
    runtime::utils::try_flatten_applied(watcher)
        .any(|res| future::ready(res.as_ref().map(|job| completed(job)).unwrap_or(false)))
        .await;
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

impl ReconciliationState for SupersetState {
    type Error = error::Error;

    fn reconcile(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<ReconcileFunctionAction, Self::Error>> + Send + '_>>
    {
        info!("========================= Starting reconciliation =========================");

        Box::pin(async move {
            self.init_status()
                .await?
                .then(self.context.handle_deletion(
                    Box::pin(self.delete_all_pods()),
                    FINALIZER_NAME,
                    true,
                ))
                .await?
                .then(self.context.delete_illegal_pods(
                    self.existing_pods.as_slice(),
                    &self.get_required_labels(),
                    ContinuationStrategy::OneRequeue,
                ))
                .await?
                .then(
                    self.context
                        .wait_for_terminating_pods(self.existing_pods.as_slice()),
                )
                .await?
                .then(
                    self.context
                        .wait_for_running_and_ready_pods(&self.existing_pods),
                )
                .await?
                .then(self.process_command())
                .await?
                .then(self.context.delete_excess_pods(
                    list_eligible_nodes_for_role_and_group(&self.eligible_nodes).as_slice(),
                    &self.existing_pods,
                    ContinuationStrategy::OneRequeue,
                ))
                .await?
                .then(self.create_missing_pods())
                .await
        })
    }
}

struct SupersetStrategy {
    config: Arc<ProductConfigManager>,
}

impl SupersetStrategy {
    pub fn new(config: ProductConfigManager) -> SupersetStrategy {
        SupersetStrategy {
            config: Arc::new(config),
        }
    }
}

#[async_trait]
impl ControllerStrategy for SupersetStrategy {
    type Item = SupersetCluster;
    type State = SupersetState;
    type Error = Error;

    /// Init the Superset state. Store all available pods owned by this cluster for later processing.
    /// Retrieve nodes that fit selectors and store them for later processing:
    /// SupersetRole (we only have 'node') -> role group -> list of nodes.
    async fn init_reconcile_state(
        &self,
        context: ReconciliationContext<Self::Item>,
    ) -> Result<Self::State, Self::Error> {
        let existing_pods = context
            .list_owned(build_common_labels_for_all_managed_resources(
                APP_NAME,
                &context.resource.name(),
            ))
            .await?;
        trace!(
            "{}: Found [{}] pods",
            context.log_name(),
            existing_pods.len()
        );

        let superset_spec: SupersetClusterSpec = context.resource.spec.clone();

        let mut eligible_nodes = HashMap::new();

        eligible_nodes.insert(
            SupersetRole::Node.to_string(),
            find_nodes_that_fit_selectors(&context.client, None, &superset_spec.nodes).await?,
        );

        let mut roles = HashMap::new();
        roles.insert(
            SupersetRole::Node.to_string(),
            (
                vec![PropertyNameKind::Env],
                context.resource.spec.nodes.clone().into(),
            ),
        );

        let role_config = transform_all_roles_to_config(&context.resource, roles);
        let validated_role_config = validate_all_roles_and_groups_config(
            &context.resource.spec.version.to_string(),
            &role_config,
            &self.config,
            false,
            false,
        )?;

        Ok(SupersetState {
            context,
            existing_pods,
            eligible_nodes,
            validated_role_config,
        })
    }
}

/// This creates an instance of a [`Controller`] which waits for incoming events and reconciles them.
///
/// This is an async method and the returned future needs to be consumed to make progress.
pub async fn create_controller(client: Client, product_config_path: &str) -> OperatorResult<()> {
    let api: Api<SupersetCluster> = client.get_all_api();
    let pods_api: Api<Pod> = client.get_all_api();
    let cmd_init_api: Api<Init> = client.get_all_api();
    let cmd_restart_api: Api<Restart> = client.get_all_api();
    let cmd_start_api: Api<Start> = client.get_all_api();
    let cmd_stop_api: Api<Stop> = client.get_all_api();

    let controller = Controller::new(api)
        .owns(pods_api, ListParams::default())
        .owns(cmd_init_api, ListParams::default())
        .owns(cmd_restart_api, ListParams::default())
        .owns(cmd_start_api, ListParams::default())
        .owns(cmd_stop_api, ListParams::default());

    let product_config = ProductConfigManager::from_yaml_file(product_config_path).unwrap();

    let strategy = SupersetStrategy::new(product_config);

    controller
        .run(client, strategy, Duration::from_secs(10))
        .await;

    Ok(())
}
