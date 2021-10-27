mod error;
use crate::error::Error;
use stackable_operator::k8s_openapi::api::batch::v1::{Job, JobSpec};
use serde::Serialize;
use stackable_operator::command_controller::Command;
use stackable_superset_crd::commands::{Init, Restart, Start, Stop};

use async_trait::async_trait;
use stackable_operator::k8s_openapi::api::core::v1::{
    ConfigMap, Container, EnvVar, EnvVarSource, Pod, PodSpec, PodTemplateSpec, Secret,
    SecretKeySelector, SecretVolumeSource, Volume, VolumeMount,
};
use stackable_operator::kube::api::{ListParams, ResourceExt};
use stackable_operator::kube::Api;
use stackable_operator::kube::CustomResourceExt;
use stackable_operator::product_config::types::PropertyNameKind;
use stackable_operator::product_config::ProductConfigManager;
use stackable_operator::builder::{
    ContainerBuilder, ContainerPortBuilder, ObjectMetaBuilder, PodBuilder,
};
use stackable_operator::client::Client;
use stackable_operator::command::{clear_current_command, materialize_command};
use stackable_operator::configmap;
use stackable_operator::controller::Controller;
use stackable_operator::controller::{ControllerStrategy, ReconciliationState};
use stackable_operator::error::OperatorResult;
use stackable_operator::identity::{LabeledPodIdentityFactory, PodIdentity, PodToNodeMapping};
use stackable_operator::labels;
use stackable_operator::labels::{
    build_common_labels_for_all_managed_resources, get_recommended_labels,
};
use stackable_operator::name_utils;
use stackable_operator::product_config_utils::{
    config_for_role_and_group, transform_all_roles_to_config, validate_all_roles_and_groups_config,
    ValidatedRoleConfigByPropertyKind,
};
use stackable_operator::reconcile::{
    ContinuationStrategy, ReconcileFunctionAction, ReconcileResult, ReconciliationContext,
};
use stackable_operator::role_utils::{
    get_role_and_group_labels, list_eligible_nodes_for_role_and_group, EligibleNodesAndReplicas,
    EligibleNodesForRoleAndGroup, Role,
};
use stackable_operator::scheduler::{
    K8SUnboundedHistory, RoleGroupEligibleNodes, ScheduleStrategy, Scheduler, StickyScheduler,
};
use stackable_operator::status::HasClusterExecutionStatus;
use stackable_operator::status::{init_status, ClusterExecutionStatus};
use stackable_operator::versioning::{finalize_versioning, init_versioning};
use stackable_superset_crd::{
    SupersetCluster, SupersetClusterSpec, SupersetRole, SupersetVersion, APP_NAME,
    CONFIG_MAP_TYPE_DATA, CONFIG_MAP_TYPE_ID, HTTP_PORT,
};
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use strum::IntoEnumIterator;
use tracing::error;
use tracing::{debug, info, trace, warn};

const FINALIZER_NAME: &str = "superset.stackable.tech/cleanup";
const ID_LABEL: &str = "superset.stackable.tech/id";
const SHOULD_BE_SCRAPED: &str = "monitoring.stackable.tech/should_be_scraped";

// TODO: adapt to Superset/.. config files
// const PROPERTIES_FILE: &str = "zoo.cfg";
// const CONFIG_DIR_NAME: &str = "conf";

const IMAGE: &str = "apache/superset:latest";

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
        // - Roles (Metastore)
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

                        let config_maps = self
                            .create_config_maps(pod_id, validated_config, &state.mapping())
                            .await?;

                        self.create_pod(pod_id, &node_id.name, &config_maps, validated_config)
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

    /// Creates the config maps required for a superset instance (or role, role_group combination):
    /// * The 'zoo.cfg' properties file
    /// * The 'myid' file
    ///
    /// The 'zoo.cfg' properties are read from the product_config and/or merged with the cluster
    /// custom resource.
    ///
    /// Labels are automatically adapted from the `recommended_labels` with a type (data for
    /// 'zoo.cfg' and id for 'myid'). Names are generated via `name_utils::build_resource_name`.
    ///
    /// Returns a map with a 'type' identifier (e.g. data, id) as key and the corresponding
    /// ConfigMap as value. This is required to set the volume mounts in the pod later on.
    ///
    /// # Arguments
    ///
    /// - `pod_id` - The `PodIdentity` containing app, instance, role, group names and the id.
    /// - `validated_config` - The validated product config.
    /// - `id_mapping` - All id to node mappings required to create config maps
    ///
    async fn create_config_maps(
        &self,
        pod_id: &PodIdentity,
        validated_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
        id_mapping: &PodToNodeMapping,
    ) -> Result<HashMap<&'static str, ConfigMap>, Error> {
        Ok(HashMap::new())
    }

    /// Creates the pod required for the superset instance.
    ///
    /// # Arguments
    ///
    /// - `pod_id` - The `PodIdentity` containing app, instance, role, group names and the id.
    /// - `node_name` - The node_name for this pod.
    /// - `config_maps` - The config maps and respective types required for this pod.
    /// - `validated_config` - The validated product config.
    ///
    async fn create_pod(
        &self,
        pod_id: &PodIdentity,
        node_name: &str,
        config_maps: &HashMap<&'static str, ConfigMap>,
        validated_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    ) -> Result<Pod, Error> {
        let http_port = Some(String::from("8088"));

        let version: &SupersetVersion = &self.context.resource.spec.version;

        let mut cb = ContainerBuilder::new(APP_NAME);
        cb.image(IMAGE);

        let pod_name = name_utils::build_resource_name(
            pod_id.app(),
            &self.context.name(),
            pod_id.role(),
            Some(pod_id.group()),
            Some(node_name),
            None,
        )?;

        let annotations = BTreeMap::new();

        if let Some(http_port) = http_port {
            cb.add_container_port(
                ContainerPortBuilder::new(http_port.parse()?)
                    .name(HTTP_PORT)
                    .build(),
            );
        }

        let mut recommended_labels = get_recommended_labels(
            &self.context.resource,
            pod_id.app(),
            &version.to_string(),
            pod_id.role(),
            pod_id.group(),
        );
        recommended_labels.insert(ID_LABEL.to_string(), pod_id.id().to_string());

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
            .add_container(cb.build())
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

        // TODO Make names unique

        let job_name = format!("{}-init-db", command.name());

        // TODO Move commands into init script
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

        let env_var_from_secret = |var_name, secret_key| EnvVar {
            name: String::from(var_name),
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    name: Some(command.spec.credentials_secret.clone()),
                    key: String::from(secret_key),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let pod = PodTemplateSpec {
            metadata: Some(ObjectMetaBuilder::new().name(&job_name).build()?),
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: job_name.clone(),
                    image: Some(String::from(IMAGE)),
                    command: Some(vec![String::from("/bin/sh")]),
                    args: Some(vec![String::from("-c"), commands.join("; ")]),
                    env: Some(vec![
                        env_var_from_secret("ADMIN_USERNAME", "adminUser.username"),
                        env_var_from_secret("ADMIN_FIRSTNAME", "adminUser.firstname"),
                        env_var_from_secret("ADMIN_LASTNAME", "adminUser.lastname"),
                        env_var_from_secret("ADMIN_EMAIL", "adminUser.email"),
                        env_var_from_secret("ADMIN_PASSWORD", "adminUser.password"),
                    ]),
                    ..Default::default()
                }],
                restart_policy: Some(String::from("Never")),
                ..Default::default()
            }),
        };

        let job = Job {
            metadata: ObjectMetaBuilder::new()
                .name(&job_name)
                .namespace(&self.context.client.default_namespace)
                .build()?,
            spec: Some(JobSpec {
                template: pod,
                ..Default::default()
            }),
            status: None,
        };

        client.create(&job).await?;

        clear_current_command(client, resource).await?;

        let patch = command.finish_patch();
        client.merge_patch_status(command, &patch).await?;

        Ok(ReconcileFunctionAction::Done)
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
    /// SupersetRole (we only have 'server') -> role group -> list of nodes.
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
            find_nodes_that_fit_selectors(&context.client, None, &superset_spec.servers).await?,
        );

        let mut roles = HashMap::new();
        roles.insert(
            SupersetRole::Node.to_string(),
            (vec![], context.resource.spec.servers.clone().into()),
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

/// Return a map where the key corresponds to the role_group (e.g. "default", "10core10Gb") and
/// a tuple of a vector of nodes that fit the role_groups selector description, and the role_groups
/// "replicas" field for scheduling missing pods or removing excess pods.
pub async fn find_nodes_that_fit_selectors<T>(
    client: &Client,
    namespace: Option<String>,
    role: &Role<T>,
) -> OperatorResult<HashMap<String, EligibleNodesAndReplicas>>
where
    T: Serialize,
{
    let mut found_nodes = HashMap::new();
    for (group_name, role_group) in &role.role_groups {
        let selector = role_group.selector.to_owned().unwrap_or_default(); // krustlet::add_stackable_selector(role_group.selector.as_ref());
        let nodes = client
            .list_with_label_selector(namespace.as_deref(), &selector)
            .await?;
        debug!(
            "Found [{}] nodes for role group [{}]: [{:?}]",
            nodes.len(),
            group_name,
            nodes
        );
        found_nodes.insert(
            group_name.clone(),
            EligibleNodesAndReplicas {
                nodes,
                replicas: role_group.replicas,
            },
        );
    }
    Ok(found_nodes)
}

/// This creates an instance of a [`Controller`] which waits for incoming events and reconciles them.
///
/// This is an async method and the returned future needs to be consumed to make progress.
pub async fn create_controller(client: Client, product_config_path: &str) -> OperatorResult<()> {
    if let Err(error) = stackable_operator::crd::wait_until_crds_present(
        &client,
        vec![
            SupersetCluster::crd_name(),
            Restart::crd_name(),
            Start::crd_name(),
            Stop::crd_name(),
        ],
        None,
    )
    .await
    {
        error!("Required CRDs missing, aborting: {:?}", error);
        return Err(error);
    };

    let api: Api<SupersetCluster> = client.get_all_api();
    let pods_api: Api<Pod> = client.get_all_api();
    let config_maps_api: Api<ConfigMap> = client.get_all_api();
    let cmd_restart_api: Api<Restart> = client.get_all_api();
    let cmd_start_api: Api<Start> = client.get_all_api();
    let cmd_stop_api: Api<Stop> = client.get_all_api();

    let controller = Controller::new(api)
        .owns(pods_api, ListParams::default())
        .owns(config_maps_api, ListParams::default())
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
