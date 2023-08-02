//! Ensures that `Pod`s are configured and running for each [`SupersetCluster`]

use stackable_operator::builder::resources::ResourceRequirementsBuilder;
use stackable_operator::k8s_openapi::DeepMerge;

use crate::util::build_recommended_labels;
use crate::{
    config::{self, PYTHON_IMPORTS},
    controller_commons::{self, CONFIG_VOLUME_NAME, LOG_CONFIG_VOLUME_NAME, LOG_VOLUME_NAME},
    product_logging::{
        extend_config_map_with_log_config, resolve_vector_aggregator_address, LOG_CONFIG_FILE,
    },
    APP_PORT, OPERATOR_NAME,
};

use indoc::formatdoc;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder,
        PodSecurityContextBuilder,
    },
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    commons::{
        authentication::AuthenticationClassProvider, product_image_selection::ResolvedProductImage,
        rbac::build_rbac_resources,
    },
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{ConfigMap, Service, ServicePort, ServiceSpec},
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    kube::{
        runtime::{controller::Action, reflector::ObjectRef},
        Resource, ResourceExt,
    },
    labels::{role_group_selector_labels, role_selector_labels},
    logging::controller::ReconcilerError,
    product_config::{
        flask_app_config_writer::{self, FlaskAppConfigWriterError},
        types::PropertyNameKind,
        ProductConfigManager,
    },
    product_config_utils::{transform_all_roles_to_config, validate_all_roles_and_groups_config},
    product_logging::{self, spec::Logging},
    role_utils::RoleGroupRef,
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder, ClusterCondition, ClusterConditionSet,
        ClusterConditionStatus, ClusterConditionType, ConditionBuilder,
    },
};
use stackable_superset_crd::authentication::SuperSetAuthenticationConfigResolved;
use stackable_superset_crd::supersetdb::SupersetDBStatus;
use stackable_superset_crd::SupersetClusterStatus;
use stackable_superset_crd::{
    supersetdb::{SupersetDB, SupersetDBStatusCondition},
    Container, SupersetCluster, SupersetConfig, SupersetConfigOptions, SupersetRole, APP_NAME,
    CONFIG_DIR, LOG_CONFIG_DIR, LOG_DIR, PYTHONPATH, SUPERSET_CONFIG_FILENAME,
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};

pub const SUPERSET_CONTROLLER_NAME: &str = "supersetcluster";
pub const DOCKER_IMAGE_BASE_NAME: &str = "superset";

const METRICS_PORT_NAME: &str = "metrics";
const METRICS_PORT: i32 = 9102;

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub product_config: ProductConfigManager,
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object has no namespace"))]
    ObjectHasNoNamespace,
    #[snafu(display("object defines no node role"))]
    NoNodeRole,
    #[snafu(display("failed to calculate global service name"))]
    GlobalServiceNameNotFound,
    #[snafu(display("invalid container name"))]
    InvalidContainerName {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to create cluster resources"))]
    CreateClusterResources {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to apply global Service"))]
    ApplyRoleService {
        source: stackable_operator::error::Error,
    },

    #[snafu(display("failed to retrieve superset db"))]
    SupersetDBRetrieval {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("superset db {superset_db} initialization failed, not starting superset"))]
    SupersetDBFailed { superset_db: ObjectRef<SupersetDB> },
    #[snafu(display("failed to apply Superset DB"))]
    CreateSupersetObject {
        source: stackable_superset_crd::supersetdb::Error,
    },
    #[snafu(display("failed to apply Superset DB"))]
    ApplySupersetDB {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to apply Service for {rolegroup}"))]
    ApplyRoleGroupService {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },
    #[snafu(display("failed to build config file for {rolegroup}"))]
    BuildRoleGroupConfigFile {
        source: FlaskAppConfigWriterError,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },
    #[snafu(display("failed to build ConfigMap for {rolegroup}"))]
    BuildRoleGroupConfig {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },
    #[snafu(display("failed to apply ConfigMap for {rolegroup}"))]
    ApplyRoleGroupConfig {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },
    #[snafu(display("failed to apply StatefulSet for {rolegroup}"))]
    ApplyRoleGroupStatefulSet {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },
    #[snafu(display("failed to generate product config"))]
    GenerateProductConfig {
        source: stackable_operator::product_config_utils::ConfigError,
    },
    #[snafu(display("invalid product config"))]
    InvalidProductConfig {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to apply authentication configuration"))]
    InvalidAuthenticationConfig {
        source: stackable_superset_crd::authentication::Error,
    },
    #[snafu(display(
        "failed to get the {SUPERSET_CONFIG_FILENAME} file from node or product config"
    ))]
    MissingSupersetConfigInNodeConfig,
    #[snafu(display("failed to get {timeout} from {SUPERSET_CONFIG_FILENAME} file. It should be set in the product config or by user input", timeout = SupersetConfigOptions::SupersetWebserverTimeout))]
    MissingWebServerTimeoutInSupersetConfig,
    #[snafu(display("failed to resolve and merge config for role and role group"))]
    FailedToResolveConfig {
        source: stackable_superset_crd::Error,
    },
    #[snafu(display("failed to resolve the Vector aggregator address"))]
    ResolveVectorAggregatorAddress {
        source: crate::product_logging::Error,
    },
    #[snafu(display("failed to add the logging configuration to the ConfigMap [{cm_name}]"))]
    InvalidLoggingConfig {
        source: crate::product_logging::Error,
        cm_name: String,
    },
    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to patch service account"))]
    ApplyServiceAccount {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to patch role binding"))]
    ApplyRoleBinding {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to build RBAC objects"))]
    BuildRBACObjects {
        source: stackable_operator::error::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub async fn reconcile_superset(superset: Arc<SupersetCluster>, ctx: Arc<Ctx>) -> Result<Action> {
    tracing::info!("Starting reconcile");

    let client = &ctx.client;
    let resolved_product_image: ResolvedProductImage = superset
        .spec
        .image
        .resolve(DOCKER_IMAGE_BASE_NAME, crate::built_info::CARGO_PKG_VERSION);
    let superset_role = SupersetRole::Node;

    let cluster_operation_cond_builder =
        ClusterOperationsConditionBuilder::new(&superset.spec.cluster_config.cluster_operation);

    if wait_for_db_and_update_status(
        client,
        &superset,
        &resolved_product_image,
        &cluster_operation_cond_builder,
    )
    .await?
    {
        return Ok(Action::await_change());
    }

    let vector_aggregator_address = resolve_vector_aggregator_address(
        client,
        superset.as_ref(),
        superset
            .spec
            .cluster_config
            .vector_aggregator_config_map_name
            .as_deref(),
    )
    .await
    .context(ResolveVectorAggregatorAddressSnafu)?;

    let authentication_config = superset
        .spec
        .cluster_config
        .authentication
        .resolve(client)
        .await
        .context(InvalidAuthenticationConfigSnafu)?;

    let validated_config = validate_all_roles_and_groups_config(
        &resolved_product_image.product_version,
        &transform_all_roles_to_config(
            superset.as_ref(),
            [(
                superset_role.to_string(),
                (
                    vec![
                        PropertyNameKind::Env,
                        PropertyNameKind::File(SUPERSET_CONFIG_FILENAME.into()),
                    ],
                    superset.spec.nodes.clone().context(NoNodeRoleSnafu)?,
                ),
            )]
            .into(),
        )
        .context(GenerateProductConfigSnafu)?,
        &ctx.product_config,
        false,
        false,
    )
    .context(InvalidProductConfigSnafu)?;

    let role_node_config = validated_config
        .get(superset_role.to_string().as_str())
        .map(Cow::Borrowed)
        .unwrap_or_default();

    let mut cluster_resources = ClusterResources::new(
        APP_NAME,
        OPERATOR_NAME,
        SUPERSET_CONTROLLER_NAME,
        &superset.object_ref(&()),
        ClusterResourceApplyStrategy::from(&superset.spec.cluster_config.cluster_operation),
    )
    .context(CreateClusterResourcesSnafu)?;

    let (rbac_sa, rbac_rolebinding) = build_rbac_resources(
        superset.as_ref(),
        APP_NAME,
        cluster_resources.get_required_labels(),
    )
    .context(BuildRBACObjectsSnafu)?;

    let rbac_sa = cluster_resources
        .add(client, rbac_sa)
        .await
        .context(ApplyServiceAccountSnafu)?;
    cluster_resources
        .add(client, rbac_rolebinding)
        .await
        .context(ApplyRoleBindingSnafu)?;

    let node_role_service = build_node_role_service(&superset, &resolved_product_image)?;
    cluster_resources
        .add(client, node_role_service)
        .await
        .context(ApplyRoleServiceSnafu)?;

    let mut ss_cond_builder = StatefulSetConditionBuilder::default();

    for (rolegroup_name, rolegroup_config) in role_node_config.iter() {
        let rolegroup = superset.node_rolegroup_ref(rolegroup_name);

        let config = superset
            .merged_config(&SupersetRole::Node, &rolegroup)
            .context(FailedToResolveConfigSnafu)?;

        let rg_service =
            build_node_rolegroup_service(&superset, &resolved_product_image, &rolegroup)?;
        let rg_configmap = build_rolegroup_config_map(
            &superset,
            &resolved_product_image,
            &rolegroup,
            rolegroup_config,
            &authentication_config,
            &config.logging,
            vector_aggregator_address.as_deref(),
        )?;
        let rg_statefulset = build_server_rolegroup_statefulset(
            &superset,
            &resolved_product_image,
            &superset_role,
            &rolegroup,
            rolegroup_config,
            &authentication_config,
            &rbac_sa.name_any(),
            &config,
        )?;
        cluster_resources
            .add(client, rg_service)
            .await
            .with_context(|_| ApplyRoleGroupServiceSnafu {
                rolegroup: rolegroup.clone(),
            })?;
        cluster_resources
            .add(client, rg_configmap)
            .await
            .with_context(|_| ApplyRoleGroupConfigSnafu {
                rolegroup: rolegroup.clone(),
            })?;
        ss_cond_builder.add(
            cluster_resources
                .add(client, rg_statefulset.clone())
                .await
                .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                    rolegroup: rolegroup.clone(),
                })?,
        );
    }

    cluster_resources
        .delete_orphaned_resources(client)
        .await
        .context(DeleteOrphanedResourcesSnafu)?;

    let status = SupersetClusterStatus {
        conditions: compute_conditions(
            superset.as_ref(),
            &[&ss_cond_builder, &cluster_operation_cond_builder],
        ),
    };
    client
        .apply_patch_status(OPERATOR_NAME, &*superset, &status)
        .await
        .context(ApplyStatusSnafu)?;

    Ok(Action::await_change())
}

/// The server-role service is the primary endpoint that should be used by clients that do not perform internal load balancing,
/// including targets outside of the cluster.
fn build_node_role_service(
    superset: &SupersetCluster,
    resolved_product_image: &ResolvedProductImage,
) -> Result<Service> {
    let role_name = SupersetRole::Node.to_string();
    let role_svc_name = superset
        .node_role_service_name()
        .context(GlobalServiceNameNotFoundSnafu)?;
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(superset)
            .name(format!("{}-external", &role_svc_name))
            .ownerreference_from_resource(superset, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                superset,
                SUPERSET_CONTROLLER_NAME,
                &resolved_product_image.app_version_label,
                &role_name,
                "global",
            ))
            .build(),
        spec: Some(ServiceSpec {
            type_: Some(
                superset
                    .spec
                    .cluster_config
                    .listener_class
                    .k8s_service_type(),
            ),
            ports: Some(vec![ServicePort {
                name: Some("superset".to_string()),
                port: APP_PORT.into(),
                protocol: Some("TCP".to_string()),
                ..ServicePort::default()
            }]),
            selector: Some(role_selector_labels(superset, APP_NAME, &role_name)),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
fn build_rolegroup_config_map(
    superset: &SupersetCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup: &RoleGroupRef<SupersetCluster>,
    rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    authentication_config: &Vec<SuperSetAuthenticationConfigResolved>,
    logging: &Logging<Container>,
    vector_aggregator_address: Option<&str>,
) -> Result<ConfigMap, Error> {
    let mut config = rolegroup_config
        .get(&PropertyNameKind::File(
            SUPERSET_CONFIG_FILENAME.to_string(),
        ))
        .cloned()
        .unwrap_or_default();

    config::add_superset_config(&mut config, authentication_config);

    let mut config_file = Vec::new();
    flask_app_config_writer::write::<SupersetConfigOptions, _, _>(
        &mut config_file,
        config.iter(),
        PYTHON_IMPORTS,
    )
    .with_context(|_| BuildRoleGroupConfigFileSnafu {
        rolegroup: rolegroup.clone(),
    })?;

    let mut cm_builder = ConfigMapBuilder::new();

    cm_builder
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(superset)
                .name(rolegroup.object_name())
                .ownerreference_from_resource(superset, None, Some(true))
                .context(ObjectMissingMetadataForOwnerRefSnafu)?
                .with_recommended_labels(build_recommended_labels(
                    superset,
                    SUPERSET_CONTROLLER_NAME,
                    &resolved_product_image.app_version_label,
                    &rolegroup.role,
                    &rolegroup.role_group,
                ))
                .build(),
        )
        .add_data(
            SUPERSET_CONFIG_FILENAME,
            String::from_utf8(config_file).unwrap(),
        );

    extend_config_map_with_log_config(
        rolegroup,
        vector_aggregator_address,
        logging,
        &Container::Superset,
        &Container::Vector,
        &mut cm_builder,
    )
    .context(InvalidLoggingConfigSnafu {
        cm_name: rolegroup.object_name(),
    })?;

    cm_builder
        .build()
        .with_context(|_| BuildRoleGroupConfigSnafu {
            rolegroup: rolegroup.clone(),
        })
}

/// The rolegroup [`Service`] is a headless service that allows direct access to the instances of a certain rolegroup
///
/// This is mostly useful for internal communication between peers, or for clients that perform client-side load balancing.
fn build_node_rolegroup_service(
    superset: &SupersetCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup: &RoleGroupRef<SupersetCluster>,
) -> Result<Service> {
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(superset)
            .name(&rolegroup.object_name())
            .ownerreference_from_resource(superset, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                superset,
                SUPERSET_CONTROLLER_NAME,
                &resolved_product_image.app_version_label,
                &rolegroup.role,
                &rolegroup.role_group,
            ))
            .with_label("prometheus.io/scrape", "true")
            .build(),
        spec: Some(ServiceSpec {
            // Internal communication does not need to be exposed
            type_: Some("ClusterIP".to_string()),
            cluster_ip: Some("None".to_string()),
            ports: Some(vec![
                ServicePort {
                    name: Some("superset".to_string()),
                    port: APP_PORT.into(),
                    protocol: Some("TCP".to_string()),
                    ..ServicePort::default()
                },
                ServicePort {
                    name: Some(METRICS_PORT_NAME.into()),
                    port: METRICS_PORT,
                    protocol: Some("TCP".to_string()),
                    ..ServicePort::default()
                },
            ]),
            selector: Some(role_group_selector_labels(
                superset,
                APP_NAME,
                &rolegroup.role,
                &rolegroup.role_group,
            )),
            publish_not_ready_addresses: Some(true),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

/// The rolegroup [`StatefulSet`] runs the rolegroup, as configured by the administrator.
///
/// The [`Pod`](`stackable_operator::k8s_openapi::api::core::v1::Pod`)s are accessible through the corresponding [`Service`] (from [`build_node_rolegroup_service`]).
#[allow(clippy::too_many_arguments)]
fn build_server_rolegroup_statefulset(
    superset: &SupersetCluster,
    resolved_product_image: &ResolvedProductImage,
    superset_role: &SupersetRole,
    rolegroup_ref: &RoleGroupRef<SupersetCluster>,
    node_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    authentication_config: &Vec<SuperSetAuthenticationConfigResolved>,
    sa_name: &str,
    merged_config: &SupersetConfig,
) -> Result<StatefulSet> {
    let role = superset.get_role(superset_role).context(NoNodeRoleSnafu)?;
    let role_group = role
        .role_groups
        .get(&rolegroup_ref.role_group)
        .context(NoNodeRoleSnafu)?;

    let mut pb = PodBuilder::new();
    pb.metadata_builder(|m| {
        m.with_recommended_labels(build_recommended_labels(
            superset,
            SUPERSET_CONTROLLER_NAME,
            &resolved_product_image.app_version_label,
            &rolegroup_ref.role,
            &rolegroup_ref.role_group,
        ))
    })
    .image_pull_secrets_from_product_image(resolved_product_image)
    .security_context(
        PodSecurityContextBuilder::new()
            .run_as_user(1000)
            .run_as_group(0)
            .fs_group(1000) // Needed for secret-operator
            .build(),
    )
    .affinity(&merged_config.affinity)
    .service_account_name(sa_name)
    .build_template();

    let mut superset_cb = ContainerBuilder::new(&Container::Superset.to_string())
        .context(InvalidContainerNameSnafu)?;

    for (name, value) in node_config
        .get(&PropertyNameKind::Env)
        .cloned()
        .unwrap_or_default()
    {
        if name == SupersetConfig::CREDENTIALS_SECRET_PROPERTY {
            superset_cb.add_env_var_from_secret("SECRET_KEY", &value, "connections.secretKey");
            superset_cb.add_env_var_from_secret(
                "SQLALCHEMY_DATABASE_URI",
                &value,
                "connections.sqlalchemyDatabaseUri",
            );
        } else if name == SupersetConfig::MAPBOX_SECRET_PROPERTY {
            superset_cb.add_env_var_from_secret(
                "MAPBOX_API_KEY",
                &value,
                "connections.mapboxApiKey",
            );
        } else {
            superset_cb.add_env_var(name, value);
        };
    }

    add_authentication_volumes_and_volume_mounts(authentication_config, &mut superset_cb, &mut pb);

    let webserver_timeout = node_config
        .get(&PropertyNameKind::File(
            SUPERSET_CONFIG_FILENAME.to_string(),
        ))
        .context(MissingSupersetConfigInNodeConfigSnafu)?
        .get(&SupersetConfigOptions::SupersetWebserverTimeout.to_string())
        .context(MissingWebServerTimeoutInSupersetConfigSnafu)?;

    superset_cb
        .image_from_product_image(resolved_product_image)
        .add_container_port("http", APP_PORT.into())
        .add_volume_mount(CONFIG_VOLUME_NAME, CONFIG_DIR)
        .add_volume_mount(LOG_CONFIG_VOLUME_NAME, LOG_CONFIG_DIR)
        .add_volume_mount(LOG_VOLUME_NAME, LOG_DIR)
        .command(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            formatdoc! {"
                mkdir --parents {PYTHONPATH} && \
                cp {CONFIG_DIR}/* {PYTHONPATH} && \
                cp {LOG_CONFIG_DIR}/{LOG_CONFIG_FILE} {PYTHONPATH} && \
                superset init && \
                gunicorn \
                --bind 0.0.0.0:${{SUPERSET_PORT}} \
                --worker-class gthread \
                --threads 20 \
                --timeout {webserver_timeout} \
                --limit-request-line 0 \
                --limit-request-field_size 0 \
                'superset.app:create_app()'
            "},
        ])
        .resources(merged_config.resources.clone().into());

    pb.add_container(superset_cb.build());

    let metrics_container = ContainerBuilder::new("metrics")
        .context(InvalidContainerNameSnafu)?
        .image_from_product_image(resolved_product_image)
        .command(vec!["/bin/bash".to_string(), "-c".to_string()])
        .args(vec!["/stackable/statsd_exporter".to_string()])
        .add_container_port(METRICS_PORT_NAME, METRICS_PORT)
        .resources(
            ResourceRequirementsBuilder::new()
                .with_cpu_request("100m")
                .with_cpu_limit("200m")
                .with_memory_request("64Mi")
                .with_memory_limit("64Mi")
                .build(),
        )
        .build();

    pb.add_volumes(controller_commons::create_volumes(
        &rolegroup_ref.object_name(),
        merged_config.logging.containers.get(&Container::Superset),
    ));
    pb.add_container(metrics_container);

    if merged_config.logging.enable_vector_agent {
        pb.add_container(product_logging::framework::vector_container(
            resolved_product_image,
            CONFIG_VOLUME_NAME,
            LOG_VOLUME_NAME,
            merged_config.logging.containers.get(&Container::Vector),
            ResourceRequirementsBuilder::new()
                .with_cpu_request("250m")
                .with_cpu_limit("500m")
                .with_memory_request("128Mi")
                .with_memory_limit("128Mi")
                .build(),
        ));
    }

    let mut pod_template = pb.build_template();
    pod_template.merge_from(role.config.pod_overrides.clone());
    pod_template.merge_from(role_group.config.pod_overrides.clone());

    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(superset)
            .name(&rolegroup_ref.object_name())
            .ownerreference_from_resource(superset, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(build_recommended_labels(
                superset,
                SUPERSET_CONTROLLER_NAME,
                &resolved_product_image.app_version_label,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
            ))
            .with_label("restarter.stackable.tech/enabled", "true")
            .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some("Parallel".to_string()),
            replicas: role_group.replicas.map(i32::from),
            selector: LabelSelector {
                match_labels: Some(role_group_selector_labels(
                    superset,
                    APP_NAME,
                    &rolegroup_ref.role,
                    &rolegroup_ref.role_group,
                )),
                ..LabelSelector::default()
            },
            service_name: rolegroup_ref.object_name(),
            template: pod_template,
            ..StatefulSetSpec::default()
        }),
        status: None,
    })
}

fn add_authentication_volumes_and_volume_mounts(
    authentication_config: &Vec<SuperSetAuthenticationConfigResolved>,
    cb: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) {
    // TODO: Currently there can be only one AuthenticationClass due to FlaskAppBuilder restrictions.
    //    Needs adaptation once FAB and superset support multiple auth methods.
    // The checks for max one AuthenticationClass and the provider are done in crd/src/authentication.rs
    for config in authentication_config {
        if let Some(auth_class) = &config.authentication_class {
            match &auth_class.spec.provider {
                AuthenticationClassProvider::Ldap(ldap) => {
                    ldap.add_volumes_and_mounts(pb, vec![cb]);
                }
                AuthenticationClassProvider::Tls(_) | AuthenticationClassProvider::Static(_) => {}
            }
        }
    }
}

pub fn error_policy(_obj: Arc<SupersetCluster>, _error: &Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(5))
}

/// Return true if the controller should wait for the DB to be set up.
///
/// As a side-effect, the Superset cluster status is updated as long as the controller waits
/// for the DB to come up.
///
/// Having the DB set up by a Job managed by a different controller has it's own
/// set of problems as described here: <https://github.com/stackabletech/superset-operator/issues/351>.
/// The Airflow operator uses the same pattern as implemented here for setting up the DB.
///
/// When the ticket above is implemented, this function will most likely be removed completely.
async fn wait_for_db_and_update_status(
    client: &stackable_operator::client::Client,
    superset: &SupersetCluster,
    resolved_product_image: &ResolvedProductImage,
    cluster_operation_condition_builder: &ClusterOperationsConditionBuilder<'_>,
) -> Result<bool> {
    // Ensure DB Schema exists
    let superset_db = SupersetDB::for_superset(superset, resolved_product_image)
        .context(CreateSupersetObjectSnafu)?;
    client
        .apply_patch(SUPERSET_CONTROLLER_NAME, &superset_db, &superset_db)
        .await
        .context(ApplySupersetDBSnafu)?;

    let superset_db = client
        .get::<SupersetDB>(
            &superset.name_unchecked(),
            superset
                .namespace()
                .as_deref()
                .context(ObjectHasNoNamespaceSnafu)?,
        )
        .await
        .context(SupersetDBRetrievalSnafu)?;

    tracing::debug!("{}", format!("Checking status: {:#?}", superset_db.status));

    // Update the Superset cluster status, only if the controller needs to wait.
    // This avoids updating the status twice per reconcile call. when the DB
    // has a ready condition.
    let db_cond_builder = DbConditionBuilder(superset_db.status);
    if bool::from(&db_cond_builder) {
        let status = SupersetClusterStatus {
            conditions: compute_conditions(
                superset,
                &[&db_cond_builder, cluster_operation_condition_builder],
            ),
        };

        client
            .apply_patch_status(OPERATOR_NAME, superset, &status)
            .await
            .context(ApplyStatusSnafu)?;
    }

    Ok(bool::from(&db_cond_builder))
}

struct DbConditionBuilder(Option<SupersetDBStatus>);
impl ConditionBuilder for DbConditionBuilder {
    fn build_conditions(&self) -> ClusterConditionSet {
        let (status, message) = if let Some(ref status) = self.0 {
            match status.condition {
                SupersetDBStatusCondition::Pending | SupersetDBStatusCondition::Initializing => (
                    ClusterConditionStatus::False,
                    "Waiting for SupersetDB initialization to complete",
                ),
                SupersetDBStatusCondition::Failed => (
                    ClusterConditionStatus::False,
                    "Superset database initialization failed.",
                ),
                SupersetDBStatusCondition::Ready => (
                    ClusterConditionStatus::True,
                    "Superset database initialization ready.",
                ),
            }
        } else {
            (
                ClusterConditionStatus::Unknown,
                "Waiting for Superset database initialization to start.",
            )
        };

        let cond = ClusterCondition {
            reason: None,
            message: Some(String::from(message)),
            status,
            type_: ClusterConditionType::Available,
            last_transition_time: None,
            last_update_time: None,
        };

        vec![cond].into()
    }
}

/// Evaluates to true if the DB is not ready yet (the controller needs to wait).
/// Otherwise false.
impl From<&DbConditionBuilder> for bool {
    fn from(cond_builder: &DbConditionBuilder) -> bool {
        if let Some(ref status) = cond_builder.0 {
            match status.condition {
                SupersetDBStatusCondition::Pending | SupersetDBStatusCondition::Initializing => {
                    true
                }
                SupersetDBStatusCondition::Failed => true,
                SupersetDBStatusCondition::Ready => false,
            }
        } else {
            true
        }
    }
}
