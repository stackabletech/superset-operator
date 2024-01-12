//! Ensures that `Pod`s are configured and running for each [`SupersetCluster`]
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use indoc::formatdoc;
use product_config::{
    flask_app_config_writer::{self, FlaskAppConfigWriterError},
    types::PropertyNameKind,
    ProductConfigManager,
};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        resources::ResourceRequirementsBuilder, ConfigMapBuilder, ContainerBuilder,
        ObjectMetaBuilder, PodBuilder, PodSecurityContextBuilder,
    },
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    commons::{
        authentication::oidc, product_image_selection::ResolvedProductImage,
        rbac::build_rbac_resources,
    },
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{ConfigMap, HTTPGetAction, Probe, Service, ServicePort, ServiceSpec},
        },
        apimachinery::pkg::{apis::meta::v1::LabelSelector, util::intstr::IntOrString},
        DeepMerge,
    },
    kube::{runtime::controller::Action, Resource, ResourceExt},
    labels::{role_group_selector_labels, role_selector_labels},
    logging::controller::ReconcilerError,
    product_config_utils::{transform_all_roles_to_config, validate_all_roles_and_groups_config},
    product_logging::{
        self,
        framework::{create_vector_shutdown_file_command, remove_vector_shutdown_file_command},
        spec::Logging,
    },
    role_utils::{GenericRoleConfig, RoleGroupRef},
    status::condition::{
        compute_conditions, operations::ClusterOperationsConditionBuilder,
        statefulset::StatefulSetConditionBuilder,
    },
    time::Duration,
    utils::COMMON_BASH_TRAP_FUNCTIONS,
};
use stackable_superset_crd::authentication::SupersetAuthenticationClassResolved;
use stackable_superset_crd::{
    authentication::SupersetClientAuthenticationDetailsResolved, Container, SupersetCluster,
    SupersetClusterStatus, SupersetConfig, SupersetConfigOptions, SupersetRole, APP_NAME,
    PYTHONPATH, STACKABLE_CONFIG_DIR, STACKABLE_LOG_CONFIG_DIR, STACKABLE_LOG_DIR,
    SUPERSET_CONFIG_FILENAME,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    commands::add_cert_to_system_truststore_command,
    config::{self, PYTHON_IMPORTS},
    controller_commons::{self, CONFIG_VOLUME_NAME, LOG_CONFIG_VOLUME_NAME, LOG_VOLUME_NAME},
    operations::{graceful_shutdown::add_graceful_shutdown_config, pdb::add_pdbs},
    product_logging::{
        extend_config_map_with_log_config, resolve_vector_aggregator_address, LOG_CONFIG_FILE,
    },
    util::build_recommended_labels,
    APP_PORT, OPERATOR_NAME,
};

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

    #[snafu(display("failed to create PodDisruptionBudget"))]
    FailedToCreatePdb {
        source: crate::operations::pdb::Error,
    },

    #[snafu(display("failed to configure graceful shutdown"))]
    GracefulShutdown {
        source: crate::operations::graceful_shutdown::Error,
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

    let auth_config = SupersetClientAuthenticationDetailsResolved::from(
        superset
            .spec
            .cluster_config
            .authentication
            .as_deref()
            .unwrap_or_default(),
        client,
    )
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
            &auth_config,
            &config.logging,
            vector_aggregator_address.as_deref(),
        )?;
        let rg_statefulset = build_server_rolegroup_statefulset(
            &superset,
            &resolved_product_image,
            &superset_role,
            &rolegroup,
            rolegroup_config,
            &auth_config,
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

    let role_config = superset.role_config(&superset_role);
    if let Some(GenericRoleConfig {
        pod_disruption_budget: pdb,
    }) = role_config
    {
        add_pdbs(
            pdb,
            &superset,
            &superset_role,
            client,
            &mut cluster_resources,
        )
        .await
        .context(FailedToCreatePdbSnafu)?;
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
                name: Some("http".to_string()),
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
    authentication_config: &SupersetClientAuthenticationDetailsResolved,
    logging: &Logging<Container>,
    vector_aggregator_address: Option<&str>,
) -> Result<ConfigMap, Error> {
    let mut config_properties = BTreeMap::new();

    // TODO: this is true per default for versions 3.0.0 and up.
    //    We deactivate it here to keep existing functionality.
    //    However this is a security issue and should be configured properly
    //    Issue: https://github.com/stackabletech/superset-operator/issues/416
    config_properties.insert("TALISMAN_ENABLED".to_string(), "False".to_string());

    config::add_superset_config(&mut config_properties, authentication_config);

    // The order here should be kept in order to preserve overrides.
    // No properties should be added after this extend.
    config_properties.extend(
        rolegroup_config
            .get(&PropertyNameKind::File(
                SUPERSET_CONFIG_FILENAME.to_string(),
            ))
            .cloned()
            .unwrap_or_default(),
    );

    let mut config_file = Vec::new();
    flask_app_config_writer::write::<SupersetConfigOptions, _, _>(
        &mut config_file,
        config_properties.iter(),
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
                    name: Some("http".to_string()),
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
    authentication_config: &SupersetClientAuthenticationDetailsResolved,
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

    let secret = &superset.spec.cluster_config.credentials_secret;

    superset_cb
        .image_from_product_image(resolved_product_image)
        .add_container_port("http", APP_PORT.into())
        .add_volume_mount(CONFIG_VOLUME_NAME, STACKABLE_CONFIG_DIR)
        .add_volume_mount(LOG_CONFIG_VOLUME_NAME, STACKABLE_LOG_CONFIG_DIR)
        .add_volume_mount(LOG_VOLUME_NAME, STACKABLE_LOG_DIR)
        .add_env_var_from_secret("ADMIN_USERNAME", secret, "adminUser.username")
        .add_env_var_from_secret("ADMIN_FIRSTNAME", secret, "adminUser.firstname")
        .add_env_var_from_secret("ADMIN_LASTNAME", secret, "adminUser.lastname")
        .add_env_var_from_secret("ADMIN_EMAIL", secret, "adminUser.email")
        .add_env_var_from_secret("ADMIN_PASSWORD", secret, "adminUser.password")
        .add_env_var("SSL_CERT_DIR", "/stackable/certs/")
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
            formatdoc! {"
                mkdir --parents {PYTHONPATH} && \
                cp {STACKABLE_CONFIG_DIR}/* {PYTHONPATH} && \
                cp {STACKABLE_LOG_CONFIG_DIR}/{LOG_CONFIG_FILE} {PYTHONPATH} && \
                {auth_commands}
                superset db upgrade && \
                superset fab create-admin \
                    --username \"$ADMIN_USERNAME\" \
                    --firstname \"$ADMIN_FIRSTNAME\" \
                    --lastname \"$ADMIN_LASTNAME\" \
                    --email \"$ADMIN_EMAIL\" \
                    --password \"$ADMIN_PASSWORD\" && \
                superset init && \
                {COMMON_BASH_TRAP_FUNCTIONS}
                {remove_vector_shutdown_file_command}
                prepare_signal_handlers
                gunicorn \
                --bind 0.0.0.0:${{SUPERSET_PORT}} \
                --worker-class gthread \
                --threads 20 \
                --timeout {webserver_timeout} \
                --limit-request-line 0 \
                --limit-request-field_size 0 \
                'superset.app:create_app()' &
                wait_for_termination $!
                {create_vector_shutdown_file_command}",
            auth_commands = authentication_start_commands(authentication_config).unwrap_or_default(),
            remove_vector_shutdown_file_command =
                remove_vector_shutdown_file_command(STACKABLE_LOG_DIR),
            create_vector_shutdown_file_command =
                create_vector_shutdown_file_command(STACKABLE_LOG_DIR),
            },
        ])
        .resources(merged_config.resources.clone().into());
    let probe = Probe {
        http_get: Some(HTTPGetAction {
            port: IntOrString::Int(APP_PORT.into()),
            path: Some("/health".to_string()),
            ..HTTPGetAction::default()
        }),
        initial_delay_seconds: Some(15),
        period_seconds: Some(15),
        timeout_seconds: Some(1),
        failure_threshold: Some(3),
        success_threshold: Some(1),
        ..Probe::default()
    };
    superset_cb.readiness_probe(probe.clone());
    superset_cb.liveness_probe(probe);

    pb.add_container(superset_cb.build());
    add_graceful_shutdown_config(merged_config, &mut pb).context(GracefulShutdownSnafu)?;

    let metrics_container = ContainerBuilder::new("metrics")
        .context(InvalidContainerNameSnafu)?
        .image_from_product_image(resolved_product_image)
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
        ])
        .args(vec![formatdoc! {"
            {COMMON_BASH_TRAP_FUNCTIONS}
            prepare_signal_handlers
            /stackable/statsd_exporter &
            wait_for_termination $!
        "}])
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
            // Set to `OrderedReady`, to make sure Pods start after another and the init commands don't run in parallel
            pod_management_policy: Some("OrderedReady".to_string()),
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
    auth_config: &SupersetClientAuthenticationDetailsResolved,
    cb: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) {
    match &auth_config.authentication_class_resolved {
        Some(SupersetAuthenticationClassResolved::Ldap { provider }) => {
            provider.add_volumes_and_mounts(pb, vec![cb]);
        }
        Some(SupersetAuthenticationClassResolved::Oidc { oidc, provider, .. }) => {
            cb.add_env_vars(
                oidc::AuthenticationProvider::client_credentials_env_var_mounts(
                    oidc.client_credentials_secret_ref.clone(),
                ),
            );
            provider.tls.add_volumes_and_mounts(pb, vec![cb]);
        }
        None => (),
    }
}

fn authentication_start_commands(
    auth_config: &SupersetClientAuthenticationDetailsResolved,
) -> Option<String> {
    match &auth_config.authentication_class_resolved {
        Some(SupersetAuthenticationClassResolved::Oidc { provider, .. }) => {
            if provider.tls.uses_tls() && !provider.tls.uses_tls_verification() {
                // TODO Add snafu error
                panic!("Superset does not allow that");
            }

            provider
                .tls
                .tls_ca_cert_mount_path()
                .map(|tls_ca_cert_mount_path| {
                    add_cert_to_system_truststore_command(&tls_ca_cert_mount_path)
                })

            // WebPKI will be handled implicitly
        }
        Some(SupersetAuthenticationClassResolved::Ldap { .. }) | None => None,
    }
}

pub fn error_policy(_obj: Arc<SupersetCluster>, _error: &Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(*Duration::from_secs(5))
}
