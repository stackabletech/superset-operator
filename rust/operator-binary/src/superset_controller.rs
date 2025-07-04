//! Ensures that `Pod`s are configured and running for each [`SupersetCluster`]
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap},
    io::Write,
    sync::Arc,
};

use const_format::concatcp;
use indoc::formatdoc;
use product_config::{
    ProductConfigManager,
    flask_app_config_writer::{self, FlaskAppConfigWriterError},
    types::PropertyNameKind,
};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        self,
        configmap::ConfigMapBuilder,
        meta::ObjectMetaBuilder,
        pod::{
            PodBuilder,
            container::ContainerBuilder,
            resources::ResourceRequirementsBuilder,
            security::PodSecurityContextBuilder,
            volume::{
                ListenerOperatorVolumeSourceBuilder, ListenerOperatorVolumeSourceBuilderError,
                ListenerReference,
            },
        },
    },
    cluster_resources::{ClusterResourceApplyStrategy, ClusterResources},
    commons::{product_image_selection::ResolvedProductImage, rbac::build_rbac_resources},
    crd::authentication::oidc,
    k8s_openapi::{
        DeepMerge,
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{ConfigMap, EnvVar, HTTPGetAction, Probe},
        },
        apimachinery::pkg::{apis::meta::v1::LabelSelector, util::intstr::IntOrString},
    },
    kube::{
        Resource, ResourceExt,
        core::{DeserializeGuard, error_boundary},
        runtime::controller::Action,
    },
    kvp::{Label, Labels},
    logging::controller::ReconcilerError,
    product_config_utils::{
        CONFIG_OVERRIDE_FILE_FOOTER_KEY, CONFIG_OVERRIDE_FILE_HEADER_KEY,
        transform_all_roles_to_config, validate_all_roles_and_groups_config,
    },
    product_logging::{
        self,
        framework::{
            LoggingError, create_vector_shutdown_file_command, remove_vector_shutdown_file_command,
        },
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
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    OPERATOR_NAME,
    authorization::opa::{OPA_IMPORTS, SupersetOpaConfigResolved},
    commands::add_cert_to_python_certifi_command,
    config::{self, PYTHON_IMPORTS},
    controller_commons::{self, CONFIG_VOLUME_NAME, LOG_CONFIG_VOLUME_NAME, LOG_VOLUME_NAME},
    crd::{
        APP_NAME, APP_PORT, METRICS_PORT, METRICS_PORT_NAME, PYTHONPATH, STACKABLE_CONFIG_DIR,
        STACKABLE_LOG_CONFIG_DIR, STACKABLE_LOG_DIR, SUPERSET_CONFIG_FILENAME,
        SupersetConfigOptions, SupersetRole,
        authentication::{
            SupersetAuthenticationClassResolved, SupersetClientAuthenticationDetailsResolved,
        },
        v1alpha1::{Container, SupersetCluster, SupersetClusterStatus, SupersetConfig},
    },
    listener::{LISTENER_VOLUME_DIR, LISTENER_VOLUME_NAME, build_group_listener},
    operations::{graceful_shutdown::add_graceful_shutdown_config, pdb::add_pdbs},
    product_logging::{LOG_CONFIG_FILE, extend_config_map_with_log_config},
    service::{
        build_node_rolegroup_headless_service, build_node_rolegroup_metrics_service,
        rolegroup_headless_service_name,
    },
    util::build_recommended_labels,
};

pub const SUPERSET_CONTROLLER_NAME: &str = "supersetcluster";
pub const SUPERSET_FULL_CONTROLLER_NAME: &str =
    concatcp!(SUPERSET_CONTROLLER_NAME, '.', OPERATOR_NAME);
pub const DOCKER_IMAGE_BASE_NAME: &str = "superset";

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

    #[snafu(display("object defines no node role-group"))]
    NoNodeRoleGroup,

    #[snafu(display("invalid container name"))]
    InvalidContainerName {
        source: stackable_operator::builder::pod::container::Error,
    },

    #[snafu(display("failed to create cluster resources"))]
    CreateClusterResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to apply global Service"))]
    ApplyRoleService {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to apply Service for {rolegroup}"))]
    ApplyRoleGroupService {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },

    #[snafu(display("failed to build config file for {rolegroup}"))]
    BuildRoleGroupConfigFile {
        source: FlaskAppConfigWriterError,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },

    #[snafu(display("failed to build ConfigMap for {rolegroup}"))]
    BuildRoleGroupConfig {
        source: stackable_operator::builder::configmap::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },

    #[snafu(display("failed to apply ConfigMap for {rolegroup}"))]
    ApplyRoleGroupConfig {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },

    #[snafu(display("failed to apply StatefulSet for {rolegroup}"))]
    ApplyRoleGroupStatefulSet {
        source: stackable_operator::cluster_resources::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },

    #[snafu(display("failed to generate product config"))]
    GenerateProductConfig {
        source: stackable_operator::product_config_utils::Error,
    },

    #[snafu(display("invalid product config"))]
    InvalidProductConfig {
        source: stackable_operator::product_config_utils::Error,
    },

    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to apply authentication configuration"))]
    InvalidAuthenticationConfig {
        source: crate::crd::authentication::Error,
    },

    #[snafu(display(
        "failed to get the {SUPERSET_CONFIG_FILENAME} file from node or product config"
    ))]
    MissingSupersetConfigInNodeConfig,

    #[snafu(display("failed to get {timeout} from {SUPERSET_CONFIG_FILENAME} file. It should be set in the product config or by user input", timeout = SupersetConfigOptions::SupersetWebserverTimeout))]
    MissingWebServerTimeoutInSupersetConfig,

    #[snafu(display("failed to resolve and merge config for role and role group"))]
    FailedToResolveConfig { source: crate::crd::Error },

    #[snafu(display("vector agent is enabled but vector aggregator ConfigMap is missing"))]
    VectorAggregatorConfigMapMissing,

    #[snafu(display("failed to add the logging configuration to the ConfigMap [{cm_name}]"))]
    InvalidLoggingConfig {
        source: crate::product_logging::Error,
        cm_name: String,
    },

    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to patch service account"))]
    ApplyServiceAccount {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to patch role binding"))]
    ApplyRoleBinding {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to build RBAC objects"))]
    BuildRBACObjects {
        source: stackable_operator::commons::rbac::Error,
    },

    #[snafu(display("failed to create PodDisruptionBudget"))]
    FailedToCreatePdb {
        source: crate::operations::pdb::Error,
    },

    #[snafu(display("failed to configure graceful shutdown"))]
    GracefulShutdown {
        source: crate::operations::graceful_shutdown::Error,
    },

    #[snafu(display("failed to build Labels"))]
    LabelBuild {
        source: stackable_operator::kvp::LabelError,
    },

    #[snafu(display("failed to build Metadata"))]
    MetadataBuild {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to get required Labels"))]
    GetRequiredLabels {
        source:
            stackable_operator::kvp::KeyValuePairError<stackable_operator::kvp::LabelValueError>,
    },

    #[snafu(display("failed to add Superset config settings"))]
    AddSupersetConfig { source: crate::config::Error },

    #[snafu(display("failed to add LDAP Volumes and VolumeMounts"))]
    AddLdapVolumesAndVolumeMounts {
        source: stackable_operator::crd::authentication::ldap::v1alpha1::Error,
    },

    #[snafu(display("failed to add TLS Volumes and VolumeMounts"))]
    AddTlsVolumesAndVolumeMounts {
        source: stackable_operator::commons::tls_verification::TlsClientDetailsError,
    },

    #[snafu(display(
        "failed to write to String (Vec<u8> to be precise) containing superset config"
    ))]
    WriteToConfigFileString { source: std::io::Error },

    #[snafu(display("failed to configure logging"))]
    ConfigureLogging { source: LoggingError },

    #[snafu(display("failed to add needed volume"))]
    AddVolume { source: builder::pod::Error },

    #[snafu(display("failed to add needed volumeMount"))]
    AddVolumeMount {
        source: builder::pod::container::Error,
    },

    #[snafu(display("SupersetCluster object is invalid"))]
    InvalidSupersetCluster {
        source: error_boundary::InvalidObject,
    },

    #[snafu(display("invalid OPA config"))]
    InvalidOpaConfig {
        source: stackable_operator::commons::opa::Error,
    },

    #[snafu(display("failed to build listener volume"))]
    BuildListenerVolume {
        source: ListenerOperatorVolumeSourceBuilderError,
    },

    #[snafu(display("failed to apply group listener"))]
    ApplyGroupListener {
        source: stackable_operator::cluster_resources::Error,
    },
    #[snafu(display("failed to configure listener"))]
    ListenerConfiguration { source: crate::listener::Error },
    #[snafu(display("faild to configure service"))]
    ServiceConfiguration { source: crate::service::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub async fn reconcile_superset(
    superset: Arc<DeserializeGuard<SupersetCluster>>,
    ctx: Arc<Ctx>,
) -> Result<Action> {
    tracing::info!("Starting reconcile");

    let superset = superset
        .0
        .as_ref()
        .map_err(error_boundary::InvalidObject::clone)
        .context(InvalidSupersetClusterSnafu)?;

    let client = &ctx.client;
    let resolved_product_image: ResolvedProductImage = superset
        .spec
        .image
        .resolve(DOCKER_IMAGE_BASE_NAME, crate::built_info::PKG_VERSION);
    let superset_role = SupersetRole::Node;

    let cluster_operation_cond_builder =
        ClusterOperationsConditionBuilder::new(&superset.spec.cluster_config.cluster_operation);

    let auth_config = SupersetClientAuthenticationDetailsResolved::from(
        &superset.spec.cluster_config.authentication,
        client,
    )
    .await
    .context(InvalidAuthenticationConfigSnafu)?;

    let validated_config = validate_all_roles_and_groups_config(
        &resolved_product_image.product_version,
        &transform_all_roles_to_config(
            superset,
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

    let superset_opa_config = match superset.get_opa_config() {
        Some(opa_config) => Some(
            SupersetOpaConfigResolved::from_opa_config(client, superset, opa_config)
                .await
                .context(InvalidOpaConfigSnafu)?,
        ),
        None => None,
    };

    let (rbac_sa, rbac_rolebinding) = build_rbac_resources(
        superset,
        APP_NAME,
        cluster_resources
            .get_required_labels()
            .context(GetRequiredLabelsSnafu)?,
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

    let mut ss_cond_builder = StatefulSetConditionBuilder::default();

    for (rolegroup_name, rolegroup_config) in role_node_config.iter() {
        let rolegroup = superset.node_rolegroup_ref(rolegroup_name);

        let config = superset
            .merged_config(&SupersetRole::Node, &rolegroup)
            .context(FailedToResolveConfigSnafu)?;

        let rg_configmap = build_rolegroup_config_map(
            superset,
            &resolved_product_image,
            &rolegroup,
            rolegroup_config,
            &auth_config,
            &superset_opa_config,
            &config.logging,
        )?;
        let rg_statefulset = build_server_rolegroup_statefulset(
            superset,
            &resolved_product_image,
            &superset_role,
            &rolegroup,
            rolegroup_config,
            &auth_config,
            &rbac_sa.name_any(),
            &config,
        )?;

        let rg_metrics_service =
            build_node_rolegroup_metrics_service(superset, &resolved_product_image, &rolegroup)
                .context(ServiceConfigurationSnafu)?;

        let rg_headless_service =
            build_node_rolegroup_headless_service(superset, &resolved_product_image, &rolegroup)
                .context(ServiceConfigurationSnafu)?;

        cluster_resources
            .add(client, rg_metrics_service)
            .await
            .with_context(|_| ApplyRoleGroupServiceSnafu {
                rolegroup: rolegroup.clone(),
            })?;

        cluster_resources
            .add(client, rg_headless_service)
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

    if let Some(listener_class) = &superset_role.listener_class_name(superset) {
        if let Some(listener_group_name) = superset.group_listener_name(&superset_role) {
            let group_listener = build_group_listener(
                superset,
                build_recommended_labels(
                    superset,
                    SUPERSET_CONTROLLER_NAME,
                    &resolved_product_image.product_version,
                    &superset_role.to_string(),
                    "none",
                ),
                listener_class.to_string(),
                listener_group_name,
            )
            .context(ListenerConfigurationSnafu)?;
            cluster_resources
                .add(client, group_listener)
                .await
                .context(ApplyGroupListenerSnafu)?;
        }
    }

    let generic_role_config = superset.generic_role_config(&superset_role);
    if let Some(GenericRoleConfig {
        pod_disruption_budget: pdb,
    }) = generic_role_config
    {
        add_pdbs(
            &pdb,
            superset,
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
            superset,
            &[&ss_cond_builder, &cluster_operation_cond_builder],
        ),
    };
    client
        .apply_patch_status(OPERATOR_NAME, superset, &status)
        .await
        .context(ApplyStatusSnafu)?;

    Ok(Action::await_change())
}

/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
#[allow(clippy::too_many_arguments)]
fn build_rolegroup_config_map(
    superset: &SupersetCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup: &RoleGroupRef<SupersetCluster>,
    rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    authentication_config: &SupersetClientAuthenticationDetailsResolved,
    superset_opa_config: &Option<SupersetOpaConfigResolved>,
    logging: &Logging<Container>,
) -> Result<ConfigMap, Error> {
    let mut config_properties = BTreeMap::new();
    let mut imports = PYTHON_IMPORTS.to_vec();
    // TODO: this is true per default for versions 3.0.0 and up.
    //    We deactivate it here to keep existing functionality.
    //    However this is a security issue and should be configured properly
    //    Issue: https://github.com/stackabletech/superset-operator/issues/416
    config_properties.insert("TALISMAN_ENABLED".to_string(), "False".to_string());

    config::add_superset_config(&mut config_properties, authentication_config)
        .context(AddSupersetConfigSnafu)?;

    // Adding opa configuration properties to config_properties.
    // This will be injected as key/value pair in superset_config.py
    if let Some(opa_config) = superset_opa_config {
        // If opa role mapping is configured, insert CustomOpaSecurityManager import
        imports.extend(OPA_IMPORTS);

        config_properties.extend(opa_config.as_config());
    }

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

    // By removing the keys from `config_properties`, we avoid pasting the Python code into a Python variable as well
    // (which would be bad)
    if let Some(header) = config_properties.remove(CONFIG_OVERRIDE_FILE_HEADER_KEY) {
        writeln!(config_file, "{}", header).context(WriteToConfigFileStringSnafu)?;
    }
    let temp_file_footer = config_properties.remove(CONFIG_OVERRIDE_FILE_FOOTER_KEY);

    flask_app_config_writer::write::<SupersetConfigOptions, _, _>(
        &mut config_file,
        config_properties.iter(),
        &imports,
    )
    .with_context(|_| BuildRoleGroupConfigFileSnafu {
        rolegroup: rolegroup.clone(),
    })?;

    if let Some(footer) = temp_file_footer {
        writeln!(config_file, "{}", footer).context(WriteToConfigFileStringSnafu)?;
    }

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
                .context(MetadataBuildSnafu)?
                .build(),
        )
        .add_data(
            SUPERSET_CONFIG_FILENAME,
            String::from_utf8(config_file).unwrap(),
        );

    extend_config_map_with_log_config(
        rolegroup,
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

/// The rolegroup [`StatefulSet`] runs the rolegroup, as configured by the administrator.
///
/// The [`Pod`](`stackable_operator::k8s_openapi::api::core::v1::Pod`)s are accessible through the corresponding
/// [`Service`](`stackable_operator::k8s_openapi::api::core::v1::Service`) (via [`build_node_rolegroup_headless_service`] and metrics from [`build_node_rolegroup_metrics_service`]).
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
        .context(NoNodeRoleGroupSnafu)?;

    let recommended_object_labels = build_recommended_labels(
        superset,
        SUPERSET_CONTROLLER_NAME,
        &resolved_product_image.app_version_label,
        &rolegroup_ref.role,
        &rolegroup_ref.role_group,
    );
    // Used for PVC templates that cannot be modified once they are deployed
    let unversioned_recommended_labels = Labels::recommended(build_recommended_labels(
        superset,
        SUPERSET_CONTROLLER_NAME,
        // A version value is required, and we do want to use the "recommended" format for the other desired labels
        "none",
        &rolegroup_ref.role,
        &rolegroup_ref.role_group,
    ))
    .context(LabelBuildSnafu)?;

    let metadata = ObjectMetaBuilder::new()
        .with_recommended_labels(recommended_object_labels.clone())
        .context(MetadataBuildSnafu)?
        .build();

    let mut pb = &mut PodBuilder::new();

    pb = pb
        .metadata(metadata)
        .image_pull_secrets_from_product_image(resolved_product_image)
        .security_context(
            PodSecurityContextBuilder::new()
                .fs_group(1000) // Needed for secret-operator
                .build(),
        )
        .affinity(&merged_config.affinity)
        .service_account_name(sa_name);

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

    add_authentication_volumes_and_volume_mounts(authentication_config, &mut superset_cb, pb)?;

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
        .add_volume_mount(CONFIG_VOLUME_NAME, STACKABLE_CONFIG_DIR).context(AddVolumeMountSnafu)?
        .add_volume_mount(LOG_CONFIG_VOLUME_NAME, STACKABLE_LOG_CONFIG_DIR).context(AddVolumeMountSnafu)?
        .add_volume_mount(LOG_VOLUME_NAME, STACKABLE_LOG_DIR).context(AddVolumeMountSnafu)?
        .add_env_var_from_secret("ADMIN_USERNAME", secret, "adminUser.username")
        .add_env_var_from_secret("ADMIN_FIRSTNAME", secret, "adminUser.firstname")
        .add_env_var_from_secret("ADMIN_LASTNAME", secret, "adminUser.lastname")
        .add_env_var_from_secret("ADMIN_EMAIL", secret, "adminUser.email")
        .add_env_var_from_secret("ADMIN_PASSWORD", secret, "adminUser.password")
        // Needed by the `containerdebug` process to log it's tracing information to.
        .add_env_var("CONTAINERDEBUG_LOG_DIRECTORY", format!("{STACKABLE_LOG_DIR}/containerdebug"))
        .add_env_var("SSL_CERT_DIR", "/stackable/certs/")
        .add_env_vars(authentication_env_vars(authentication_config))
        .command(vec![
            "/bin/bash".to_string(),
            "-x".to_string(),
            "-euo".to_string(),
            "pipefail".to_string(),
            "-c".to_string(),
        ])
        .args(vec![formatdoc! {"
            {COMMON_BASH_TRAP_FUNCTIONS}

            mkdir --parents {PYTHONPATH}
            cp {STACKABLE_CONFIG_DIR}/* {PYTHONPATH}
            cp {STACKABLE_LOG_CONFIG_DIR}/{LOG_CONFIG_FILE} {PYTHONPATH}

            {auth_commands}

            superset db upgrade
            set +x
            echo 'Running \"superset fab create-admin [...]\", which is not shown as it leaks the Superset admin credentials'
            superset fab create-admin --username \"$ADMIN_USERNAME\" --firstname \"$ADMIN_FIRSTNAME\" --lastname \"$ADMIN_LASTNAME\" --email \"$ADMIN_EMAIL\" --password \"$ADMIN_PASSWORD\"
            set -x
            superset init

            {remove_vector_shutdown_file_command}
            prepare_signal_handlers
            containerdebug --output={STACKABLE_LOG_DIR}/containerdebug-state.json --loop &
            gunicorn --bind 0.0.0.0:${{SUPERSET_PORT}} --worker-class gthread --threads 20 --timeout {webserver_timeout} --limit-request-line 0 --limit-request-field_size 0 'superset.app:create_app()' &
            wait_for_termination $!

            {create_vector_shutdown_file_command}
        ",
            auth_commands = authentication_start_commands(authentication_config),
            remove_vector_shutdown_file_command =
                remove_vector_shutdown_file_command(STACKABLE_LOG_DIR),
            create_vector_shutdown_file_command =
                create_vector_shutdown_file_command(STACKABLE_LOG_DIR),
        }])
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

    // listener endpoints will use persistent volumes
    // so that load balancers can hard-code the target addresses and
    // that it is possible to connect to a consistent address
    let pvcs = if let Some(group_listener_name) = superset.group_listener_name(superset_role) {
        let pvc = ListenerOperatorVolumeSourceBuilder::new(
            &ListenerReference::ListenerName(group_listener_name),
            &unversioned_recommended_labels,
        )
        .context(BuildListenerVolumeSnafu)?
        .build_pvc(LISTENER_VOLUME_NAME.to_owned())
        .context(BuildListenerVolumeSnafu)?;
        Some(vec![pvc])
    } else {
        None
    };

    superset_cb
        .add_volume_mount(LISTENER_VOLUME_NAME, LISTENER_VOLUME_DIR)
        .context(AddVolumeMountSnafu)?;

    pb.add_container(superset_cb.build());
    add_graceful_shutdown_config(merged_config, pb).context(GracefulShutdownSnafu)?;

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
        .add_container_port(METRICS_PORT_NAME, METRICS_PORT.into())
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
    ))
    .context(AddVolumeSnafu)?;
    pb.add_container(metrics_container);

    if merged_config.logging.enable_vector_agent {
        match &superset
            .spec
            .cluster_config
            .vector_aggregator_config_map_name
        {
            Some(vector_aggregator_config_map_name) => {
                pb.add_container(
                    product_logging::framework::vector_container(
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
                        vector_aggregator_config_map_name,
                    )
                    .context(ConfigureLoggingSnafu)?,
                );
            }
            None => {
                VectorAggregatorConfigMapMissingSnafu.fail()?;
            }
        }
    }

    let mut pod_template = pb.build_template();
    pod_template.merge_from(role.config.pod_overrides.clone());
    pod_template.merge_from(role_group.config.pod_overrides.clone());

    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(superset)
            .name(rolegroup_ref.object_name())
            .ownerreference_from_resource(superset, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(recommended_object_labels)
            .context(MetadataBuildSnafu)?
            .with_label(
                Label::try_from(("restarter.stackable.tech/enabled", "true"))
                    .context(LabelBuildSnafu)?,
            )
            .build(),
        spec: Some(StatefulSetSpec {
            // Set to `OrderedReady`, to make sure Pods start after another and the init commands don't run in parallel
            pod_management_policy: Some("OrderedReady".to_string()),
            replicas: role_group.replicas.map(i32::from),
            selector: LabelSelector {
                match_labels: Some(
                    Labels::role_group_selector(
                        superset,
                        APP_NAME,
                        &rolegroup_ref.role,
                        &rolegroup_ref.role_group,
                    )
                    .context(LabelBuildSnafu)?
                    .into(),
                ),
                ..LabelSelector::default()
            },
            service_name: Some(rolegroup_headless_service_name(rolegroup_ref)),
            template: pod_template,
            volume_claim_templates: pvcs,
            ..StatefulSetSpec::default()
        }),
        status: None,
    })
}

fn add_authentication_volumes_and_volume_mounts(
    auth_config: &SupersetClientAuthenticationDetailsResolved,
    cb: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) -> Result<()> {
    // Different authentication entries can reference the same secret
    // class or TLS certificate. It must be ensured that the volumes
    // and volume mounts are only added once in such a case.

    let mut ldap_authentication_providers = BTreeSet::new();
    let mut tls_client_credentials = BTreeSet::new();

    for auth_class_resolved in &auth_config.authentication_classes_resolved {
        match auth_class_resolved {
            SupersetAuthenticationClassResolved::Ldap { provider } => {
                ldap_authentication_providers.insert(provider);
            }
            SupersetAuthenticationClassResolved::Oidc { provider, .. } => {
                tls_client_credentials.insert(&provider.tls);
            }
        }
    }

    for provider in ldap_authentication_providers {
        provider
            .add_volumes_and_mounts(pb, vec![cb])
            .context(AddLdapVolumesAndVolumeMountsSnafu)?;
    }

    for tls in tls_client_credentials {
        tls.add_volumes_and_mounts(pb, vec![cb])
            .context(AddTlsVolumesAndVolumeMountsSnafu)?;
    }

    Ok(())
}

fn authentication_env_vars(
    auth_config: &SupersetClientAuthenticationDetailsResolved,
) -> Vec<EnvVar> {
    // Different OIDC authentication entries can reference the same
    // client secret. It must be ensured that the env variables are only
    // added once in such a case.

    let mut oidc_client_credentials_secrets = BTreeSet::new();

    for auth_class_resolved in &auth_config.authentication_classes_resolved {
        match auth_class_resolved {
            SupersetAuthenticationClassResolved::Ldap { .. } => {}
            SupersetAuthenticationClassResolved::Oidc {
                client_auth_options: oidc,
                ..
            } => {
                oidc_client_credentials_secrets
                    .insert(oidc.client_credentials_secret_ref.to_owned());
            }
        }
    }

    oidc_client_credentials_secrets
        .iter()
        .cloned()
        .flat_map(oidc::v1alpha1::AuthenticationProvider::client_credentials_env_var_mounts)
        .collect()
}

fn authentication_start_commands(
    auth_config: &SupersetClientAuthenticationDetailsResolved,
) -> String {
    let mut commands = Vec::new();

    let mut tls_client_credentials = BTreeSet::new();

    for auth_class_resolved in &auth_config.authentication_classes_resolved {
        match auth_class_resolved {
            SupersetAuthenticationClassResolved::Oidc { provider, .. } => {
                tls_client_credentials.insert(&provider.tls);

                // WebPKI will be handled implicitly
            }
            SupersetAuthenticationClassResolved::Ldap { .. } => {}
        }
    }

    for tls in tls_client_credentials {
        commands.push(tls.tls_ca_cert_mount_path().map(|tls_ca_cert_mount_path| {
            add_cert_to_python_certifi_command(&tls_ca_cert_mount_path)
        }));
    }

    commands
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn error_policy(
    _obj: Arc<DeserializeGuard<SupersetCluster>>,
    error: &Error,
    _ctx: Arc<Ctx>,
) -> Action {
    match error {
        Error::InvalidSupersetCluster { .. } => Action::await_change(),
        _ => Action::requeue(*Duration::from_secs(5)),
    }
}
