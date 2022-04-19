//! Ensures that `Pod`s are configured and running for each [`SupersetCluster`]

use crate::{
    util::{statsd_exporter_version, superset_version},
    APP_NAME, APP_PORT,
};

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder},
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMap, ConfigMapVolumeSource, Service, ServicePort, ServiceSpec, Volume, Secret
            },
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    kube::{runtime::controller::{Action, Context}, ResourceExt},
    error::OperatorResult,
    labels::{role_group_selector_labels, role_selector_labels},
    logging::controller::ReconcilerError,
    product_config::{
        flask_app_config_writer::{self, FlaskAppConfigWriterError},
        types::PropertyNameKind,
        ProductConfigManager,
    },
    product_config_utils::{transform_all_roles_to_config, validate_all_roles_and_groups_config},
    role_utils::RoleGroupRef,
};
use stackable_superset_crd::{
    supersetdb::SupersetDB, SupersetCluster, SupersetConfig, SupersetConfigOptions, SupersetRole,
    PYTHONPATH, SUPERSET_CONFIG_FILENAME,
};
use strum::{EnumDiscriminants, IntoStaticStr};

const FIELD_MANAGER_SCOPE: &str = "supersetcluster";

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
    #[snafu(display("failed to retrieve superset version"))]
    NoSupersetVersion { source: crate::util::Error },
    #[snafu(display("failed to retrieve statsd exporter version"))]
    NoStatsdExporterVersion { source: crate::util::Error },
    #[snafu(display("object defines no node role"))]
    NoNodeRole,
    #[snafu(display("failed to calculate global service name"))]
    GlobalServiceNameNotFound,
    #[snafu(display("failed to apply global Service"))]
    ApplyRoleService {
        source: stackable_operator::error::Error,
    },

    #[snafu(display("failed to apply Superset DB"))]
    CreateSupersetObject {
        source: stackable_superset_crd::supersetdb::Error,
    },
    #[snafu(display("failed to apply Superset DB"))]
    ApplySupersetDB {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to apply Service for {}", rolegroup))]
    ApplyRoleGroupService {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },
    #[snafu(display("failed to build config file for {}", rolegroup))]
    BuildRoleGroupConfigFile {
        source: FlaskAppConfigWriterError,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },
    #[snafu(display("failed to build ConfigMap for {}", rolegroup))]
    BuildRoleGroupConfig {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },
    #[snafu(display("failed to apply ConfigMap for {}", rolegroup))]
    ApplyRoleGroupConfig {
        source: stackable_operator::error::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },
    #[snafu(display("failed to apply StatefulSet for {}", rolegroup))]
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
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub async fn reconcile_superset(
    superset: Arc<SupersetCluster>,
    ctx: Context<Ctx>,
) -> Result<Action> {
    tracing::info!("Starting reconcile");

    let client = &ctx.get_ref().client;

    // Ensure DB Schema is set up
    let superset_db = SupersetDB::for_superset(&superset).context(CreateSupersetObjectSnafu)?;
    client
        .apply_patch(FIELD_MANAGER_SCOPE, &superset_db, &superset_db)
        .await
        .context(ApplySupersetDBSnafu)?;

    let validated_config = validate_all_roles_and_groups_config(
        superset_version(&superset).context(NoSupersetVersionSnafu)?,
        &transform_all_roles_to_config(
            &*superset,
            [(
                SupersetRole::Node.to_string(),
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
        &ctx.get_ref().product_config,
        false,
        false,
    )
    .context(InvalidProductConfigSnafu)?;
    let role_node_config = validated_config
        .get(&SupersetRole::Node.to_string())
        .map(Cow::Borrowed)
        .unwrap_or_default();

    let node_role_service = build_node_role_service(&superset)?;
    client
        .apply_patch(FIELD_MANAGER_SCOPE, &node_role_service, &node_role_service)
        .await
        .context(ApplyRoleServiceSnafu)?;
    for (rolegroup_name, rolegroup_config) in role_node_config.iter() {
        let rolegroup = superset.node_rolegroup_ref(rolegroup_name);

        let rg_service = build_node_rolegroup_service(&rolegroup, &superset)?;
        let rg_configmap = build_rolegroup_config_map(&superset, &rolegroup, rolegroup_config)?;
        let rg_statefulset =
            build_server_rolegroup_statefulset(&rolegroup, &superset, rolegroup_config, &ctx).await?;
        client
            .apply_patch(FIELD_MANAGER_SCOPE, &rg_service, &rg_service)
            .await
            .with_context(|_| ApplyRoleGroupServiceSnafu {
                rolegroup: rolegroup.clone(),
            })?;
        client
            .apply_patch(FIELD_MANAGER_SCOPE, &rg_configmap, &rg_configmap)
            .await
            .with_context(|_| ApplyRoleGroupConfigSnafu {
                rolegroup: rolegroup.clone(),
            })?;
        client
            .apply_patch(FIELD_MANAGER_SCOPE, &rg_statefulset, &rg_statefulset)
            .await
            .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                rolegroup: rolegroup.clone(),
            })?;
    }

    Ok(Action::await_change())
}

/// The server-role service is the primary endpoint that should be used by clients that do not perform internal load balancing,
/// including targets outside of the cluster.
pub fn build_node_role_service(superset: &SupersetCluster) -> Result<Service> {
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
            .with_recommended_labels(
                superset,
                APP_NAME,
                superset_version(superset).context(NoSupersetVersionSnafu)?,
                &role_name,
                "global",
            )
            .with_label(
                "statsd-exporter",
                statsd_exporter_version(superset).context(NoStatsdExporterVersionSnafu)?,
            )
            .build(),
        spec: Some(ServiceSpec {
            ports: Some(vec![ServicePort {
                name: Some("superset".to_string()),
                port: APP_PORT.into(),
                protocol: Some("TCP".to_string()),
                ..ServicePort::default()
            }]),
            selector: Some(role_selector_labels(superset, APP_NAME, &role_name)),
            type_: Some("NodePort".to_string()),
            ..ServiceSpec::default()
        }),
        status: None,
    })
}

/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
fn build_rolegroup_config_map(
    superset: &SupersetCluster,
    rolegroup: &RoleGroupRef<SupersetCluster>,
    rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
) -> Result<ConfigMap, Error> {
    let mut config = rolegroup_config
        .get(&PropertyNameKind::File(
            SUPERSET_CONFIG_FILENAME.to_string(),
        ))
        .cloned()
        .unwrap_or_default();

    config.insert(
        SupersetConfigOptions::SecretKey.to_string(),
        "os.environ.get('SECRET_KEY')".into(),
    );
    config.insert(
        SupersetConfigOptions::SqlalchemyDatabaseUri.to_string(),
        "os.environ.get('SQLALCHEMY_DATABASE_URI')".into(),
    );
    config.insert(
        SupersetConfigOptions::StatsLogger.to_string(),
        "StatsdStatsLogger(host='0.0.0.0', port=9125)".into(),
    );

    let imports = [
        "import os",
        "from superset.stats_logger import StatsdStatsLogger",
    ];

    let mut config_file = Vec::new();
    flask_app_config_writer::write::<SupersetConfigOptions, _, _>(
        &mut config_file,
        config.iter(),
        &imports,
    )
    .with_context(|_| BuildRoleGroupConfigFileSnafu {
        rolegroup: rolegroup.clone(),
    })?;

    ConfigMapBuilder::new()
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(superset)
                .name(rolegroup.object_name())
                .ownerreference_from_resource(superset, None, Some(true))
                .context(ObjectMissingMetadataForOwnerRefSnafu)?
                .with_recommended_labels(
                    superset,
                    APP_NAME,
                    superset_version(superset).context(NoSupersetVersionSnafu)?,
                    &rolegroup.role,
                    &rolegroup.role_group,
                )
                .build(),
        )
        .add_data(
            SUPERSET_CONFIG_FILENAME,
            String::from_utf8(config_file).unwrap(),
        )
        .build()
        .with_context(|_| BuildRoleGroupConfigSnafu {
            rolegroup: rolegroup.clone(),
        })
}

/// The rolegroup [`Service`] is a headless service that allows direct access to the instances of a certain rolegroup
///
/// This is mostly useful for internal communication between peers, or for clients that perform client-side load balancing.
fn build_node_rolegroup_service(
    rolegroup: &RoleGroupRef<SupersetCluster>,
    superset: &SupersetCluster,
) -> Result<Service> {
    Ok(Service {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(superset)
            .name(&rolegroup.object_name())
            .ownerreference_from_resource(superset, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(
                superset,
                APP_NAME,
                superset_version(superset).context(NoSupersetVersionSnafu)?,
                &rolegroup.role,
                &rolegroup.role_group,
            )
            .with_label(
                "statsd-exporter",
                statsd_exporter_version(superset).context(NoStatsdExporterVersionSnafu)?,
            )
            .with_label("prometheus.io/scrape", "true")
            .build(),
        spec: Some(ServiceSpec {
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
async fn build_server_rolegroup_statefulset(
    rolegroup_ref: &RoleGroupRef<SupersetCluster>,
    superset: &SupersetCluster,
    node_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    ctx: &Context<Ctx>,
) -> Result<StatefulSet> {
    let rolegroup = superset
        .spec
        .nodes
        .as_ref()
        .context(NoNodeRoleSnafu)?
        .role_groups
        .get(&rolegroup_ref.role_group);

    let superset_version = superset_version(superset).context(NoSupersetVersionSnafu)?;

    let image = format!("docker.stackable.tech/stackable/superset:{superset_version}-stackable1");

    let statsd_exporter_version =
        statsd_exporter_version(superset).context(NoStatsdExporterVersionSnafu)?;

    let statsd_exporter_image =
        format!("docker.stackable.tech/prom/statsd-exporter:{statsd_exporter_version}");

    let mut cb = ContainerBuilder::new("superset");

    for (name, value) in node_config
        .get(&PropertyNameKind::Env)
        .cloned()
        .unwrap_or_default()
    {
        if name == SupersetConfig::CREDENTIALS_SECRET_PROPERTY {
            cb.add_env_var_from_secret("SECRET_KEY", &value, "connections.secretKey");
            cb.add_env_var_from_secret(
                "SQLALCHEMY_DATABASE_URI",
                &value,
                "connections.sqlalchemyDatabaseUri",
            );
        } else {
            cb.add_env_var(name, value);
        };
    }

    let secret_name = node_config
        .get(&PropertyNameKind::Env)
        .and_then(|vars| vars.get(SupersetConfig::CREDENTIALS_SECRET_PROPERTY))
        .unwrap();
    
    let namespace_name = superset
        .namespace()
        .unwrap();

    let client = &ctx.get_ref().client;

    let s : OperatorResult<Secret> = client.get(secret_name, Some(&namespace_name)).await;

    let s = match s {
        Ok(sec) => sec,
        Err(error) => {
            panic!("Problem obtaining secret {:?}", error)
        },
    };
   
    // if the mapbox api key is configured set the env variable
    if let Some(map) = s.data {
        match map.get("connections.mapBoxApiKey") { 
            Some(api_key) => {

                let key = String::from_utf8(api_key.0.clone()).unwrap(); 

                cb.add_env_var("MAPBOX_API_KEY", key);
            },
            None => ()
        }
    }

    let container = cb
        .image(image)
        .add_container_port("http", APP_PORT.into())
        .add_volume_mount("config", PYTHONPATH)
        .build();
    let metrics_container = ContainerBuilder::new("metrics")
        .image(statsd_exporter_image)
        .add_container_port(METRICS_PORT_NAME, METRICS_PORT)
        .build();
    Ok(StatefulSet {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(superset)
            .name(&rolegroup_ref.object_name())
            .ownerreference_from_resource(superset, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .with_recommended_labels(
                superset,
                APP_NAME,
                superset_version,
                &rolegroup_ref.role,
                &rolegroup_ref.role_group,
            )
            .with_label("statsd-exporter", statsd_exporter_version)
            .build(),
        spec: Some(StatefulSetSpec {
            pod_management_policy: Some("Parallel".to_string()),
            replicas: if superset.spec.stopped.unwrap_or(false) {
                Some(0)
            } else {
                rolegroup.and_then(|rg| rg.replicas).map(i32::from)
            },
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
            template: PodBuilder::new()
                .metadata_builder(|m| {
                    m.with_recommended_labels(
                        superset,
                        APP_NAME,
                        superset_version,
                        &rolegroup_ref.role,
                        &rolegroup_ref.role_group,
                    )
                    .with_label("statsd-exporter", statsd_exporter_version)
                })
                .add_container(container)
                .add_container(metrics_container)
                .add_volume(Volume {
                    name: "config".to_string(),
                    config_map: Some(ConfigMapVolumeSource {
                        name: Some(rolegroup_ref.object_name()),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .build_template(),
            ..StatefulSetSpec::default()
        }),
        status: None,
    })
}

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(5))
}
