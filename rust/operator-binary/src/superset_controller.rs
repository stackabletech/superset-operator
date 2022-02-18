//! Ensures that `Pod`s are configured and running for each [`SupersetCluster`]

use crate::{
    util::{env_var_from_secret, statsd_exporter_version, superset_version},
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
    builder::{ContainerBuilder, ObjectMetaBuilder, PodBuilder},
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{Service, ServicePort, ServiceSpec},
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    kube::runtime::controller::{Context, ReconcilerAction},
    labels::{role_group_selector_labels, role_selector_labels},
    logging::controller::ReconcilerError,
    product_config::{types::PropertyNameKind, ProductConfigManager},
    product_config_utils::{transform_all_roles_to_config, validate_all_roles_and_groups_config},
    role_utils::RoleGroupRef,
};
use stackable_superset_crd::{
    supersetdb::SupersetDB, SupersetCluster, SupersetConfig, SupersetRole,
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
) -> Result<ReconcilerAction> {
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
                    vec![PropertyNameKind::Env],
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
        let rg_statefulset =
            build_server_rolegroup_statefulset(&rolegroup, &superset, rolegroup_config)?;
        client
            .apply_patch(FIELD_MANAGER_SCOPE, &rg_service, &rg_service)
            .await
            .with_context(|_| ApplyRoleGroupServiceSnafu {
                rolegroup: rolegroup.clone(),
            })?;
        client
            .apply_patch(FIELD_MANAGER_SCOPE, &rg_statefulset, &rg_statefulset)
            .await
            .with_context(|_| ApplyRoleGroupStatefulSetSnafu {
                rolegroup: rolegroup.clone(),
            })?;
    }

    Ok(ReconcilerAction {
        requeue_after: None,
    })
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
fn build_server_rolegroup_statefulset(
    rolegroup_ref: &RoleGroupRef<SupersetCluster>,
    superset: &SupersetCluster,
    node_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
) -> Result<StatefulSet> {
    let rolegroup = superset
        .spec
        .nodes
        .as_ref()
        .context(NoNodeRoleSnafu)?
        .role_groups
        .get(&rolegroup_ref.role_group);

    let superset_version = superset_version(superset).context(NoSupersetVersionSnafu)?;

    let image = format!("docker.stackable.tech/stackable/superset:{superset_version}-stackable0");

    let statsd_exporter_version =
        statsd_exporter_version(superset).context(NoStatsdExporterVersionSnafu)?;

    let statsd_exporter_image =
        format!("docker.stackable.tech/prom/statsd-exporter:{statsd_exporter_version}");

    let env = node_config
        .get(&PropertyNameKind::Env)
        .and_then(|vars| vars.get(SupersetConfig::CREDENTIALS_SECRET_PROPERTY))
        .map(|secret| {
            vec![
                env_var_from_secret("SECRET_KEY", secret, "connections.secretKey"),
                env_var_from_secret(
                    "SQLALCHEMY_DATABASE_URI",
                    secret,
                    "connections.sqlalchemyDatabaseUri",
                ),
            ]
        })
        .unwrap_or_default();

    let container = ContainerBuilder::new("superset")
        .image(image)
        .add_env_vars(env)
        .add_container_port("http", APP_PORT.into())
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
                .build_template(),
            ..StatefulSetSpec::default()
        }),
        status: None,
    })
}

pub fn error_policy(_error: &Error, _ctx: Context<Ctx>) -> ReconcilerAction {
    ReconcilerAction {
        requeue_after: Some(Duration::from_secs(5)),
    }
}
