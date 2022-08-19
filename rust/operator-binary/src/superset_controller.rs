//! Ensures that `Pod`s are configured and running for each [`SupersetCluster`]

use crate::{
    config::{self, PYTHON_IMPORTS},
    util::{statsd_exporter_version, superset_version},
    APP_NAME, APP_PORT,
};
use indoc::formatdoc;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{
        ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodBuilder,
        PodSecurityContextBuilder, SecretOperatorVolumeSourceBuilder, VolumeBuilder,
    },
    commons::{
        authentication::{AuthenticationClass, AuthenticationClassProvider},
        secret_class::SecretClassVolumeScope,
        tls::{CaCert, TlsServerVerification, TlsVerification},
    },
    k8s_openapi::{
        api::{
            apps::v1::{StatefulSet, StatefulSetSpec},
            core::v1::{
                ConfigMap, ConfigMapVolumeSource, Service, ServicePort, ServiceSpec, Volume,
            },
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    kube::{
        runtime::{controller::Action, reflector::ObjectRef},
        ResourceExt,
    },
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
    supersetdb::{SupersetDB, SupersetDBStatusCondition},
    SupersetCluster, SupersetConfig, SupersetConfigOptions, SupersetRole, PYTHONPATH,
    SUPERSET_CONFIG_FILENAME,
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};
use strum::{EnumDiscriminants, IntoStaticStr};
use tracing::log::debug;

const FIELD_MANAGER_SCOPE: &str = "supersetcluster";

const METRICS_PORT_NAME: &str = "metrics";
const METRICS_PORT: i32 = 9102;
pub const SECRETS_DIR: &str = "/stackable/secrets/";
pub const CERTS_DIR: &str = "/stackable/certificates/";

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
    #[snafu(display("Superset doesn't support the AuthenticationClass provider {authentication_class_provider} from AuthenticationClass {authentication_class}"))]
    AuthenticationClassProviderNotSupported {
        authentication_class_provider: String,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
    #[snafu(display("failed to retrieve AuthenticationClass {authentication_class}"))]
    AuthenticationClassRetrieval {
        source: stackable_operator::error::Error,
        authentication_class: ObjectRef<AuthenticationClass>,
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

    // Ensure DB Schema exists
    let superset_db = SupersetDB::for_superset(&superset).context(CreateSupersetObjectSnafu)?;
    client
        .apply_patch(FIELD_MANAGER_SCOPE, &superset_db, &superset_db)
        .await
        .context(ApplySupersetDBSnafu)?;

    let superset_db = client
        .get::<SupersetDB>(&superset.name(), superset.namespace().as_deref())
        .await
        .context(SupersetDBRetrievalSnafu)?;

    if let Some(ref status) = superset_db.status {
        match status.condition {
            SupersetDBStatusCondition::Pending | SupersetDBStatusCondition::Initializing => {
                debug!(
                    "Waiting for SupersetDB initialization to complete, not starting Superset yet"
                );
                return Ok(Action::await_change());
            }
            SupersetDBStatusCondition::Failed => {
                return SupersetDBFailedSnafu {
                    superset_db: ObjectRef::from_obj(&superset_db),
                }
                .fail();
            }
            SupersetDBStatusCondition::Ready => (), // Continue starting Superset
        }
    } else {
        debug!("Waiting for SupersetDBStatus to be reported, not starting Superset yet");
        return Ok(Action::await_change());
    }

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
        &ctx.product_config,
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

    let authentication_class = match &superset.spec.authentication_config {
        Some(authentication_config) => {
            match &authentication_config.authentication_class {
                Some(authentication_class) => {
                    Some(
                        client
                            .get::<AuthenticationClass>(authentication_class, None) // AuthenticationClass has ClusterScope
                            .await
                            .context(AuthenticationClassRetrievalSnafu {
                                authentication_class: ObjectRef::<AuthenticationClass>::new(
                                    authentication_class,
                                ),
                            })?,
                    )
                }
                None => None,
            }
        }
        None => None,
    };

    for (rolegroup_name, rolegroup_config) in role_node_config.iter() {
        let rolegroup = superset.node_rolegroup_ref(rolegroup_name);

        let rg_service = build_node_rolegroup_service(&rolegroup, &superset)?;
        let rg_configmap = build_rolegroup_config_map(
            &superset,
            &rolegroup,
            rolegroup_config,
            authentication_class.as_ref(),
        )?;
        let rg_statefulset = build_server_rolegroup_statefulset(
            &rolegroup,
            &superset,
            rolegroup_config,
            authentication_class.as_ref(),
        )?;
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
fn build_node_role_service(superset: &SupersetCluster) -> Result<Service> {
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
    authentication_class: Option<&AuthenticationClass>,
) -> Result<ConfigMap, Error> {
    let mut config = rolegroup_config
        .get(&PropertyNameKind::File(
            SUPERSET_CONFIG_FILENAME.to_string(),
        ))
        .cloned()
        .unwrap_or_default();

    config::add_superset_config(
        &mut config,
        superset.spec.authentication_config.as_ref(),
        authentication_class,
    );

    let mut config_file = Vec::new();
    flask_app_config_writer::write::<SupersetConfigOptions, _, _>(
        &mut config_file,
        config.iter(),
        PYTHON_IMPORTS,
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
fn build_server_rolegroup_statefulset(
    rolegroup_ref: &RoleGroupRef<SupersetCluster>,
    superset: &SupersetCluster,
    node_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    authentication_class: Option<&AuthenticationClass>,
) -> Result<StatefulSet> {
    let rolegroup = superset
        .spec
        .nodes
        .as_ref()
        .context(NoNodeRoleSnafu)?
        .role_groups
        .get(&rolegroup_ref.role_group);

    let superset_version = superset_version(superset).context(NoSupersetVersionSnafu)?;

    let image = format!("docker.stackable.tech/stackable/superset:{superset_version}");

    let statsd_exporter_version =
        statsd_exporter_version(superset).context(NoStatsdExporterVersionSnafu)?;

    let statsd_exporter_image =
        format!("docker.stackable.tech/prom/statsd-exporter:{statsd_exporter_version}");

    let mut cb = ContainerBuilder::new("superset");
    let mut pb = PodBuilder::new();

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
        } else if name == SupersetConfig::MAPBOX_SECRET_PROPERTY {
            cb.add_env_var_from_secret("MAPBOX_API_KEY", &value, "connections.mapboxApiKey");
        } else {
            cb.add_env_var(name, value);
        };
    }

    if let Some(authentication_class) = authentication_class {
        add_authentication_volumes_and_volume_mounts(authentication_class, &mut cb, &mut pb)?;
    }

    let webserver_timeout = node_config
        .get(&PropertyNameKind::File("superset_config.py".to_string()))
        .unwrap()
        .get(&SupersetConfigOptions::SupersetWebserverTimeout.to_string())
        .unwrap();

    let container = cb
        .image(image)
        .add_container_port("http", APP_PORT.into())
        .add_volume_mount("config", PYTHONPATH)
        .command(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            formatdoc! {"
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
            .with_label("restarter.stackable.tech/enabled", "true")
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
            template: pb
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
                .security_context(PodSecurityContextBuilder::new().fs_group(1000).build()) // Needed for secret-operator
                .build_template(),
            ..StatefulSetSpec::default()
        }),
        status: None,
    })
}

fn add_authentication_volumes_and_volume_mounts(
    authentication_class: &AuthenticationClass,
    cb: &mut ContainerBuilder,
    pb: &mut PodBuilder,
) -> Result<()> {
    let authentication_class_name = authentication_class.metadata.name.as_ref().unwrap();

    match &authentication_class.spec.provider {
        AuthenticationClassProvider::Ldap(ldap) => {
            if let Some(bind_credentials) = &ldap.bind_credentials {
                let volume_name = format!("{authentication_class_name}-bind-credentials");

                pb.add_volume(build_secret_operator_volume(
                    &volume_name,
                    &bind_credentials.secret_class,
                    bind_credentials.scope.as_ref(),
                ));
                cb.add_volume_mount(&volume_name, format!("{SECRETS_DIR}{volume_name}"));
            }

            if let Some(tls) = &ldap.tls {
                match &tls.verification {
                    TlsVerification::Server(TlsServerVerification {
                        ca_cert: CaCert::SecretClass(cert_secret_class),
                    }) => {
                        let volume_name = format!("{authentication_class_name}-tls-certificate");

                        pb.add_volume(build_secret_operator_volume(
                            &volume_name,
                            cert_secret_class,
                            None,
                        ));
                        cb.add_volume_mount(&volume_name, format!("{CERTS_DIR}{volume_name}"));
                    }
                    // Explicitly listing other possibilities to not oversee new enum variants in the future
                    TlsVerification::None {}
                    | TlsVerification::Server(TlsServerVerification {
                        ca_cert: CaCert::WebPki {},
                    }) => {}
                }
            }

            Ok(())
        }
        _ => AuthenticationClassProviderNotSupportedSnafu {
            authentication_class_provider: authentication_class.spec.provider.to_string(),
            authentication_class: ObjectRef::<AuthenticationClass>::new(authentication_class_name),
        }
        .fail(),
    }
}

fn build_secret_operator_volume(
    volume_name: &str,
    secret_class_name: &str,
    scope: Option<&SecretClassVolumeScope>,
) -> Volume {
    let mut secret_operator_volume_source_builder =
        SecretOperatorVolumeSourceBuilder::new(secret_class_name);

    if let Some(scope) = scope {
        if scope.pod {
            secret_operator_volume_source_builder.with_pod_scope();
        }
        if scope.node {
            secret_operator_volume_source_builder.with_node_scope();
        }
        for service in &scope.services {
            secret_operator_volume_source_builder.with_service_scope(service);
        }
    }

    VolumeBuilder::new(volume_name)
        .ephemeral(secret_operator_volume_source_builder.build())
        .build()
}

pub fn error_policy(_error: &Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(5))
}
