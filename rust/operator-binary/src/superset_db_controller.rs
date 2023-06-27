use crate::{
    config::{self, PYTHON_IMPORTS},
    controller_commons::{self, CONFIG_VOLUME_NAME, LOG_CONFIG_VOLUME_NAME, LOG_VOLUME_NAME},
    product_logging::{
        extend_config_map_with_log_config, resolve_vector_aggregator_address, LOG_CONFIG_FILE,
    },
    rbac,
    superset_controller::DOCKER_IMAGE_BASE_NAME,
    util::{get_job_state, JobState},
};

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::{ConfigMapBuilder, ContainerBuilder, ObjectMetaBuilder, PodSecurityContextBuilder},
    commons::product_image_selection::ResolvedProductImage,
    k8s_openapi::api::{
        batch::v1::{Job, JobSpec},
        core::v1::{ConfigMap, PodSpec, PodTemplateSpec, Secret},
    },
    kube::{
        runtime::{controller::Action, reflector::ObjectRef},
        ResourceExt,
    },
    logging::controller::ReconcilerError,
    product_config::flask_app_config_writer::{self, FlaskAppConfigWriterError},
    product_logging::{self, spec::Logging},
    role_utils::RoleGroupRef,
};
use stackable_superset_crd::{
    supersetdb::{
        InitDbContainer, SupersetDB, SupersetDBStatus, SupersetDBStatusCondition, SupersetDbConfig,
    },
    SupersetConfigOptions, APP_NAME, CONFIG_DIR, LOG_CONFIG_DIR, LOG_DIR, PYTHONPATH,
    SUPERSET_CONFIG_FILENAME,
};
use std::collections::BTreeMap;
use std::{sync::Arc, time::Duration};
use strum::{EnumDiscriminants, IntoStaticStr};

pub const SUPERSET_DB_CONTROLLER_NAME: &str = "superset-db";

pub struct Ctx {
    pub client: stackable_operator::client::Client,
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object has no namespace"))]
    ObjectHasNoNamespace,
    #[snafu(display("failed to apply Job for {}", superset_db))]
    ApplyJob {
        source: stackable_operator::error::Error,
        superset_db: ObjectRef<SupersetDB>,
    },
    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("database state is 'initializing' but failed to find job {}", init_job))]
    GetInitializationJob {
        source: stackable_operator::error::Error,
        init_job: ObjectRef<Job>,
    },
    #[snafu(display("Failed to check whether the secret ({}) exists", secret))]
    SecretCheck {
        source: stackable_operator::error::Error,
        secret: ObjectRef<Secret>,
    },
    #[snafu(display("failed to build Superset config"))]
    BuildSupersetConfig { source: FlaskAppConfigWriterError },
    #[snafu(display("failed to build ConfigMap [{name}]"))]
    BuildConfigMap {
        name: String,
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to patch ConfigMap [{name}]"))]
    ApplyConfigMap {
        name: String,
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to resolve and merge config"))]
    FailedToResolveConfig {
        source: stackable_superset_crd::supersetdb::Error,
    },
    #[snafu(display("invalid container name"))]
    InvalidContainerName {
        source: stackable_operator::error::Error,
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
    #[snafu(display("failed to patch service account"))]
    ApplyServiceAccount {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to patch role binding"))]
    ApplyRoleBinding {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("unable to find SecretClass with airflow credentials"))]
    SecretNotFound,
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub async fn reconcile_superset_db(superset_db: Arc<SupersetDB>, ctx: Arc<Ctx>) -> Result<Action> {
    tracing::info!("Starting reconcile");

    let client = &ctx.client;
    let resolved_product_image: ResolvedProductImage =
        superset_db.spec.image.resolve(DOCKER_IMAGE_BASE_NAME);

    let (rbac_sa, rbac_rolebinding) = rbac::build_rbac_resources(superset_db.as_ref(), APP_NAME);
    client
        .apply_patch(SUPERSET_DB_CONTROLLER_NAME, &rbac_sa, &rbac_sa)
        .await
        .context(ApplyServiceAccountSnafu)?;
    client
        .apply_patch(
            SUPERSET_DB_CONTROLLER_NAME,
            &rbac_rolebinding,
            &rbac_rolebinding,
        )
        .await
        .context(ApplyRoleBindingSnafu)?;

    if let Some(ref s) = superset_db.status {
        match s.condition {
            SupersetDBStatusCondition::Pending => {
                let secret_exists = client
                    .get_opt::<Secret>(
                        &superset_db.spec.credentials_secret,
                        superset_db
                            .namespace()
                            .as_deref()
                            .context(ObjectHasNoNamespaceSnafu)?,
                    )
                    .await
                    .with_context(|_| {
                        let mut secret_ref =
                            ObjectRef::<Secret>::new(&superset_db.spec.credentials_secret);
                        if let Some(ns) = superset_db.namespace() {
                            secret_ref = secret_ref.within(&ns);
                        }
                        SecretCheckSnafu { secret: secret_ref }
                    })?
                    .is_some();
                if secret_exists {
                    let vector_aggregator_address = resolve_vector_aggregator_address(
                        client,
                        superset_db.as_ref(),
                        superset_db
                            .spec
                            .vector_aggregator_config_map_name
                            .as_deref(),
                    )
                    .await
                    .context(ResolveVectorAggregatorAddressSnafu)?;

                    let config = superset_db
                        .merged_config()
                        .context(FailedToResolveConfigSnafu)?;

                    let config_map = build_config_map(
                        &superset_db,
                        &config.logging,
                        vector_aggregator_address.as_deref(),
                    )?;
                    client
                        .apply_patch(SUPERSET_DB_CONTROLLER_NAME, &config_map, &config_map)
                        .await
                        .context(ApplyConfigMapSnafu {
                            name: config_map.name_any(),
                        })?;

                    let job = build_init_job(
                        &superset_db,
                        &resolved_product_image,
                        &rbac_sa.name_any(),
                        &config,
                        &config_map.name_unchecked(),
                    )?;
                    client
                        .apply_patch(SUPERSET_DB_CONTROLLER_NAME, &job, &job)
                        .await
                        .context(ApplyJobSnafu {
                            superset_db: ObjectRef::from_obj(&*superset_db),
                        })?;
                    // The job is started, update status to reflect new state
                    client
                        .apply_patch_status(
                            SUPERSET_DB_CONTROLLER_NAME,
                            &*superset_db,
                            &s.initializing(),
                        )
                        .await
                        .context(ApplyStatusSnafu)?;
                } else {
                    return SecretNotFoundSnafu.fail(); 
                }
            }
            SupersetDBStatusCondition::Initializing => {
                // In here, check the associated job that is running.
                // If it is still running, do nothing. If it completed, set status to ready, if it failed, set status to failed.
                let ns = superset_db
                    .namespace()
                    .unwrap_or_else(|| "default".to_string());
                let job_name = superset_db.job_name();
                let job =
                    client
                        .get::<Job>(&job_name, &ns)
                        .await
                        .context(GetInitializationJobSnafu {
                            init_job: ObjectRef::<Job>::new(&job_name).within(&ns),
                        })?;

                let new_status = match get_job_state(&job) {
                    JobState::Complete => Some(s.ready()),
                    JobState::Failed => Some(s.failed()),
                    JobState::InProgress => None,
                };

                if let Some(ns) = new_status {
                    client
                        .apply_patch_status(SUPERSET_DB_CONTROLLER_NAME, &*superset_db, &ns)
                        .await
                        .context(ApplyStatusSnafu)?;
                }
            }
            SupersetDBStatusCondition::Ready => (),
            SupersetDBStatusCondition::Failed => (),
        }
    } else {
        // Status is none => initialize the status object as "Provisioned"
        let new_status = SupersetDBStatus::new();
        client
            .apply_patch_status(SUPERSET_DB_CONTROLLER_NAME, &*superset_db, &new_status)
            .await
            .context(ApplyStatusSnafu)?;
    }

    Ok(Action::await_change())
}

fn build_init_job(
    superset_db: &SupersetDB,
    resolved_product_image: &ResolvedProductImage,
    sa_name: &str,
    config: &SupersetDbConfig,
    config_map_name: &str,
) -> Result<Job> {
    let mut commands = vec![
        format!("mkdir -p {PYTHONPATH}"),
        format!("cp {CONFIG_DIR}/* {PYTHONPATH}"),
        format!("cp {LOG_CONFIG_DIR}/{LOG_CONFIG_FILE} {PYTHONPATH}"),
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
    if superset_db.spec.load_examples {
        commands.push(String::from("superset load_examples"));
    }
    commands.push(product_logging::framework::shutdown_vector_command(LOG_DIR));

    let secret = &superset_db.spec.credentials_secret;

    let mut containers = Vec::new();

    let mut cb = ContainerBuilder::new(&InitDbContainer::SupersetInitDb.to_string())
        .context(InvalidContainerNameSnafu)?;

    cb.image_from_product_image(resolved_product_image)
        .command(vec!["/bin/bash".to_string()])
        .args(vec![
            String::from("-euo"),
            String::from("pipefail"),
            String::from("-c"),
            commands.join("; "),
        ])
        .add_env_var_from_secret("SECRET_KEY", secret, "connections.secretKey")
        .add_env_var_from_secret(
            "SQLALCHEMY_DATABASE_URI",
            secret,
            "connections.sqlalchemyDatabaseUri",
        )
        .add_env_var_from_secret("ADMIN_USERNAME", secret, "adminUser.username")
        .add_env_var_from_secret("ADMIN_FIRSTNAME", secret, "adminUser.firstname")
        .add_env_var_from_secret("ADMIN_LASTNAME", secret, "adminUser.lastname")
        .add_env_var_from_secret("ADMIN_EMAIL", secret, "adminUser.email")
        .add_env_var_from_secret("ADMIN_PASSWORD", secret, "adminUser.password")
        .add_volume_mount(CONFIG_VOLUME_NAME, CONFIG_DIR)
        .add_volume_mount(LOG_CONFIG_VOLUME_NAME, LOG_CONFIG_DIR)
        .add_volume_mount(LOG_VOLUME_NAME, LOG_DIR);

    containers.push(cb.build());

    if config.logging.enable_vector_agent {
        containers.push(product_logging::framework::vector_container(
            resolved_product_image,
            CONFIG_VOLUME_NAME,
            LOG_VOLUME_NAME,
            config.logging.containers.get(&InitDbContainer::Vector),
        ));
    }

    let volumes = controller_commons::create_volumes(
        config_map_name,
        config
            .logging
            .containers
            .get(&InitDbContainer::SupersetInitDb),
    );

    let pod = PodTemplateSpec {
        metadata: Some(
            ObjectMetaBuilder::new()
                .name(format!("{}-init", superset_db.name_unchecked()))
                .build(),
        ),
        spec: Some(PodSpec {
            containers,
            image_pull_secrets: resolved_product_image.pull_secrets.clone(),
            restart_policy: Some("Never".to_string()),
            volumes: Some(volumes),
            service_account: Some(sa_name.to_string()),
            security_context: Some(
                PodSecurityContextBuilder::new()
                    .run_as_user(1000)
                    .run_as_group(0)
                    .build(),
            ),
            ..Default::default()
        }),
    };

    let job = Job {
        metadata: ObjectMetaBuilder::new()
            .name(superset_db.name_unchecked())
            .namespace_opt(superset_db.namespace())
            .ownerreference_from_resource(superset_db, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .build(),
        spec: Some(JobSpec {
            template: pod,
            ..Default::default()
        }),
        status: None,
    };

    Ok(job)
}

fn build_config_map(
    superset_db: &SupersetDB,
    logging: &Logging<InitDbContainer>,
    vector_aggregator_address: Option<&str>,
) -> Result<ConfigMap> {
    let mut config = BTreeMap::new();
    config::add_superset_config(&mut config, None, None);

    let mut config_file = Vec::new();
    flask_app_config_writer::write::<SupersetConfigOptions, _, _>(
        &mut config_file,
        config.iter(),
        PYTHON_IMPORTS,
    )
    .context(BuildSupersetConfigSnafu)?;

    let mut cm_builder = ConfigMapBuilder::new();

    let cm_name = format!("{cluster}-init-db", cluster = superset_db.name_unchecked());

    cm_builder
        .metadata(
            ObjectMetaBuilder::new()
                .name(&cm_name)
                .namespace_opt(superset_db.namespace())
                .ownerreference_from_resource(superset_db, None, Some(true))
                .context(ObjectMissingMetadataForOwnerRefSnafu)?
                .build(),
        )
        .add_data(
            SUPERSET_CONFIG_FILENAME,
            String::from_utf8(config_file).unwrap(),
        );

    extend_config_map_with_log_config(
        &RoleGroupRef {
            cluster: ObjectRef::from_obj(superset_db),
            role: String::new(),
            role_group: String::new(),
        },
        vector_aggregator_address,
        logging,
        &InitDbContainer::SupersetInitDb,
        &InitDbContainer::Vector,
        &mut cm_builder,
    )
    .context(InvalidLoggingConfigSnafu {
        cm_name: cm_name.to_owned(),
    })?;

    cm_builder
        .build()
        .context(BuildConfigMapSnafu { name: cm_name })
}

pub fn error_policy(_obj: Arc<SupersetDB>, _error: &Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(5))
}
