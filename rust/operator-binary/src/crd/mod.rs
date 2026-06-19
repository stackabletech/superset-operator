use std::str::FromStr;

use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stackable_operator::{
    commons::{
        affinity::StackableAffinity,
        cache::UserInformationCache,
        cluster_operation::ClusterOperation,
        opa::OpaConfig,
        product_image_selection::ProductImage,
        resources::{
            CpuLimitsFragment, MemoryLimitsFragment, NoRuntimeLimits, NoRuntimeLimitsFragment,
            Resources, ResourcesFragment,
        },
    },
    config::{fragment::Fragment, merge::Merge},
    deep_merger::ObjectOverrides,
    k8s_openapi::apimachinery::pkg::api::resource::Quantity,
    kube::{CustomResource, ResourceExt},
    memory::{BinaryMultiple, MemoryQuantity},
    product_logging::{self, spec::Logging},
    role_utils::{GenericRoleConfig, Role},
    schemars::{self, JsonSchema},
    shared::time::Duration,
    status::condition::{ClusterCondition, HasStatusCondition},
    v2::{
        config_overrides::KeyValueConfigOverrides,
        flask_config_writer::{FlaskAppConfigOptions, PythonType},
        role_utils::GenericCommonConfig,
        types::{
            common::Port,
            kubernetes::{ConfigMapName, ListenerClassName},
        },
    },
    versioned::versioned,
};
use strum::{Display, EnumIter, EnumString};

use crate::crd::{
    databases::{
        CeleryBrokerConnection, CeleryResultsBackendConnection, MetadataDatabaseConnection,
    },
    v1alpha1::SupersetRoleConfig,
};

/// Default [`ListenerClassName`] value used by the rolegroup listener.
pub const DEFAULT_LISTENER_CLASS: &str = "cluster-internal";

/// Default listener class used by the rolegroup listener.
fn default_listener_class() -> ListenerClassName {
    ListenerClassName::from_str(DEFAULT_LISTENER_CLASS)
        .expect("the default listener class is a valid listener class name")
}

pub mod affinity;
pub mod authentication;
pub mod authorization;
pub mod databases;
pub mod druidconnection;

pub const FIELD_MANAGER: &str = "superset-operator";
pub const APP_NAME: &str = "superset";
pub const STACKABLE_CONFIG_DIR: &str = "/stackable/config";
pub const STACKABLE_LOG_CONFIG_DIR: &str = "/stackable/log_config";
pub const PYTHONPATH: &str = "/stackable/app/pythonpath";
pub const MAX_LOG_FILES_SIZE: MemoryQuantity = MemoryQuantity {
    value: 10.0,
    unit: BinaryMultiple::Mebi,
};

pub const INTERNAL_SECRET_SECRET_KEY: &str = "SECRET_KEY";

/// Env-var prefix for the metadata database connection credentials (e.g. `METADATA_DATABASE_*`).
pub const METADATA_DATABASE_ENV_PREFIX: &str = "METADATA";

pub const APP_PORT_NAME: &str = "http";
pub const APP_PORT: Port = Port(8088);
pub const METRICS_PORT_NAME: &str = "metrics";
pub const METRICS_PORT: Port = Port(9102);

const DEFAULT_NODE_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_minutes_unchecked(2);

pub type SupersetRoleType = Role<
    v1alpha1::SupersetConfigFragment,
    v1alpha1::SupersetConfigOverrides,
    SupersetRoleConfig,
    GenericCommonConfig,
>;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Configuration/Executor conflict!"))]
    NoRoleForExecutorFailure,

    #[snafu(display("object has no associated namespace"))]
    NoNamespace,
}

#[derive(Display, EnumIter, EnumString)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum SupersetConfigOptions {
    SecretKey,
    SqlalchemyDatabaseUri,
    StatsLogger,
    RowLimit,
    MapboxApiKey,
    OauthProviders,
    SupersetWebserverTimeout,
    LoggingConfigurator,
    AuthType,
    AuthUserRegistration,
    AuthUserRegistrationRole,
    AuthRolesSyncAtLogin,
    AuthLdapServer,
    AuthLdapBindUser,
    AuthLdapBindPassword,
    AuthLdapSearch,
    AuthLdapSearchFilter,
    AuthLdapUidField,
    AuthLdapGroupField,
    AuthLdapFirstnameField,
    AuthLdapLastnameField,
    AuthLdapEmailField,
    AuthLdapAllowSelfSigned,
    AuthLdapTlsDemand,
    AuthLdapTlsCertfile,
    AuthLdapTlsKeyfile,
    AuthLdapTlsCacertfile,
    CustomSecurityManager,
    AuthOpaRequestUrl,
    AuthOpaPackage,
    AuthOpaRule,
    AuthOpaCacheMaxEntries,
    AuthOpaCacheTtlInSec,
    // Flask AppBuilder (currently) requires this to be set, even if not used,
    // otherwise the web UI cannot be used,
    RecaptchaPublicKey,
}

#[versioned(
    version(name = "v1alpha1"),
    crates(
        kube_core = "stackable_operator::kube::core",
        kube_client = "stackable_operator::kube::client",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars",
        versioned = "stackable_operator::versioned"
    )
)]
pub mod versioned {
    /// A Superset cluster stacklet. This resource is managed by the Stackable operator for Apache Superset.
    /// Find more information on how to use it and the resources that the operator generates in the
    /// [operator documentation](DOCS_BASE_URL_PLACEHOLDER/superset/).
    #[versioned(crd(
        group = "superset.stackable.tech",
        plural = "supersetclusters",
        shortname = "superset",
        status = "v1alpha1::SupersetClusterStatus",
        namespaced,
    ))]
    #[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SupersetClusterSpec {
        // no doc - docs in the struct.
        pub image: ProductImage,

        /// Settings that affect all roles and role groups.
        /// The settings in the `clusterConfig` are cluster wide settings that do not need to be configurable at role or role group level.
        pub cluster_config: v1alpha1::SupersetClusterConfig,

        // no doc - docs in the struct.
        #[serde(default)]
        pub object_overrides: ObjectOverrides,

        // no doc - docs in the struct.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nodes: Option<SupersetRoleType>,

        // no doc - docs in the struct.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub workers: Option<SupersetRoleType>,

        // no doc - docs in the struct.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub beat: Option<SupersetRoleType>,
    }

    // TODO: move generic version to op-rs?
    #[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SupersetRoleConfig {
        #[serde(flatten)]
        pub common: GenericRoleConfig,

        /// This field controls which [ListenerClass](https://docs.stackable.tech/home/nightly/listener-operator/listenerclass.html) is used to expose the webserver.
        #[serde(default = "default_listener_class")]
        pub listener_class: ListenerClassName,
    }

    #[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, Merge, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SupersetConfigOverrides {
        #[serde(default, rename = "superset_config.py")]
        pub superset_config_py: KeyValueConfigOverrides,
    }

    #[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SupersetClusterConfig {
        /// List of AuthenticationClasses used to authenticate users.
        #[serde(default)]
        pub authentication: Vec<authentication::v1alpha1::SupersetClientAuthenticationDetails>,

        /// Authorization options for Superset.
        ///
        /// Currently only role assignment is supported. This means that roles are assigned to users in
        /// OPA but, due to the way Superset is implemented, the database also needs to be updated
        /// to reflect these assignments.
        /// Therefore, user roles and permissions must already exist in the Superset database before
        /// they can be assigned to a user.
        /// Warning: Any user roles assigned with the Superset UI are discarded.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub authorization: Option<v1alpha1::SupersetAuthorization>,

        /// Configure the database where Superset stores all its internal metadata.
        pub metadata_database: MetadataDatabaseConnection,

        /// Connection information for the celery backend database.
        /// Only works if `workers` (and `beat`) roles are set.
        ///
        /// Ignored otherwise.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub celery_results_backend: Option<CeleryResultsBackendConnection>,

        /// Connection information for the celery broker queue.
        ///
        /// Only works if `workers` (and `beat`) roles are set.
        /// Ignored otherwise.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub celery_broker: Option<CeleryBrokerConnection>,

        /// The name of the Secret object containing the admin user credentials.
        /// Read the
        /// [getting started guide first steps](DOCS_BASE_URL_PLACEHOLDER/superset/getting_started/first_steps)
        /// to find out more.
        pub credentials_secret_name: String,

        /// Cluster operations like pause reconciliation or cluster stop.
        #[serde(default)]
        pub cluster_operation: ClusterOperation,

        /// The name of a Secret object.
        /// The Secret should contain a key `connections.mapboxApiKey`.
        /// This is the API key required for map charts to work that use mapbox.
        /// The token should be in the JWT format.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mapbox_secret: Option<String>,

        /// Name of the Vector aggregator [discovery ConfigMap](DOCS_BASE_URL_PLACEHOLDER/concepts/service_discovery).
        /// It must contain the key `ADDRESS` with the address of the Vector aggregator.
        /// Follow the [logging tutorial](DOCS_BASE_URL_PLACEHOLDER/tutorials/logging-vector-aggregator)
        /// to learn how to configure log aggregation with Vector.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub vector_aggregator_config_map_name: Option<ConfigMapName>,
    }

    #[derive(Clone, Debug, Default, Fragment, JsonSchema, PartialEq)]
    #[fragment_attrs(
        derive(
            Clone,
            Debug,
            Default,
            Deserialize,
            Merge,
            JsonSchema,
            PartialEq,
            Serialize
        ),
        serde(rename_all = "camelCase")
    )]
    pub struct SupersetConfig {
        /// Row limit when requesting chart data. Corresponds to ROW_LIMIT.
        pub row_limit: Option<i32>,

        /// Maximum time period a Superset request can take before timing out. This
        /// setting affects the maximum duration a query to an underlying datasource
        /// can take. If you get timeout errors before your query returns the result
        /// you may need to increase this timeout. Corresponds to
        /// SUPERSET_WEBSERVER_TIMEOUT.
        pub webserver_timeout: Option<u32>,

        /// CPU and memory limits for Superset pods
        #[fragment_attrs(serde(default))]
        pub resources: Resources<v1alpha1::SupersetStorageConfig, NoRuntimeLimits>,

        #[fragment_attrs(serde(default))]
        pub logging: Logging<v1alpha1::Container>,

        #[fragment_attrs(serde(default))]
        pub affinity: StackableAffinity,

        /// Time period Pods have to gracefully shut down, e.g. `30m`, `1h` or `2d`. Consult the operator documentation for details.
        #[fragment_attrs(serde(default))]
        pub graceful_shutdown_timeout: Option<Duration>,
    }

    #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SupersetAuthorization {
        pub role_mapping_from_opa: v1alpha1::SupersetOpaRoleMappingConfig,
    }

    #[derive(Clone, Deserialize, Serialize, Eq, JsonSchema, Debug, PartialEq)]
    #[serde(rename_all = "camelCase")]
    pub struct SupersetOpaRoleMappingConfig {
        #[serde(flatten)]
        pub opa: OpaConfig,

        /// Configuration for an Superset internal cache for calls to OPA
        #[serde(default)]
        pub cache: UserInformationCache,
    }

    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, Debug, Default, JsonSchema, PartialEq, Fragment)]
    #[fragment_attrs(
        allow(clippy::derive_partial_eq_without_eq),
        derive(
            Clone,
            Debug,
            Default,
            Deserialize,
            Merge,
            JsonSchema,
            PartialEq,
            Serialize
        ),
        serde(rename_all = "camelCase")
    )]
    pub struct SupersetStorageConfig {}

    #[derive(
        Clone,
        Debug,
        Deserialize,
        Display,
        Eq,
        EnumIter,
        JsonSchema,
        Ord,
        PartialEq,
        PartialOrd,
        Serialize,
    )]
    #[serde(rename_all = "kebab-case")]
    #[strum(serialize_all = "kebab-case")]
    pub enum Container {
        Superset,
        Vector,
    }

    #[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SupersetClusterStatus {
        #[serde(default)]
        pub conditions: Vec<ClusterCondition>,
    }
}

impl Default for v1alpha1::SupersetRoleConfig {
    fn default() -> Self {
        v1alpha1::SupersetRoleConfig {
            listener_class: default_listener_class(),
            common: Default::default(),
        }
    }
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Display,
    EnumIter,
    EnumString,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub enum SupersetRole {
    #[strum(serialize = "node")]
    Node,
    #[strum(serialize = "worker")]
    Worker,
    #[strum(serialize = "beat")]
    Beat,
}

impl SupersetRole {
    pub fn listener_class_name(
        &self,
        superset: &v1alpha1::SupersetCluster,
    ) -> Option<ListenerClassName> {
        match self {
            Self::Node => superset
                .spec
                .nodes
                .to_owned()
                .map(|node| node.role_config.listener_class),
            Self::Worker | Self::Beat => None,
        }
    }

    pub fn role_name(&self) -> stackable_operator::v2::types::operator::RoleName {
        self.to_string()
            .parse()
            .expect("a Superset serialises to a valid RoleName")
    }
}

impl FlaskAppConfigOptions for SupersetConfigOptions {
    fn python_type(&self) -> PythonType {
        match self {
            SupersetConfigOptions::SecretKey => PythonType::Expression,
            SupersetConfigOptions::SqlalchemyDatabaseUri => PythonType::Expression,
            SupersetConfigOptions::StatsLogger => PythonType::Expression,
            SupersetConfigOptions::RowLimit => PythonType::IntLiteral,
            SupersetConfigOptions::MapboxApiKey => PythonType::Expression,
            SupersetConfigOptions::OauthProviders => PythonType::Expression,
            SupersetConfigOptions::SupersetWebserverTimeout => PythonType::IntLiteral,
            SupersetConfigOptions::LoggingConfigurator => PythonType::Expression,
            SupersetConfigOptions::AuthType => PythonType::Expression,
            SupersetConfigOptions::AuthUserRegistration => PythonType::BoolLiteral,
            // Going to be an expression as we default it from env, if and only if opa is used
            SupersetConfigOptions::AuthUserRegistrationRole => PythonType::StringLiteral,
            SupersetConfigOptions::AuthRolesSyncAtLogin => PythonType::BoolLiteral,
            SupersetConfigOptions::AuthLdapServer => PythonType::StringLiteral,
            SupersetConfigOptions::AuthLdapBindUser => PythonType::Expression,
            SupersetConfigOptions::AuthLdapBindPassword => PythonType::Expression,
            SupersetConfigOptions::AuthLdapSearch => PythonType::StringLiteral,
            SupersetConfigOptions::AuthLdapSearchFilter => PythonType::StringLiteral,
            SupersetConfigOptions::AuthLdapUidField => PythonType::StringLiteral,
            SupersetConfigOptions::AuthLdapGroupField => PythonType::StringLiteral,
            SupersetConfigOptions::AuthLdapFirstnameField => PythonType::StringLiteral,
            SupersetConfigOptions::AuthLdapLastnameField => PythonType::StringLiteral,
            SupersetConfigOptions::AuthLdapEmailField => PythonType::StringLiteral,
            SupersetConfigOptions::AuthLdapAllowSelfSigned => PythonType::BoolLiteral,
            SupersetConfigOptions::AuthLdapTlsDemand => PythonType::BoolLiteral,
            SupersetConfigOptions::AuthLdapTlsCertfile => PythonType::StringLiteral,
            SupersetConfigOptions::AuthLdapTlsKeyfile => PythonType::StringLiteral,
            SupersetConfigOptions::AuthLdapTlsCacertfile => PythonType::StringLiteral,
            // Configuration options used by CustomOpaSecurityManager
            SupersetConfigOptions::CustomSecurityManager => PythonType::Expression,
            SupersetConfigOptions::AuthOpaRequestUrl => PythonType::StringLiteral,
            SupersetConfigOptions::AuthOpaPackage => PythonType::StringLiteral,
            SupersetConfigOptions::AuthOpaRule => PythonType::StringLiteral,
            SupersetConfigOptions::AuthOpaCacheMaxEntries => PythonType::IntLiteral,
            SupersetConfigOptions::AuthOpaCacheTtlInSec => PythonType::IntLiteral,
            // Flask AppBuilder (currently) requires this option to be set (even if empty).
            // If we set it to a string, the user cannot then get it from an expression in
            // configOverrides. So we make it an expression, but will need to manually quote the
            // empty string as a default.
            SupersetConfigOptions::RecaptchaPublicKey => PythonType::Expression,
        }
    }
}

impl v1alpha1::SupersetConfig {
    pub(crate) fn default_config(
        cluster_name: &str,
        role: &SupersetRole,
    ) -> v1alpha1::SupersetConfigFragment {
        match role {
            SupersetRole::Node => v1alpha1::SupersetConfigFragment {
                resources: ResourcesFragment {
                    cpu: CpuLimitsFragment {
                        min: Some(Quantity("300m".to_owned())),
                        max: Some(Quantity("1200m".to_owned())),
                    },
                    memory: MemoryLimitsFragment {
                        limit: Some(Quantity("2Gi".to_owned())),
                        runtime_limits: NoRuntimeLimitsFragment {},
                    },
                    storage: v1alpha1::SupersetStorageConfigFragment {},
                },
                logging: product_logging::spec::default_logging(),
                affinity: affinity::get_affinity(cluster_name, role),
                graceful_shutdown_timeout: Some(DEFAULT_NODE_GRACEFUL_SHUTDOWN_TIMEOUT),
                row_limit: None,
                webserver_timeout: None,
            },
            SupersetRole::Worker => v1alpha1::SupersetConfigFragment {
                resources: ResourcesFragment {
                    cpu: CpuLimitsFragment {
                        min: Some(Quantity("1000m".to_owned())),
                        max: Some(Quantity("2000m".to_owned())),
                    },
                    memory: MemoryLimitsFragment {
                        limit: Some(Quantity("4Gi".to_owned())),
                        runtime_limits: NoRuntimeLimitsFragment {},
                    },
                    storage: v1alpha1::SupersetStorageConfigFragment {},
                },
                logging: product_logging::spec::default_logging(),
                affinity: affinity::get_affinity(cluster_name, role),
                graceful_shutdown_timeout: Some(DEFAULT_NODE_GRACEFUL_SHUTDOWN_TIMEOUT),
                row_limit: None,
                webserver_timeout: None,
            },
            SupersetRole::Beat => v1alpha1::SupersetConfigFragment {
                resources: ResourcesFragment {
                    cpu: CpuLimitsFragment {
                        min: Some(Quantity("100m".to_owned())),
                        max: Some(Quantity("500m".to_owned())),
                    },
                    memory: MemoryLimitsFragment {
                        limit: Some(Quantity("1Gi".to_owned())),
                        runtime_limits: NoRuntimeLimitsFragment {},
                    },
                    storage: v1alpha1::SupersetStorageConfigFragment {},
                },
                logging: product_logging::spec::default_logging(),
                affinity: affinity::get_affinity(cluster_name, role),
                graceful_shutdown_timeout: Some(DEFAULT_NODE_GRACEFUL_SHUTDOWN_TIMEOUT),
                row_limit: None,
                webserver_timeout: None,
            },
        }
    }
}

impl HasStatusCondition for v1alpha1::SupersetCluster {
    fn conditions(&self) -> Vec<ClusterCondition> {
        match &self.status {
            Some(status) => status.conditions.clone(),
            None => vec![],
        }
    }
}

impl v1alpha1::SupersetCluster {
    pub fn shared_secret_key_secret_name(&self) -> String {
        format!("{}-secret-key", &self.name_any())
    }

    /// The connection to the metadata database.
    pub fn metadata_database(&self) -> &MetadataDatabaseConnection {
        &self.spec.cluster_config.metadata_database
    }

    /// The name of the group-listener provided for a specific role.
    /// Nodes will use this group listener so that only one load balancer
    /// is needed for that role.
    pub fn group_listener_name(&self, role: &SupersetRole) -> Option<String> {
        match role {
            SupersetRole::Node => Some(format!(
                "{cluster_name}-{role}",
                cluster_name = self.name_any()
            )),
            SupersetRole::Worker | SupersetRole::Beat => None,
        }
    }

    pub fn generic_role_config(&self, role: &SupersetRole) -> Option<GenericRoleConfig> {
        self.get_role_config(role).map(|r| r.common.to_owned())
    }

    pub fn get_role_config(&self, role: &SupersetRole) -> Option<&SupersetRoleConfig> {
        self.get_role(role).as_ref().map(|c| &c.role_config)
    }

    pub fn get_role(&self, role: &SupersetRole) -> Option<&SupersetRoleType> {
        match role {
            SupersetRole::Node => self.spec.nodes.as_ref(),
            SupersetRole::Worker => self.spec.workers.as_ref(),
            SupersetRole::Beat => self.spec.beat.as_ref(),
        }
    }

    pub fn get_opa_config(&self) -> Option<&v1alpha1::SupersetOpaRoleMappingConfig> {
        self.spec
            .cluster_config
            .authorization
            .as_ref()
            .map(|a| &a.role_mapping_from_opa)
    }
}

#[cfg(test)]
mod tests {
    use stackable_operator::versioned::test_utils::RoundtripTestData;

    use super::v1alpha1;

    impl RoundtripTestData for v1alpha1::SupersetClusterSpec {
        fn roundtrip_test_data() -> Vec<Self> {
            stackable_operator::utils::yaml_from_str_singleton_map(indoc::indoc! {r#"
              - image:
                  productVersion: 1.2.3
                  pullPolicy: IfNotPresent
                clusterOperation:
                  reconciliationPaused: false
                  stopped: true
                clusterConfig:
                  credentialsSecretName: superset-admin-credentials
                  metadataDatabase:
                    postgresql:
                      host: superset-postgresql
                      database: superset
                      credentialsSecretName: superset-postgresql-credentials
                  authentication:
                    - authenticationClass: my-ldap
                  authorization:
                    roleMappingFromOpa:
                      configMapName: opa
                      package: superset
                  vectorAggregatorConfigMapName: vector-aggregator-discovery
                nodes:
                  envOverrides:
                    COMMON_VAR: role-value
                    ROLE_VAR: role-value
                  config:
                    resources:
                      cpu:
                        min: 100m
                        max: "1"
                      memory:
                        limit: 1Gi
                    logging:
                      enableVectorAgent: true
                  configOverrides:
                    superset_config.py:
                      FILE_HEADER: |
                        COMMON_HEADER_VAR = role-value
                        ROLE_HEADER_VAR = role-value
                      FILE_FOOTER: |
                        ROLE_FOOTER_VAR = role-value
                  roleGroups:
                    default:
                      replicas: 1
                      configOverrides:
                        superset_config.py:
                          FILE_HEADER: |
                            COMMON_HEADER_VAR = "group-value"
                      envOverrides:
                        COMMON_VAR: group-value
                        GROUP_VAR: group-value
        "#})
            .expect("Failed to parse SupersetClusterSpec YAML")
        }
    }
}
