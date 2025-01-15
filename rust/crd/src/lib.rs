use std::collections::BTreeMap;

use authentication::SupersetClientAuthenticationDetails;
use product_config::flask_app_config_writer::{FlaskAppConfigOptions, PythonType};
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    commons::{
        affinity::StackableAffinity,
        cluster_operation::ClusterOperation,
        opa::OpaConfig,
        product_image_selection::ProductImage,
        resources::{
            CpuLimitsFragment, MemoryLimitsFragment, NoRuntimeLimits, NoRuntimeLimitsFragment,
            Resources, ResourcesFragment,
        },
    },
    config::{fragment, fragment::Fragment, fragment::ValidationError, merge::Merge},
    k8s_openapi::apimachinery::pkg::api::resource::Quantity,
    kube::{runtime::reflector::ObjectRef, CustomResource, ResourceExt},
    memory::{BinaryMultiple, MemoryQuantity},
    product_config_utils::{self, Configuration},
    product_logging::{self, spec::Logging},
    role_utils::{GenericRoleConfig, Role, RoleGroupRef},
    schemars::{self, JsonSchema},
    status::condition::{ClusterCondition, HasStatusCondition},
    time::Duration,
};
use strum::{Display, EnumIter, EnumString, IntoEnumIterator};

use crate::affinity::get_affinity;

pub mod affinity;
pub mod authentication;
pub mod druidconnection;

pub const APP_NAME: &str = "superset";
pub const STACKABLE_CONFIG_DIR: &str = "/stackable/config";
pub const STACKABLE_LOG_CONFIG_DIR: &str = "/stackable/log_config";
pub const STACKABLE_LOG_DIR: &str = "/stackable/log";
pub const PYTHONPATH: &str = "/stackable/app/pythonpath";
pub const SUPERSET_CONFIG_FILENAME: &str = "superset_config.py";
pub const MAX_LOG_FILES_SIZE: MemoryQuantity = MemoryQuantity {
    value: 10.0,
    unit: BinaryMultiple::Mebi,
};

const DEFAULT_NODE_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_minutes_unchecked(2);

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("unknown Superset role found {role}. Should be one of {roles:?}"))]
    UnknownSupersetRole { role: String, roles: Vec<String> },

    #[snafu(display("fragment validation failure"))]
    FragmentValidationFailure { source: ValidationError },
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
    StackableOpaBaseUrl,
    StackableOpaPackage,
    StackableOpaRule,
    OpaRolesCacheTTL,
}

impl SupersetConfigOptions {
    /// Mapping from `SupersetConfigOptions` to the values set in `SupersetConfigFragment`.
    /// `None` is returned if either the according option is not set or is not exposed in the
    /// `SupersetConfig`.
    fn config_type_to_string(&self, superset_config: &SupersetConfigFragment) -> Option<String> {
        match self {
            SupersetConfigOptions::RowLimit => superset_config.row_limit.map(|v| v.to_string()),
            SupersetConfigOptions::SupersetWebserverTimeout => {
                superset_config.webserver_timeout.map(|v| v.to_string())
            }
            _ => None,
        }
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
            SupersetConfigOptions::AuthUserRegistrationRole => PythonType::Expression,
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
            SupersetConfigOptions::StackableOpaBaseUrl => PythonType::StringLiteral,
            SupersetConfigOptions::StackableOpaPackage => PythonType::StringLiteral,
            SupersetConfigOptions::StackableOpaRule => PythonType::StringLiteral,
            SupersetConfigOptions::OpaRolesCacheTTL => PythonType::IntLiteral,
        }
    }
}

/// A Superset cluster stacklet. This resource is managed by the Stackable operator for Apache Superset.
/// Find more information on how to use it and the resources that the operator generates in the
/// [operator documentation](DOCS_BASE_URL_PLACEHOLDER/superset/).
#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "superset.stackable.tech",
    version = "v1alpha1",
    kind = "SupersetCluster",
    plural = "supersetclusters",
    shortname = "superset",
    status = "SupersetClusterStatus",
    namespaced,
    crates(
        kube_core = "stackable_operator::kube::core",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct SupersetClusterSpec {
    // no doc - docs in the struct.
    pub image: ProductImage,

    /// Settings that affect all roles and role groups.
    /// The settings in the `clusterConfig` are cluster wide settings that do not need to be configurable at role or role group level.
    pub cluster_config: SupersetClusterConfig,

    // no doc - docs in the struct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Role<SupersetConfigFragment>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetClusterConfig {
    /// List of AuthenticationClasses used to authenticate users.
    #[serde(default)]
    pub authentication: Vec<SupersetClientAuthenticationDetails>,

    /// Authorziation options for Superset.
    /// Currently only role mapping is enabled. This means if a user logs in and Opa authorization is enabled
    /// user roles got synced from opa into superset roles. Roles get created automated.
    /// Warning: This will discard all roles managed by the superset administrator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<SupersetAuthorization>,

    /// The name of the Secret object containing the admin user credentials and database connection details.
    /// Read the
    /// [getting started guide first steps](DOCS_BASE_URL_PLACEHOLDER/superset/getting_started/first_steps)
    /// to find out more.
    pub credentials_secret: String,

    /// Cluster operations like pause reconciliation or cluster stop.
    #[serde(default)]
    pub cluster_operation: ClusterOperation,

    /// This field controls which type of Service the Operator creates for this SupersetCluster:
    ///
    /// * cluster-internal: Use a ClusterIP service
    ///
    /// * external-unstable: Use a NodePort service
    ///
    /// * external-stable: Use a LoadBalancer service
    ///
    /// This is a temporary solution with the goal to keep yaml manifests forward compatible.
    /// In the future, this setting will control which [ListenerClass](DOCS_BASE_URL_PLACEHOLDER/listener-operator/listenerclass.html)
    /// will be used to expose the service, and ListenerClass names will stay the same, allowing for a non-breaking change.
    #[serde(default)]
    pub listener_class: CurrentlySupportedListenerClasses,

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
    pub vector_aggregator_config_map_name: Option<String>,
}

// TODO: Temporary solution until listener-operator is finished
#[derive(Clone, Debug, Default, Display, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum CurrentlySupportedListenerClasses {
    #[default]
    #[serde(rename = "cluster-internal")]
    ClusterInternal,

    #[serde(rename = "external-unstable")]
    ExternalUnstable,

    #[serde(rename = "external-stable")]
    ExternalStable,
}

impl CurrentlySupportedListenerClasses {
    pub fn k8s_service_type(&self) -> String {
        match self {
            CurrentlySupportedListenerClasses::ClusterInternal => "ClusterIP".to_string(),
            CurrentlySupportedListenerClasses::ExternalUnstable => "NodePort".to_string(),
            CurrentlySupportedListenerClasses::ExternalStable => "LoadBalancer".to_string(),
        }
    }
}
#[derive(Clone, Deserialize, Serialize, Eq, JsonSchema, Debug, PartialEq)]
pub struct SupersetOpaConfig {
    #[serde(flatten)]
    pub opa: OpaConfig,
    #[serde(default = "opa_rule_name_default")]
    pub rule_name: String,
    #[serde(default = "ttl_default_time")]
    pub ttl: i8,
}

fn ttl_default_time() -> i8 {
    10
}
fn opa_rule_name_default() -> String {
    "user_rules".to_string()
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetAuthorization {
    pub opa: Option<SupersetOpaConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetCredentials {
    pub admin_user: AdminUserCredentials,
    pub connections: Connections,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserCredentials {
    pub username: String,
    pub firstname: String,
    pub lastname: String,
    pub email: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Connections {
    pub secret_key: String,
    pub sqlalchemy_database_uri: String,
}

#[derive(
    Clone, Debug, Deserialize, Display, EnumIter, Eq, Hash, JsonSchema, PartialEq, Serialize,
)]
pub enum SupersetRole {
    #[strum(serialize = "node")]
    Node,
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
    pub resources: Resources<SupersetStorageConfig, NoRuntimeLimits>,

    #[fragment_attrs(serde(default))]
    pub logging: Logging<Container>,

    #[fragment_attrs(serde(default))]
    pub affinity: StackableAffinity,

    /// Time period Pods have to gracefully shut down, e.g. `30m`, `1h` or `2d`. Consult the operator documentation for details.
    #[fragment_attrs(serde(default))]
    pub graceful_shutdown_timeout: Option<Duration>,
}

impl SupersetConfig {
    pub const CREDENTIALS_SECRET_PROPERTY: &'static str = "credentialsSecret";
    pub const MAPBOX_SECRET_PROPERTY: &'static str = "mapboxSecret";

    fn default_config(cluster_name: &str, role: &SupersetRole) -> SupersetConfigFragment {
        SupersetConfigFragment {
            resources: ResourcesFragment {
                cpu: CpuLimitsFragment {
                    min: Some(Quantity("300m".to_owned())),
                    max: Some(Quantity("1200m".to_owned())),
                },
                memory: MemoryLimitsFragment {
                    limit: Some(Quantity("2Gi".to_owned())),
                    runtime_limits: NoRuntimeLimitsFragment {},
                },
                storage: SupersetStorageConfigFragment {},
            },
            logging: product_logging::spec::default_logging(),
            affinity: get_affinity(cluster_name, role),
            graceful_shutdown_timeout: Some(DEFAULT_NODE_GRACEFUL_SHUTDOWN_TIMEOUT),
            row_limit: None,
            webserver_timeout: None,
        }
    }
}

impl Configuration for SupersetConfigFragment {
    type Configurable = SupersetCluster;

    fn compute_env(
        &self,
        cluster: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, product_config_utils::Error> {
        let mut result = BTreeMap::new();
        result.insert(
            SupersetConfig::CREDENTIALS_SECRET_PROPERTY.to_string(),
            Some(cluster.spec.cluster_config.credentials_secret.clone()),
        );
        if let Some(msec) = &cluster.spec.cluster_config.mapbox_secret {
            result.insert(
                SupersetConfig::MAPBOX_SECRET_PROPERTY.to_string(),
                Some(msec.clone()),
            );
        }

        Ok(result)
    }

    fn compute_cli(
        &self,
        _cluster: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, product_config_utils::Error> {
        Ok(BTreeMap::new())
    }

    fn compute_files(
        &self,
        _cluster: &Self::Configurable,
        _role_name: &str,
        file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, product_config_utils::Error> {
        let mut result = BTreeMap::new();

        if file == SUPERSET_CONFIG_FILENAME {
            for option in SupersetConfigOptions::iter() {
                if let Some(value) = option.config_type_to_string(self) {
                    result.insert(option.to_string(), Some(value));
                }
            }
        }

        Ok(result)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetClusterStatus {
    #[serde(default)]
    pub conditions: Vec<ClusterCondition>,
}

impl HasStatusCondition for SupersetCluster {
    fn conditions(&self) -> Vec<ClusterCondition> {
        match &self.status {
            Some(status) => status.conditions.clone(),
            None => vec![],
        }
    }
}

impl SupersetCluster {
    pub fn get_role(&self, role: &SupersetRole) -> Option<&Role<SupersetConfigFragment>> {
        match role {
            SupersetRole::Node => self.spec.nodes.as_ref(),
        }
    }

    /// The name of the role-level load-balanced Kubernetes `Service`
    pub fn node_role_service_name(&self) -> Option<String> {
        self.metadata.name.clone()
    }

    /// Metadata about a node rolegroup
    pub fn node_rolegroup_ref(
        &self,
        group_name: impl Into<String>,
    ) -> RoleGroupRef<SupersetCluster> {
        RoleGroupRef {
            cluster: ObjectRef::from_obj(self),
            role: SupersetRole::Node.to_string(),
            role_group: group_name.into(),
        }
    }

    pub fn role_config(&self, role: &SupersetRole) -> Option<&GenericRoleConfig> {
        match role {
            SupersetRole::Node => self.spec.nodes.as_ref().map(|n| &n.role_config),
        }
    }

    pub fn get_opa_config(&self) -> Option<&SupersetOpaConfig> {
        self.spec
            .cluster_config
            .authorization
            .as_ref()
            .and_then(|a| a.opa.as_ref())
    }

    /// Retrieve and merge resource configs for role and role groups
    pub fn merged_config(
        &self,
        role: &SupersetRole,
        rolegroup_ref: &RoleGroupRef<SupersetCluster>,
    ) -> Result<SupersetConfig, Error> {
        // Initialize the result with all default values as baseline
        let conf_defaults = SupersetConfig::default_config(&self.name_any(), role);

        let role = match role {
            SupersetRole::Node => self.spec.nodes.as_ref().context(UnknownSupersetRoleSnafu {
                role: role.to_string(),
                roles: vec![role.to_string()],
            })?,
        };

        // Retrieve role resource config
        let mut conf_role = role.config.config.to_owned();

        // Retrieve rolegroup specific resource config
        let mut conf_rolegroup = role
            .role_groups
            .get(&rolegroup_ref.role_group)
            .map(|rg| rg.config.config.clone())
            .unwrap_or_default();

        // Merge more specific configs into default config
        // Hierarchy is:
        // 1. RoleGroup
        // 2. Role
        // 3. Default
        conf_role.merge(&conf_defaults);
        conf_rolegroup.merge(&conf_role);

        tracing::debug!("Merged config: {:?}", conf_rolegroup);
        fragment::validate(conf_rolegroup).context(FragmentValidationFailureSnafu)
    }
}

/// A reference to a [`SupersetCluster`]
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetClusterRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}
