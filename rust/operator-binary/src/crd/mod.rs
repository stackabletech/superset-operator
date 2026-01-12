use std::collections::BTreeMap;

use product_config::flask_app_config_writer::{FlaskAppConfigOptions, PythonType};
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};
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
    config::{
        fragment::{self, Fragment, ValidationError},
        merge::Merge,
    },
    deep_merger::ObjectOverrides,
    k8s_openapi::apimachinery::pkg::api::resource::Quantity,
    kube::{CustomResource, ResourceExt, runtime::reflector::ObjectRef},
    memory::{BinaryMultiple, MemoryQuantity},
    product_config_utils::{self, Configuration},
    product_logging::{self, spec::Logging},
    role_utils::{GenericRoleConfig, Role, RoleGroupRef},
    schemars::{self, JsonSchema},
    shared::time::Duration,
    status::condition::{ClusterCondition, HasStatusCondition},
    versioned::versioned,
};
use strum::{Display, EnumIter, EnumString, IntoEnumIterator};

use crate::{
    crd::v1alpha1::{SupersetConfigFragment, SupersetRoleConfig},
    listener::default_listener_class,
};

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

pub const APP_PORT_NAME: &str = "http";
pub const APP_PORT: u16 = 8088;
pub const METRICS_PORT_NAME: &str = "metrics";
pub const METRICS_PORT: u16 = 9102;

const DEFAULT_NODE_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_minutes_unchecked(2);

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("unknown Superset role found {role}. Should be one of {roles:?}"))]
    UnknownSupersetRole { role: String, roles: Vec<String> },

    #[snafu(display("fragment validation failure"))]
    FragmentValidationFailure { source: ValidationError },

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
        pub nodes: Option<Role<v1alpha1::SupersetConfigFragment, SupersetRoleConfig>>,
    }

    // TODO: move generic version to op-rs?
    #[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SupersetRoleConfig {
        #[serde(flatten)]
        pub common: GenericRoleConfig,

        /// This field controls which [ListenerClass](https://docs.stackable.tech/home/nightly/listener-operator/listenerclass.html) is used to expose the webserver.
        #[serde(default = "default_listener_class")]
        pub listener_class: String,
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

        /// The name of the Secret object containing the admin user credentials and database connection details.
        /// Read the
        /// [getting started guide first steps](DOCS_BASE_URL_PLACEHOLDER/superset/getting_started/first_steps)
        /// to find out more.
        pub credentials_secret: String,

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
        pub vector_aggregator_config_map_name: Option<String>,
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

impl SupersetRole {
    pub fn listener_class_name(&self, superset: &v1alpha1::SupersetCluster) -> Option<String> {
        match self {
            Self::Node => superset
                .spec
                .nodes
                .to_owned()
                .map(|node| node.role_config.listener_class),
        }
    }
}

/// A reference to a [`v1alpha1::SupersetCluster`]
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetClusterRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

impl SupersetConfigOptions {
    /// Mapping from `SupersetConfigOptions` to the values set in `SupersetConfigFragment`.
    /// `None` is returned if either the according option is not set or is not exposed in the
    /// `SupersetConfig`.
    fn config_type_to_string(
        &self,
        superset_config: &v1alpha1::SupersetConfigFragment,
    ) -> Option<String> {
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
    pub const CREDENTIALS_SECRET_PROPERTY: &'static str = "credentialsSecret";
    pub const MAPBOX_SECRET_PROPERTY: &'static str = "mapboxSecret";

    fn default_config(cluster_name: &str, role: &SupersetRole) -> v1alpha1::SupersetConfigFragment {
        v1alpha1::SupersetConfigFragment {
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
        }
    }
}

impl Configuration for v1alpha1::SupersetConfigFragment {
    type Configurable = v1alpha1::SupersetCluster;

    fn compute_env(
        &self,
        cluster: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, product_config_utils::Error> {
        let mut result = BTreeMap::new();
        result.insert(
            v1alpha1::SupersetConfig::CREDENTIALS_SECRET_PROPERTY.to_string(),
            Some(cluster.spec.cluster_config.credentials_secret.clone()),
        );
        if let Some(msec) = &cluster.spec.cluster_config.mapbox_secret {
            result.insert(
                v1alpha1::SupersetConfig::MAPBOX_SECRET_PROPERTY.to_string(),
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

impl HasStatusCondition for v1alpha1::SupersetCluster {
    fn conditions(&self) -> Vec<ClusterCondition> {
        match &self.status {
            Some(status) => status.conditions.clone(),
            None => vec![],
        }
    }
}

impl v1alpha1::SupersetCluster {
    /// The name of the group-listener provided for a specific role.
    /// Nodes will use this group listener so that only one load balancer
    /// is needed for that role.
    pub fn group_listener_name(&self, role: &SupersetRole) -> Option<String> {
        match role {
            SupersetRole::Node => Some(format!(
                "{cluster_name}-{role}",
                cluster_name = self.name_any()
            )),
        }
    }

    pub fn generic_role_config(&self, role: &SupersetRole) -> Option<GenericRoleConfig> {
        self.get_role_config(role).map(|r| r.common.to_owned())
    }

    pub fn get_role_config(&self, role: &SupersetRole) -> Option<&SupersetRoleConfig> {
        match role {
            SupersetRole::Node => self.spec.nodes.as_ref().map(|c| &c.role_config),
        }
    }

    pub fn get_role(
        &self,
        role: &SupersetRole,
    ) -> Option<&Role<SupersetConfigFragment, SupersetRoleConfig>> {
        match role {
            SupersetRole::Node => self.spec.nodes.as_ref(),
        }
    }

    /// Metadata about a node rolegroup
    pub fn node_rolegroup_ref(
        &self,
        group_name: impl Into<String>,
    ) -> RoleGroupRef<v1alpha1::SupersetCluster> {
        RoleGroupRef {
            cluster: ObjectRef::from_obj(self),
            role: SupersetRole::Node.to_string(),
            role_group: group_name.into(),
        }
    }

    pub fn get_opa_config(&self) -> Option<&v1alpha1::SupersetOpaRoleMappingConfig> {
        self.spec
            .cluster_config
            .authorization
            .as_ref()
            .map(|a| &a.role_mapping_from_opa)
    }

    /// Retrieve and merge resource configs for role and role groups
    pub fn merged_config(
        &self,
        role: &SupersetRole,
        rolegroup_ref: &RoleGroupRef<v1alpha1::SupersetCluster>,
    ) -> Result<v1alpha1::SupersetConfig, Error> {
        // Initialize the result with all default values as baseline
        let conf_defaults = v1alpha1::SupersetConfig::default_config(&self.name_any(), role);

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
