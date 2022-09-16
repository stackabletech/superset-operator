pub mod druidconnection;
pub mod supersetdb;

use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stackable_operator::{
    commons::resources::{CpuLimits, MemoryLimits, NoRuntimeLimits, Resources},
    config::merge::Merge,
    k8s_openapi::apimachinery::pkg::api::resource::Quantity,
    kube::{runtime::reflector::ObjectRef, CustomResource},
    product_config::flask_app_config_writer::{FlaskAppConfigOptions, PythonType},
    product_config_utils::{ConfigError, Configuration},
    role_utils::{Role, RoleGroupRef},
    schemars::{self, JsonSchema},
};
use std::{collections::BTreeMap, num::ParseIntError};
use strum::{Display, EnumIter, EnumString, IntoEnumIterator};

pub const APP_NAME: &str = "superset";
pub const MANAGED_BY: &str = "superset-operator";

pub const PYTHONPATH: &str = "/stackable/app/pythonpath";
pub const SUPERSET_CONFIG_FILENAME: &str = "superset_config.py";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("invalid int config value"))]
    InvalidIntConfigValue { source: ParseIntError },
}

#[derive(Display, EnumIter, EnumString)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum SupersetConfigOptions {
    SecretKey,
    SqlalchemyDatabaseUri,
    StatsLogger,
    RowLimit,
    MapboxApiKey,
    SupersetWebserverTimeout,
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
}

impl SupersetConfigOptions {
    /// Mapping from `SupersetConfigOptions` to the values set in `SupersetConfig`.
    /// `None` is returned if either the according option is not set or is not exposed in the
    /// `SupersetConfig`.
    fn config_type_to_string(&self, superset_config: &SupersetConfig) -> Option<String> {
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
            SupersetConfigOptions::SupersetWebserverTimeout => PythonType::IntLiteral,
            SupersetConfigOptions::AuthType => PythonType::Expression,
            SupersetConfigOptions::AuthUserRegistration => PythonType::BoolLiteral,
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
        }
    }
}

pub const HTTP_PORT: &str = "http";

#[derive(Clone, CustomResource, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
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
    /// Emergency stop button, if `true` then all pods are stopped without affecting configuration (as setting `replicas` to `0` would)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<bool>,
    /// Desired Superset version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statsd_exporter_version: Option<String>,
    pub credentials_secret: String,
    pub mapbox_secret: Option<String>,
    #[serde(default)]
    pub load_examples_on_init: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_config: Option<SupersetClusterAuthenticationConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Role<SupersetConfig>>,
    /// Specify the type of the created kubernetes service.
    /// This attribute will be removed in a future release when listener-operator is finished.
    /// Use with caution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_type: Option<ServiceType>,
}

// TODO: Temporary solution until listener-operator is finished
#[derive(Clone, Debug, Display, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum ServiceType {
    NodePort,
    ClusterIP,
}

impl Default for ServiceType {
    fn default() -> Self {
        Self::NodePort
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetClusterAuthenticationConfig {
    /// Name of the AuthenticationClass used to authenticate the users.
    /// At the moment only LDAP is supported.
    /// If not specified the default authentication (AUTH_DB) will be used.
    pub authentication_class: Option<String>,

    /// Allow users who are not already in the FAB DB.
    /// Gets mapped to `AUTH_USER_REGISTRATION`
    #[serde(default = "default_user_registration")]
    pub user_registration: bool,

    /// This role will be given in addition to any AUTH_ROLES_MAPPING.
    /// Gets mapped to `AUTH_USER_REGISTRATION_ROLE`
    #[serde(default = "default_user_registration_role")]
    pub user_registration_role: String,

    /// If we should replace ALL the user's roles each login, or only on registration.
    /// Gets mapped to `AUTH_ROLES_SYNC_AT_LOGIN`
    #[serde(default = "default_sync_roles_at")]
    pub sync_roles_at: LdapRolesSyncMoment,
}

pub fn default_user_registration() -> bool {
    true
}

pub fn default_user_registration_role() -> String {
    "Public".to_string()
}

/// Matches Flask's default mode of syncing at registration
pub fn default_sync_roles_at() -> LdapRolesSyncMoment {
    LdapRolesSyncMoment::Registration
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum LdapRolesSyncMoment {
    Registration,
    Login,
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

#[derive(Clone, Debug, Default, Deserialize, Eq, Merge, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetStorageConfig {}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetConfig {
    /// Row limit when requesting chart data.
    /// Corresponds to ROW_LIMIT
    pub row_limit: Option<i32>,
    /// Maximum number of seconds a Superset request can take before timing out.
    /// This setting affects the maximum duration a query to an underlying datasource can take.
    /// If you get timeout errors before your query returns the result you may need to increase this timeout.
    /// Corresponds to SUPERSET_WEBSERVER_TIMEOUT
    pub webserver_timeout: Option<u32>,
    /// CPU and memory limits for Superset pods
    pub resources: Option<Resources<SupersetStorageConfig, NoRuntimeLimits>>,
}

impl SupersetConfig {
    pub const CREDENTIALS_SECRET_PROPERTY: &'static str = "credentialsSecret";
    pub const MAPBOX_SECRET_PROPERTY: &'static str = "mapboxSecret";

    fn default_resources() -> Resources<SupersetStorageConfig, NoRuntimeLimits> {
        Resources {
            cpu: CpuLimits {
                min: Some(Quantity("200m".to_owned())),
                max: Some(Quantity("4".to_owned())),
            },
            memory: MemoryLimits {
                limit: Some(Quantity("2Gi".to_owned())),
                runtime_limits: NoRuntimeLimits {},
            },
            storage: SupersetStorageConfig {},
        }
    }
}

impl Configuration for SupersetConfig {
    type Configurable = SupersetCluster;

    fn compute_env(
        &self,
        cluster: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let mut result = BTreeMap::new();
        result.insert(
            Self::CREDENTIALS_SECRET_PROPERTY.to_string(),
            Some(cluster.spec.credentials_secret.clone()),
        );
        if let Some(msec) = &cluster.spec.mapbox_secret {
            result.insert(Self::MAPBOX_SECRET_PROPERTY.to_string(), Some(msec.clone()));
        }

        Ok(result)
    }

    fn compute_cli(
        &self,
        _cluster: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        Ok(BTreeMap::new())
    }

    fn compute_files(
        &self,
        _cluster: &Self::Configurable,
        _role_name: &str,
        file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
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
pub struct SupersetClusterStatus {}

impl SupersetCluster {
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

    /// Retrieve and merge resource configs for role and role groups
    pub fn resolve_resource_config_for_role_and_rolegroup(
        &self,
        role: &SupersetRole,
        rolegroup_ref: &RoleGroupRef<SupersetCluster>,
    ) -> Option<Resources<SupersetStorageConfig, NoRuntimeLimits>> {
        // Initialize the result with all default values as baseline
        let conf_defaults = SupersetConfig::default_resources();

        let role = match role {
            SupersetRole::Node => self.spec.nodes.as_ref()?,
        };

        // Retrieve role resource config
        let mut conf_role: Resources<SupersetStorageConfig, NoRuntimeLimits> =
            role.config.config.resources.clone().unwrap_or_default();

        // Retrieve rolegroup specific resource config
        let mut conf_rolegroup: Resources<SupersetStorageConfig, NoRuntimeLimits> = role
            .role_groups
            .get(&rolegroup_ref.role_group)
            .and_then(|rg| rg.config.config.resources.clone())
            .unwrap_or_default();

        // Merge more specific configs into default config
        // Hierarchy is:
        // 1. RoleGroup
        // 2. Role
        // 3. Default
        conf_role.merge(&conf_defaults);
        conf_rolegroup.merge(&conf_role);

        tracing::debug!("Merged resource config: {:?}", conf_rolegroup);
        Some(conf_rolegroup)
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
