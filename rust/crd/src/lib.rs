pub mod druidconnection;
pub mod supersetdb;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use stackable_operator::kube::runtime::reflector::ObjectRef;
use stackable_operator::kube::CustomResource;
use stackable_operator::product_config_utils::{ConfigError, Configuration};
use stackable_operator::role_utils::{Role, RoleGroupRef};
use stackable_operator::schemars::{self, JsonSchema};
use strum::{Display, EnumIter, EnumString};

pub const APP_NAME: &str = "superset";
pub const MANAGED_BY: &str = "superset-operator";

pub const SUPERSET_CONFIG: &str = "superset_config.py";

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
    #[serde(default)]
    pub load_examples_on_init: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Role<SupersetConfig>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_config: Option<SupersetClusterAuthenticationConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetClusterAuthenticationConfig {
    pub methods: Vec<SupersetClusterAuthenticationConfigMethod>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetClusterAuthenticationConfigMethod {
    /// Name of the AuthenticationClass used to authenticate the users
    pub authentication_class: String,
    /// Additional LDAP settings.
    /// Can only be specified when the specified AuthenticationClass uses the LDAP protocol
    /// See [Flask LDAP documentation](https://flask-appbuilder.readthedocs.io/en/latest/security.html#authentication-ldap)
    pub ldap_extras: Option<SupersetClusterAuthenticationConfigLdapExtras>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
/// Additional configs to LDAP Authentication in Superset. See <https://flask-appbuilder.readthedocs.io/en/latest/security.html#authentication-ldap>
pub struct SupersetClusterAuthenticationConfigLdapExtras {
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
#[serde(rename_all = "PascalCase")]
pub enum LdapRolesSyncMoment {
    Registration,
    Login,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetCredentials {
    pub admin_user: AdminUserCredentials,
    pub connections: Connections,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserCredentials {
    pub username: String,
    pub firstname: String,
    pub lastname: String,
    pub email: String,
    pub password: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Connections {
    pub secret_key: String,
    pub sqlalchemy_database_uri: String,
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
    PartialEq,
    Serialize,
)]
pub enum SupersetRole {
    #[strum(serialize = "node")]
    Node,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetConfig {}

impl SupersetConfig {
    pub const CREDENTIALS_SECRET_PROPERTY: &'static str = "credentialsSecret";
}

impl Configuration for SupersetConfig {
    type Configurable = SupersetCluster;

    fn compute_env(
        &self,
        cluster: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        Ok([(
            Self::CREDENTIALS_SECRET_PROPERTY.to_string(),
            Some(cluster.spec.credentials_secret.clone()),
        )]
        .into())
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
        _file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        Ok(BTreeMap::new())
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
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
