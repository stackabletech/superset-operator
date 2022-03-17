// TODO: To be moved to separate commons operator

use serde::{Deserialize, Serialize};

use stackable_operator::kube::CustomResource;
use stackable_operator::schemars::{self, JsonSchema};

#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "authentication.stackable.tech",
    version = "v1alpha1",
    kind = "AuthenticationClass",
    plural = "authenticationclasses",
    crates(
        kube_core = "stackable_operator::kube::core",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationClassSpec {
    /// Protocol used for authentication
    pub protocol: AuthenticationClassProtocol,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthenticationClassProtocol {
    Ldap(AuthenticationClassLdap),
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationClassLdap {
    /// Hostname of the LDAP server
    pub hostname: String,
    /// Port of the LDAP server
    #[serde(default = "default_port")]
    pub port: u16,
    /// LDAP search base
    #[serde(default)]
    pub search_base: String,
    /// The name of the username field
    #[serde(default = "default_uid_field")]
    pub uid_field: String,
    /// The name of the group field
    #[serde(default = "default_group_field")]
    pub group_field: String,
    /// The name of the firstname field
    #[serde(default = "default_firstname_field")]
    pub firstname_field: String,
    /// The name of the lastname field
    #[serde(default = "default_lastname_field")]
    pub lastname_field: String,
    /// The name of the email field
    #[serde(default = "default_email_field")]
    pub email_field: String,
    /// In case you need a special account for searching the LDAP server you can specify it here
    pub bind_credentials: Option<AuthenticationClassLdapBindCredentials>,
    /// Use a TLS connection. If not specified no TLS will be used
    pub tls: Option<AuthenticationClassTls>,
}

fn default_port() -> u16 {
    389
}

fn default_uid_field() -> String {
    "uid".to_string()
}

fn default_group_field() -> String {
    "memberof".to_string()
}

fn default_firstname_field() -> String {
    "givenName".to_string()
}

fn default_lastname_field() -> String {
    "sn".to_string()
}

fn default_email_field() -> String {
    "mail".to_string()
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationClassLdapBindCredentials {
    pub secret_class: String,
    pub scope: Option<AuthenticationClassSecretClassScope>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationClassSecretClassScope {
    #[serde(default)]
    pub pod: bool,
    #[serde(default)]
    pub node: bool,
    #[serde(default)]
    pub services: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthenticationClassTls {
    // Use TLS but don't verify certificates.
    // We have to use an empty struct instead of an empty Enum, otherwise we will get invalid CRDs
    Insecure {},
    // Use TLS and ca certificate to verify the server
    ServerVerification(AuthenticationClassTlsServerVerification),
    // Use TLS and ca certificate to verify the server and the client
    // MutualVerification(AuthenticationClassTlsMutualVerification),
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationClassTlsServerVerification {
    // Ca cert to verify the server
    pub server_ca_cert: AuthenticationClassCaCert,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthenticationClassCaCert {
    // Name of the ConfigMap containing the ca cert
    Configmap(String),
    // Name of the Secret containing the ca cert
    Secret(String),
    // Path to the ca cert
    Path(String),
    // SecretClass reference
    SecretClass(String),
}
