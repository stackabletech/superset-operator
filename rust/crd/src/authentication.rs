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
    pub protocol: AuthenticationClassType,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthenticationClassType {
    Ldap(AuthenticationClassLdap),
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationClassLdap {
    pub hostname: String,
    pub port: u16,
    pub domain: String,
    pub bind_credentials: AuthenticationClassLdapBindCredentials,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationClassLdapBindCredentials {
    pub secret_class: String,
    pub scope: String,
}
