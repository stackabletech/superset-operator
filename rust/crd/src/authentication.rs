// TODO: To be moved to separate commons operator

use serde::{Deserialize, Serialize};
use stackable_operator::builder::{
    SecretOperatorVolumeSourceBuilder, VolumeBuilder, VolumeMountBuilder,
};
use stackable_operator::k8s_openapi::api::core::v1::{CSIVolumeSource, Volume, VolumeMount};

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
    /// [SecretClass](https://docs.stackable.tech/secret-operator/secretclass.html) containing the LDAP bind credentials
    pub secret_class: String,
    /// [Scope](https://docs.stackable.tech/secret-operator/scope.html) of the [SecretClass](https://docs.stackable.tech/secret-operator/secretclass.html)
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
    /// Use TLS but don't verify certificates.
    /// We have to use an empty struct instead of an empty Enum because of limitations of [kube-rs](https://github.com/kube-rs/kube-rs/)
    Insecure {},
    /// Use TLS and ca certificate to verify the server
    ServerVerification(AuthenticationClassTlsServerVerification),
    /// Use TLS and ca certificate to verify the server and the client
    MutualVerification(AuthenticationClassTlsMutualVerification),
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationClassTlsServerVerification {
    /// Ca cert to verify the server
    pub server_ca_cert: AuthenticationClassCaCert,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationClassTlsMutualVerification {
    /// [SecretClass](https://docs.stackable.tech/secret-operator/secretclass.html) which will provide ca.crt, tls.crt and tls.key
    pub secret_class: String,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthenticationClassCaCert {
    /// Name of the ConfigMap containing the ca cert. Key must be "ca.crt".
    Configmap(String),
    /// Name of the Secret containing the ca cert. Key must be "ca.crt".
    Secret(String),
    /// Path to the ca cert
    Path(String),
    /// Name of the SecretClass which will provide the ca cert
    SecretClass(String),
}

impl AuthenticationClass {
    pub fn append_volumes_and_volume_mounts(
        &self,
        volumes: &mut Vec<Volume>,
        volume_mounts: &mut Vec<VolumeMount>,
    ) {
        let authentication_class_name = self.metadata.name.as_ref().unwrap();

        match &self.spec.protocol {
            AuthenticationClassProtocol::Ldap(ldap) => {
                if let Some(bind_credentials) = &ldap.bind_credentials {
                    let volume_name = format!("{authentication_class_name}-bind-credentials");
                    let volume_mount_path = format!("/secrets/{volume_name}");
                    volumes.push(
                        VolumeBuilder::new(&volume_name)
                            .csi(Self::build_secret_operator_volume(
                                &bind_credentials.secret_class,
                                &bind_credentials.scope,
                            ))
                            .build(),
                    );
                    volume_mounts.push(
                        VolumeMountBuilder::new(&volume_name, volume_mount_path)
                            .read_only(true)
                            .build(),
                    );
                }

                if let Some(tls) = &ldap.tls {
                    match tls {
                        AuthenticationClassTls::Insecure {} => {}
                        AuthenticationClassTls::ServerVerification(
                            AuthenticationClassTlsServerVerification { server_ca_cert },
                        ) => {
                            Self::append_server_ca_cert(
                                volumes,
                                volume_mounts,
                                authentication_class_name,
                                server_ca_cert,
                            );
                        }
                        AuthenticationClassTls::MutualVerification(
                            AuthenticationClassTlsMutualVerification { secret_class },
                        ) => {
                            // This will not only add the ca.crt but also the tls.crt and tls.key
                            Self::append_server_ca_cert(
                                volumes,
                                volume_mounts,
                                authentication_class_name,
                                &AuthenticationClassCaCert::SecretClass(secret_class.to_string()),
                            );
                        }
                    }
                }
            }
        }
    }

    fn build_secret_operator_volume(
        secret_class_name: &str,
        scope: &Option<AuthenticationClassSecretClassScope>,
    ) -> CSIVolumeSource {
        let mut secret_operator_volume_builder =
            SecretOperatorVolumeSourceBuilder::new(secret_class_name);

        if let Some(scope) = scope {
            if scope.pod {
                secret_operator_volume_builder.with_pod_scope();
            }
            if scope.node {
                secret_operator_volume_builder.with_node_scope();
            }
            for service in &scope.services {
                secret_operator_volume_builder.with_service_scope(service);
            }
        }

        secret_operator_volume_builder.build()
    }

    fn append_server_ca_cert(
        volumes: &mut Vec<Volume>,
        volume_mounts: &mut Vec<VolumeMount>,
        authentication_class_name: &str,
        server_ca_cert: &AuthenticationClassCaCert,
    ) {
        let volume_name = format!("{authentication_class_name}-tls-certificate");
        let volume_mount_path = format!("/certificates/{volume_name}");
        match server_ca_cert {
            AuthenticationClassCaCert::Path(_) => {}
            AuthenticationClassCaCert::Secret(secret_name) => {
                volumes.push(
                    VolumeBuilder::new(&volume_name)
                        .with_secret(secret_name, false)
                        .build(),
                );
                volume_mounts.push(
                    VolumeMountBuilder::new(&volume_name, volume_mount_path)
                        .read_only(true)
                        .build(),
                );
            }
            AuthenticationClassCaCert::Configmap(configmap_name) => {
                volumes.push(
                    VolumeBuilder::new(&volume_name)
                        .with_config_map(configmap_name)
                        .build(),
                );
                volume_mounts.push(
                    VolumeMountBuilder::new(&volume_name, volume_mount_path)
                        .read_only(true)
                        .build(),
                );
            }
            AuthenticationClassCaCert::SecretClass(secret_class_name) => {
                // We add a SecretClass Volume here to get the ca.crt, tls.crt and tls.key of the underlying SecretClass.
                // The tls.crt and tls.key will only be used when we use the AuthenticationClassTls::MutualVerification
                volumes.push(
                    VolumeBuilder::new(&volume_name)
                        .csi(
                            SecretOperatorVolumeSourceBuilder::new(secret_class_name)
                                .with_pod_scope()
                                .build(),
                        )
                        .build(),
                );
                volume_mounts.push(
                    VolumeMountBuilder::new(&volume_name, volume_mount_path)
                        .read_only(true)
                        .build(),
                );
            }
        }
    }
}
