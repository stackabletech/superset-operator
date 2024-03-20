use std::{collections::BTreeSet, future::Future, mem};

use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    commons::authentication::{
        ldap,
        oidc::{self, IdentityProviderHint},
        AuthenticationClass, AuthenticationClassProvider, ClientAuthenticationDetails,
    },
    error::OperatorResult,
    schemars::{self, JsonSchema},
};
use tracing::info;

// The assumed OIDC provider if no hint is given in the AuthClass
pub const DEFAULT_OIDC_PROVIDER: IdentityProviderHint = IdentityProviderHint::Keycloak;

const SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS: &[&str] = &["LDAP", "OIDC"];
const SUPPORTED_OIDC_PROVIDERS: &[IdentityProviderHint] = &[IdentityProviderHint::Keycloak];

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display(
        "the AuthenticationClass {auth_class_name:?} is referenced several times which is not allowed"
    ))]
    DuplicateAuthenticationClassReferencesNotAllowed { auth_class_name: String },

    #[snafu(display("failed to retrieve AuthenticationClass"))]
    AuthenticationClassRetrievalFailed {
        source: stackable_operator::error::Error,
    },

    #[snafu(display("only one authentication type at a time is supported by Superset, see https://github.com/dpgaspar/Flask-AppBuilder/issues/1924"))]
    MultipleAuthenticationTypesNotSupported,

    #[snafu(display("only one LDAP provider at a time is supported by Superset"))]
    MultipleLdapProvidersNotSupported,

    #[snafu(display(
        "the userRegistration settings must not differ between the authentication entries",
    ))]
    DifferentUserRegistrationSettingsNotAllowed,

    #[snafu(display(
        "the userRegistrationRole settings must not differ between the authentication entries",
    ))]
    DifferentUserRegistrationRoleSettingsNotAllowed,

    #[snafu(display(
        "the syncRolesAt settings must not differ between the authentication entries",
    ))]
    DifferentSyncRolesAtSettingsNotAllowed,

    #[snafu(display(
        "failed to use authentication provider {provider:?} for authentication class {auth_class_name:?} - supported providers: {SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS:?}",
    ))]
    AuthenticationProviderNotSupported {
        auth_class_name: String,
        provider: String,
    },

    #[snafu(display("invalid OIDC configuration"))]
    OidcConfigurationInvalid {
        source: stackable_operator::error::Error,
    },

    #[snafu(display("the OIDC provider {oidc_provider:?} is not yet supported (AuthenticationClass {auth_class_name:?})"))]
    OidcProviderNotSupported {
        auth_class_name: String,
        oidc_provider: String,
    },

    #[snafu(display(
        "TLS verification cannot be disabled in Superset (AuthenticationClass {auth_class_name:?})"
    ))]
    TlsVerificationCannotBeDisabled { auth_class_name: String },

    #[snafu(display(
        "invalid principalClaim {configured:?} in the {auth_class_name:?} AuthenticationClass. Superset hard-codes the claim name to {supported:?} for the Keycloak OIDC provider"
    ))]
    OidcPrincipalClaimNotSupported {
        configured: String,
        supported: String,
        auth_class_name: String,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetClientAuthenticationDetails {
    #[serde(flatten)]
    pub common: ClientAuthenticationDetails<()>,

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
    #[serde(default)]
    pub sync_roles_at: FlaskRolesSyncMoment,
}

pub fn default_user_registration() -> bool {
    true
}

pub fn default_user_registration_role() -> String {
    "Public".to_string()
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum FlaskRolesSyncMoment {
    #[default]
    Registration,
    Login,
}

/// Resolved and validated counter part for `SupersetClientAuthenticationDetails`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupersetClientAuthenticationDetailsResolved {
    pub authentication_classes_resolved: Vec<SupersetAuthenticationClassResolved>,
    pub user_registration: bool,
    pub user_registration_role: String,
    pub sync_roles_at: FlaskRolesSyncMoment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupersetAuthenticationClassResolved {
    Ldap {
        provider: ldap::AuthenticationProvider,
    },
    Oidc {
        provider: oidc::AuthenticationProvider,
        oidc: oidc::ClientAuthenticationOptions<()>,
    },
}

impl SupersetClientAuthenticationDetailsResolved {
    pub async fn from(
        auth_details: &[SupersetClientAuthenticationDetails],
        client: &Client,
    ) -> Result<SupersetClientAuthenticationDetailsResolved> {
        let resolve_auth_class = |auth_details: ClientAuthenticationDetails| async move {
            auth_details.resolve_class(client).await
        };
        SupersetClientAuthenticationDetailsResolved::resolve(auth_details, resolve_auth_class).await
    }

    pub async fn resolve<R>(
        auth_details: &[SupersetClientAuthenticationDetails],
        resolve_auth_class: impl Fn(ClientAuthenticationDetails) -> R,
    ) -> Result<SupersetClientAuthenticationDetailsResolved>
    where
        R: Future<Output = OperatorResult<AuthenticationClass>>,
    {
        let mut resolved_auth_classes = Vec::new();
        let mut user_registration = None;
        let mut user_registration_role = None;
        let mut sync_roles_at = None;

        let mut auth_class_names = BTreeSet::new();

        for entry in auth_details {
            let auth_class_name = entry.common.authentication_class_name();

            let is_new_auth_class = auth_class_names.insert(auth_class_name);
            ensure!(
                is_new_auth_class,
                DuplicateAuthenticationClassReferencesNotAllowedSnafu { auth_class_name }
            );

            let auth_class = resolve_auth_class(entry.common.clone())
                .await
                .context(AuthenticationClassRetrievalFailedSnafu)?;

            match &auth_class.spec.provider {
                AuthenticationClassProvider::Ldap(provider) => {
                    let resolved_auth_class = SupersetAuthenticationClassResolved::Ldap {
                        provider: provider.to_owned(),
                    };

                    if let Some(other) = resolved_auth_classes.first() {
                        ensure!(
                            mem::discriminant(other) == mem::discriminant(&resolved_auth_class),
                            MultipleAuthenticationTypesNotSupportedSnafu
                        );
                    }

                    ensure!(
                        resolved_auth_classes.is_empty(),
                        MultipleLdapProvidersNotSupportedSnafu
                    );

                    resolved_auth_classes.push(resolved_auth_class);
                }
                AuthenticationClassProvider::Oidc(provider) => {
                    let resolved_auth_class =
                        SupersetClientAuthenticationDetailsResolved::from_oidc(
                            auth_class_name,
                            provider,
                            entry,
                        )?;

                    if let Some(other) = resolved_auth_classes.first() {
                        ensure!(
                            mem::discriminant(other) == mem::discriminant(&resolved_auth_class),
                            MultipleAuthenticationTypesNotSupportedSnafu
                        );
                    }

                    resolved_auth_classes.push(resolved_auth_class);
                }
                _ => {
                    return Err(Error::AuthenticationProviderNotSupported {
                        auth_class_name: auth_class_name.to_owned(),
                        provider: auth_class.spec.provider.to_string(),
                    });
                }
            }

            match user_registration {
                Some(user_registration) => {
                    ensure!(
                        user_registration == entry.user_registration,
                        DifferentUserRegistrationSettingsNotAllowedSnafu
                    );
                }
                None => user_registration = Some(entry.user_registration),
            }

            match &user_registration_role {
                Some(user_registration_role) => {
                    ensure!(
                        user_registration_role == &entry.user_registration_role,
                        DifferentUserRegistrationRoleSettingsNotAllowedSnafu
                    );
                }
                None => user_registration_role = Some(entry.user_registration_role.to_owned()),
            }

            match &sync_roles_at {
                Some(sync_roles_at) => {
                    ensure!(
                        sync_roles_at == &entry.sync_roles_at,
                        DifferentSyncRolesAtSettingsNotAllowedSnafu
                    );
                }
                None => sync_roles_at = Some(entry.sync_roles_at.to_owned()),
            }
        }

        Ok(SupersetClientAuthenticationDetailsResolved {
            authentication_classes_resolved: resolved_auth_classes,
            user_registration: user_registration.unwrap_or_else(default_user_registration),
            user_registration_role: user_registration_role
                .unwrap_or_else(default_user_registration_role),
            sync_roles_at: sync_roles_at.unwrap_or_else(FlaskRolesSyncMoment::default),
        })
    }

    fn from_oidc(
        auth_class_name: &str,
        provider: &oidc::AuthenticationProvider,
        auth_details: &SupersetClientAuthenticationDetails,
    ) -> Result<SupersetAuthenticationClassResolved> {
        let oidc_provider = match &provider.provider_hint {
            None => {
                info!("No OIDC provider hint given in AuthClass {auth_class_name}, assuming {default_oidc_provider_name}",
                    default_oidc_provider_name = serde_json::to_string(&DEFAULT_OIDC_PROVIDER).unwrap());
                DEFAULT_OIDC_PROVIDER
            }
            Some(oidc_provider) => oidc_provider.to_owned(),
        };

        ensure!(
            SUPPORTED_OIDC_PROVIDERS.contains(&oidc_provider),
            OidcProviderNotSupportedSnafu {
                auth_class_name,
                oidc_provider: serde_json::to_string(&oidc_provider).unwrap(),
            }
        );

        match oidc_provider {
            IdentityProviderHint::Keycloak => {
                ensure!(
                    &provider.principal_claim == "preferred_username",
                    OidcPrincipalClaimNotSupportedSnafu {
                        configured: provider.principal_claim.clone(),
                        supported: "preferred_username".to_owned(),
                        auth_class_name,
                    }
                );
            }
        }

        ensure!(
            !provider.tls.uses_tls() || provider.tls.uses_tls_verification(),
            TlsVerificationCannotBeDisabledSnafu { auth_class_name }
        );

        Ok(SupersetAuthenticationClassResolved::Oidc {
            provider: provider.to_owned(),
            oidc: auth_details
                .common
                .oidc_or_error(auth_class_name)
                .context(OidcConfigurationInvalidSnafu)?
                .clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;

    use indoc::indoc;
    use stackable_operator::{
        commons::authentication::{
            oidc,
            tls::{CaCert, Tls, TlsClientDetails, TlsServerVerification, TlsVerification},
        },
        kube,
    };

    use super::*;

    #[tokio::test]
    async fn resolve_without_authentication_details() {
        let auth_details_resolved = test_resolve_and_expect_success("[]", "").await;

        assert_eq!(
            SupersetClientAuthenticationDetailsResolved {
                authentication_classes_resolved: Vec::default(),
                user_registration: default_user_registration(),
                user_registration_role: default_user_registration_role(),
                sync_roles_at: FlaskRolesSyncMoment::default()
            },
            auth_details_resolved
        );
    }

    #[tokio::test]
    async fn resolve_ldap_with_all_authentication_details() {
        // Avoid using defaults here
        let auth_details_resolved = test_resolve_and_expect_success(
            indoc! {"
                - authenticationClass: ldap
                  userRegistration: false
                  userRegistrationRole: Gamma
                  syncRolesAt: Login
            "},
            indoc! {"
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: ldap
                spec:
                  provider:
                    ldap:
                      hostname: my.ldap.server
            "},
        )
        .await;

        assert_eq!(
            SupersetClientAuthenticationDetailsResolved {
                authentication_classes_resolved: vec![SupersetAuthenticationClassResolved::Ldap {
                    provider: serde_yaml::from_str("hostname: my.ldap.server").unwrap()
                }],
                user_registration: false,
                user_registration_role: "Gamma".into(),
                sync_roles_at: FlaskRolesSyncMoment::Login
            },
            auth_details_resolved
        );
    }

    #[tokio::test]
    async fn resolve_oidc_with_all_authentication_details() {
        // Avoid using defaults here
        let auth_details_resolved = test_resolve_and_expect_success(
            indoc! {"
                - authenticationClass: oidc1
                  oidc:
                    clientCredentialsSecret: superset-oidc-client1
                    extraScopes:
                      - groups
                  userRegistration: false
                  userRegistrationRole: Gamma
                  syncRolesAt: Login
                - authenticationClass: oidc2
                  oidc:
                    clientCredentialsSecret: superset-oidc-client2
                  userRegistration: false
                  userRegistrationRole: Gamma
                  syncRolesAt: Login
            "},
            indoc! {"
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: oidc1
                spec:
                  provider:
                    oidc:
                      hostname: first.oidc.server
                      port: 443
                      rootPath: /realms/main
                      principalClaim: preferred_username
                      scopes:
                        - openid
                        - email
                        - profile
                      providerHint: Keycloak
                      tls:
                        verification:
                          server:
                            caCert:
                              secretClass: tls
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: oidc2
                spec:
                  provider:
                    oidc:
                      hostname: second.oidc.server
                      rootPath: /realms/test
                      principalClaim: preferred_username
                      scopes:
                        - openid
                        - email
                        - profile
            "},
        )
        .await;

        assert_eq!(
            SupersetClientAuthenticationDetailsResolved {
                authentication_classes_resolved: vec![
                    SupersetAuthenticationClassResolved::Oidc {
                        provider: oidc::AuthenticationProvider::new(
                            "first.oidc.server".into(),
                            Some(443),
                            "/realms/main".into(),
                            TlsClientDetails {
                                tls: Some(Tls {
                                    verification: TlsVerification::Server(TlsServerVerification {
                                        ca_cert: CaCert::SecretClass("tls".into())
                                    })
                                })
                            },
                            "preferred_username".into(),
                            vec!["openid".into(), "email".into(), "profile".into()],
                            Some(IdentityProviderHint::Keycloak)
                        ),
                        oidc: oidc::ClientAuthenticationOptions {
                            client_credentials_secret_ref: "superset-oidc-client1".into(),
                            extra_scopes: vec!["groups".into()],
                            product_specific_fields: ()
                        }
                    },
                    SupersetAuthenticationClassResolved::Oidc {
                        provider: oidc::AuthenticationProvider::new(
                            "second.oidc.server".into(),
                            None,
                            "/realms/test".into(),
                            TlsClientDetails { tls: None },
                            "preferred_username".into(),
                            vec!["openid".into(), "email".into(), "profile".into()],
                            None
                        ),
                        oidc: oidc::ClientAuthenticationOptions {
                            client_credentials_secret_ref: "superset-oidc-client2".into(),
                            extra_scopes: Vec::new(),
                            product_specific_fields: ()
                        }
                    }
                ],
                user_registration: false,
                user_registration_role: "Gamma".into(),
                sync_roles_at: FlaskRolesSyncMoment::Login
            },
            auth_details_resolved
        );
    }

    #[tokio::test]
    async fn reject_duplicate_authentication_class_references() {
        let error_message = test_resolve_and_expect_error(
            indoc! {"
                - authenticationClass: oidc
                  oidc:
                    clientCredentialsSecret: superset-oidc-client1
                - authenticationClass: oidc
                  oidc:
                    clientCredentialsSecret: superset-oidc-client2
            "},
            indoc! {"
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: oidc
                spec:
                  provider:
                    oidc:
                      hostname: my.oidc.server
                      principalClaim: preferred_username
                      scopes: []
            "},
        )
        .await;

        assert_eq!(
            r#"the AuthenticationClass "oidc" is referenced several times which is not allowed"#,
            error_message
        );
    }

    #[tokio::test]
    async fn reject_different_authentication_types() {
        let error_message = test_resolve_and_expect_error(
            indoc! {"
                - authenticationClass: oidc
                  oidc:
                    clientCredentialsSecret: superset-oidc-client
                - authenticationClass: ldap
            "},
            indoc! {"
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: oidc
                spec:
                  provider:
                    oidc:
                      hostname: my.oidc.server
                      principalClaim: preferred_username
                      scopes: []
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: ldap
                spec:
                  provider:
                    ldap:
                      hostname: my.ldap.server
            "},
        )
        .await;

        assert_eq!(
            "only one authentication type at a time is supported by Superset, see https://github.com/dpgaspar/Flask-AppBuilder/issues/1924",
            error_message
        );
    }

    #[tokio::test]
    async fn reject_multiple_ldap_providers() {
        let error_message = test_resolve_and_expect_error(
            indoc! {"
                - authenticationClass: ldap1
                - authenticationClass: ldap2
            "},
            indoc! {"
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: ldap1
                spec:
                  provider:
                    ldap:
                      hostname: first.ldap.server
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: ldap2
                spec:
                  provider:
                    ldap:
                      hostname: second.ldap.server
            "},
        )
        .await;

        assert_eq!(
            "only one LDAP provider at a time is supported by Superset",
            error_message
        );
    }

    #[tokio::test]
    async fn reject_different_user_registration_settings() {
        let error_message = test_resolve_and_expect_error(
            indoc! {"
                - authenticationClass: oidc1
                  oidc:
                    clientCredentialsSecret: superset-oidc-client1
                - authenticationClass: oidc2
                  oidc:
                    clientCredentialsSecret: superset-oidc-client2
                  userRegistration: false
            "},
            indoc! {"
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: oidc1
                spec:
                  provider:
                    oidc:
                      hostname: first.oidc.server
                      principalClaim: preferred_username
                      scopes: []
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: oidc2
                spec:
                  provider:
                    oidc:
                      hostname: second.oidc.server
                      principalClaim: preferred_username
                      scopes: []
            "},
        )
        .await;

        assert_eq!(
            "the userRegistration settings must not differ between the authentication entries",
            error_message
        );
    }

    #[tokio::test]
    async fn reject_different_user_registration_role_settings() {
        let error_message = test_resolve_and_expect_error(
            indoc! {"
                - authenticationClass: oidc1
                  oidc:
                    clientCredentialsSecret: superset-oidc-client1
                - authenticationClass: oidc2
                  oidc:
                    clientCredentialsSecret: superset-oidc-client2
                  userRegistrationRole: Gamma
            "},
            indoc! {"
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: oidc1
                spec:
                  provider:
                    oidc:
                      hostname: first.oidc.server
                      principalClaim: preferred_username
                      scopes: []
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: oidc2
                spec:
                  provider:
                    oidc:
                      hostname: second.oidc.server
                      principalClaim: preferred_username
                      scopes: []
            "},
        )
        .await;

        assert_eq!(
            "the userRegistrationRole settings must not differ between the authentication entries",
            error_message
        );
    }

    #[tokio::test]
    async fn reject_different_sync_roles_at_settings() {
        let error_message = test_resolve_and_expect_error(
            indoc! {"
                - authenticationClass: oidc1
                  oidc:
                    clientCredentialsSecret: superset-oidc-client1
                - authenticationClass: oidc2
                  oidc:
                    clientCredentialsSecret: superset-oidc-client2
                  syncRolesAt: Login
            "},
            indoc! {"
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: oidc1
                spec:
                  provider:
                    oidc:
                      hostname: first.oidc.server
                      principalClaim: preferred_username
                      scopes: []
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: oidc2
                spec:
                  provider:
                    oidc:
                      hostname: second.oidc.server
                      principalClaim: preferred_username
                      scopes: []
            "},
        )
        .await;

        assert_eq!(
            "the syncRolesAt settings must not differ between the authentication entries",
            error_message
        );
    }

    #[tokio::test]
    async fn reject_if_oidc_details_are_missing() {
        let error_message = test_resolve_and_expect_error(
            indoc! {"
                - authenticationClass: oidc
            "},
            indoc! {"
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: oidc
                spec:
                  provider:
                    oidc:
                      hostname: my.oidc.server
                      principalClaim: preferred_username
                      scopes: []
            "},
        )
        .await;

        assert_eq!(
            indoc! { r#"
                invalid OIDC configuration

                Caused by this error:
                  1: OIDC authentication details not specified. The AuthenticationClass "oidc" uses an OIDC provider, you need to specify OIDC authentication details (such as client credentials) as well"#
            },
            error_message
        );
    }

    #[tokio::test]
    async fn reject_wrong_principal_claim() {
        let error_message = test_resolve_and_expect_error(
            indoc! {"
                - authenticationClass: oidc
                  oidc:
                    clientCredentialsSecret: superset-oidc-client
            "},
            indoc! {"
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: oidc
                spec:
                  provider:
                    oidc:
                      hostname: my.oidc.server
                      principalClaim: sub
                      scopes: []
            "},
        )
        .await;

        assert_eq!(
            r#"invalid principalClaim "sub" in the "oidc" AuthenticationClass. Superset hard-codes the claim name to "preferred_username" for the Keycloak OIDC provider"#,
            error_message
        );
    }

    #[tokio::test]
    async fn reject_disabled_tls_verification() {
        let error_message = test_resolve_and_expect_error(
            indoc! {"
                - authenticationClass: oidc
                  oidc:
                    clientCredentialsSecret: superset-oidc-client
            "},
            indoc! {"
                ---
                apiVersion: authentication.stackable.tech/v1alpha1
                kind: AuthenticationClass
                metadata:
                  name: oidc
                spec:
                  provider:
                    oidc:
                      hostname: my.oidc.server
                      principalClaim: preferred_username
                      scopes: []
                      tls:
                        verification:
                          none: {}
            "},
        )
        .await;

        assert_eq!(
            r#"TLS verification cannot be disabled in Superset (AuthenticationClass "oidc")"#,
            error_message
        );
    }

    /// Call `SupersetClientAuthenticationDetailsResolved::resolve` with
    /// the given lists of `SupersetClientAuthenticationDetails` and
    /// `AuthenticationClass`es and return the
    /// `SupersetClientAuthenticationDetailsResolved`.
    ///
    /// The parameters are meant to be valid and resolvable. Just fail
    /// if there is an error.
    async fn test_resolve_and_expect_success(
        auth_details_yaml: &str,
        auth_classes_yaml: &str,
    ) -> SupersetClientAuthenticationDetailsResolved {
        test_resolve(auth_details_yaml, auth_classes_yaml)
            .await
            .expect("The SupersetClientAuthenticationDetails should be resolvable.")
    }

    /// Call `SupersetClientAuthenticationDetailsResolved::resolve` with
    /// the given lists of `SupersetClientAuthenticationDetails` and
    /// `AuthenticationClass`es and return the error message.
    ///
    /// The parameters are meant to be invalid or not resolvable. Just
    /// fail if there is no error.
    async fn test_resolve_and_expect_error(
        auth_details_yaml: &str,
        auth_classes_yaml: &str,
    ) -> String {
        let error = test_resolve(auth_details_yaml, auth_classes_yaml)
            .await
            .expect_err(
                "The SupersetClientAuthenticationDetails are invalid and should not be resolvable.",
            );
        snafu::Report::from_error(error)
            .to_string()
            .trim_end()
            .to_owned()
    }

    /// Call `SupersetClientAuthenticationDetailsResolved::resolve` with
    /// the given lists of `SupersetClientAuthenticationDetails` and
    /// `AuthenticationClass`es and return the result.
    async fn test_resolve(
        auth_details_yaml: &str,
        auth_classes_yaml: &str,
    ) -> Result<SupersetClientAuthenticationDetailsResolved> {
        let auth_details = deserialize_superset_client_authentication_details(auth_details_yaml);

        let auth_classes = deserialize_auth_classes(auth_classes_yaml);

        let resolve_auth_class = create_auth_class_resolver(auth_classes);

        SupersetClientAuthenticationDetailsResolved::resolve(&auth_details, resolve_auth_class)
            .await
    }

    /// Deserialize the given list of
    /// `SupersetClientAuthenticationDetails`.
    ///
    /// Fail if the given string cannot be deserialized.
    fn deserialize_superset_client_authentication_details(
        input: &str,
    ) -> Vec<SupersetClientAuthenticationDetails> {
        serde_yaml::from_str(input)
            .expect("The definition of the authentication configuration should be valid.")
    }

    /// Deserialize the given `AuthenticationClass` YAML documents.
    ///
    /// Fail if the given string cannot be deserialized.
    fn deserialize_auth_classes(input: &str) -> Vec<AuthenticationClass> {
        if input.is_empty() {
            Vec::new()
        } else {
            let deserializer = serde_yaml::Deserializer::from_str(input);
            deserializer
                .map(|d| {
                    serde_yaml::with::singleton_map_recursive::deserialize(d)
                        .expect("The definition of the AuthenticationClass should be valid.")
                })
                .collect()
        }
    }

    /// Returns a function which resolves `AuthenticationClass` names to
    /// the given list of `AuthenticationClass`es.
    ///
    /// Use this function in the tests to replace
    /// `stackable_operator::commons::authentication::ClientAuthenticationDetails`
    /// which requires a Kubernetes client.
    fn create_auth_class_resolver(
        auth_classes: Vec<AuthenticationClass>,
    ) -> impl Fn(
        ClientAuthenticationDetails,
    ) -> Pin<Box<dyn Future<Output = OperatorResult<AuthenticationClass>>>> {
        move |auth_details: ClientAuthenticationDetails| {
            let auth_classes = auth_classes.clone();
            Box::pin(async move {
                auth_classes
                    .iter()
                    .find(|auth_class| {
                        auth_class.metadata.name.as_ref()
                            == Some(auth_details.authentication_class_name())
                    })
                    .cloned()
                    .ok_or_else(|| stackable_operator::error::Error::KubeError {
                        source: kube::Error::Api(kube::error::ErrorResponse {
                            code: 404,
                            message: "AuthenticationClass not found".into(),
                            reason: "NotFound".into(),
                            status: "Failure".into(),
                        }),
                    })
            })
        }
    }
}
