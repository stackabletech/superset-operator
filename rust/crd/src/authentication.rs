use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::commons::authentication::{
    ldap, oidc, AuthenticationClassProvider, ClientAuthenticationDetails,
};
use stackable_operator::kube::ResourceExt;
use stackable_operator::{
    client::Client,
    schemars::{self, JsonSchema},
};

const SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS: [&str; 1] = ["LDAP"];

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to retrieve AuthenticationClass"))]
    AuthenticationClassRetrieval {
        source: stackable_operator::error::Error,
    },

    // TODO: Adapt message if multiple authentication classes are supported simultaneously
    #[snafu(display("Only one authentication class is currently supported at a time"))]
    MultipleAuthenticationClassesProvided,

    #[snafu(display(
        "Failed to use authentication provider {provider:?} for authentication class {auth_class:?} - supported providers: {SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS:?}",
    ))]
    AuthenticationProviderNotSupported {
        auth_class: String,
        provider: String,
    },

    #[snafu(display("Invalid OIDC configuration"))]
    OidcConfiguration {
        source: stackable_operator::error::Error,
    },

    #[snafu(display(
        "{configured:?} is not a supported principalClaim in superset for the keycloak oidc provider. Please use {supported:?} in the AuthenticationClass {auth_class_name:?}"
    ))]
    OidcPrincipalClaimNotSupported {
        configured: String,
        supported: String,
        auth_class_name: String,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub enum SupersetAuthenticationClassResolved {
    Ldap {
        provider: ldap::AuthenticationProvider,
    },
    Oidc {
        provider: oidc::AuthenticationProvider,
        oidc: oidc::ClientAuthenticationOptions<SupersetOidcExtraFields>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetClientAuthenticationDetails {
    #[serde(flatten)]
    pub common: ClientAuthenticationDetails<SupersetOidcExtraFields>,

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

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetOidcExtraFields {
    /// Path appended to the root path
    #[serde(default = "default_oidc_api_path")]
    pub oidc_api_path: String,
}

pub fn default_user_registration() -> bool {
    true
}

pub fn default_user_registration_role() -> String {
    "Public".to_string()
}

pub fn default_oidc_api_path() -> String {
    "protocol".to_string()
}

/// Resolved counter part for `SuperSetAuthenticationConfig`.
pub struct SupersetAuthenticationConfigResolved {
    pub authentication_class_resolved: Option<SupersetAuthenticationClassResolved>,
    pub user_registration: bool,
    pub user_registration_role: String,
    pub sync_roles_at: FlaskRolesSyncMoment,
}

impl SupersetAuthenticationConfigResolved {
    pub async fn from(
        auth_details: &[SupersetClientAuthenticationDetails],
        client: &Client,
    ) -> Result<SupersetAuthenticationConfigResolved> {
        // TODO: Adapt if multiple authentication types are supported by Superset.
        // This is currently not possible due to the Flask-AppBuilder not supporting it,
        // see https://github.com/dpgaspar/Flask-AppBuilder/issues/1924.
        if auth_details.len() > 1 {
            return Err(Error::MultipleAuthenticationClassesProvided);
        }

        let mut user_registration = true;
        let mut user_registration_role = Default::default();
        let mut sync_roles_at = Default::default();

        let authentication_class_resolved = match auth_details.first() {
            Some(auth_details) => {
                let auth_class = auth_details
                    .common
                    .resolve_class(client)
                    .await
                    .context(AuthenticationClassRetrievalSnafu)?;
                let auth_class_name = auth_class.name_any();

                user_registration = auth_details.user_registration;
                user_registration_role = auth_details.user_registration_role.clone();
                sync_roles_at = auth_details.sync_roles_at.clone();

                Some(match auth_class.spec.provider {
                    AuthenticationClassProvider::Ldap(provider) => {
                        SupersetAuthenticationClassResolved::Ldap { provider }
                    }
                    AuthenticationClassProvider::Oidc(provider) => {
                        if &provider.principal_claim != "preferred_username" {
                            return OidcPrincipalClaimNotSupportedSnafu {
                                configured: provider.principal_claim.clone(),
                                supported: "preferred_username".to_owned(),
                                auth_class_name,
                            }
                            .fail();
                        }
                        SupersetAuthenticationClassResolved::Oidc {
                            provider,
                            oidc: auth_details
                                .common
                                .oidc_or_error(&auth_class_name)
                                .context(OidcConfigurationSnafu)?
                                .clone(),
                        }
                    }
                    _ => {
                        // Checking for supported AuthenticationClass here is a little out of place,
                        // but is does not make sense to iterate further after finding an unsupported
                        // AuthenticationClass.
                        return Err(Error::AuthenticationProviderNotSupported {
                            auth_class: auth_class_name,
                            provider: auth_class.spec.provider.to_string(),
                        });
                    }
                })
            }
            None => None,
        };

        Ok(SupersetAuthenticationConfigResolved {
            authentication_class_resolved,
            user_registration,
            user_registration_role,
            sync_roles_at,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum FlaskRolesSyncMoment {
    #[default]
    Registration,
    Login,
}
