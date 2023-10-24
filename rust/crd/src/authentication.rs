use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::commons::authentication::{
    AuthenticationClassProvider, LdapAuthenticationProvider, OidcAuthenticationProvider,
};
use stackable_operator::{
    client::Client,
    commons::authentication::AuthenticationClass,
    kube::runtime::reflector::ObjectRef,
    schemars::{self, JsonSchema},
};

const SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS: [&str; 1] = ["LDAP"];

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to retrieve AuthenticationClass {authentication_class}"))]
    AuthenticationClassRetrieval {
        source: stackable_operator::error::Error,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
    // TODO: Adapt message if multiple authentication classes are supported simultaneously
    #[snafu(display("Only one authentication class is currently supported at a time"))]
    MultipleAuthenticationClassesProvided,
    #[snafu(display(
        "Failed to use authentication provider [{provider}] for authentication class [{authentication_class}] - supported providers: {SUPPORTED_AUTHENTICATION_CLASS_PROVIDERS:?}",
    ))]
    AuthenticationProviderNotSupported {
        authentication_class: ObjectRef<AuthenticationClass>,
        provider: String,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub enum SupersetAuthenticationClassResolved {
    Ldap {
        provider: LdapAuthenticationProvider,
    },
    Oidc {
        provider: OidcAuthenticationProvider,
        client_credentials_secret: String,
        api_path: String,
    },
}

/// Resolved counter part for `SuperSetAuthenticationConfig`.
pub struct SupersetAuthenticationConfigResolved {
    pub authentication_class: Option<SupersetAuthenticationClassResolved>,
    pub user_registration: bool,
    pub user_registration_role: String,
    pub sync_roles_at: FlaskRolesSyncMoment,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetAuthentication {
    #[serde(default)]
    authentication: Vec<SuperSetAuthenticationConfig>,
}

impl SupersetAuthentication {
    pub fn authentication_class_names(&self) -> Vec<&str> {
        let mut auth_classes = vec![];
        for config in &self.authentication {
            if let Some(auth_config) = &config.authentication_class {
                auth_classes.push(auth_config.as_str());
            }
        }
        auth_classes
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuperSetAuthenticationConfig {
    /// Name of the AuthenticationClass used to authenticate the users.
    /// If not specified the default authentication (AUTH_DB) will be used.
    pub authentication_class: Option<String>,
    /// Mandatory in case OIDC is used
    pub oidc_client_credentials_secret: Option<String>,
    /// Path appended to the root path
    /// Only used in case of OIDC
    #[serde(default = "default_oidc_api_path")]
    pub oidc_api_path: String,
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
    pub sync_roles_at: FlaskRolesSyncMoment,
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

/// Matches Flask's default mode of syncing at registration
pub fn default_sync_roles_at() -> FlaskRolesSyncMoment {
    FlaskRolesSyncMoment::Registration
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum FlaskRolesSyncMoment {
    Registration,
    Login,
}

impl SupersetAuthentication {
    /// Retrieve all provided `AuthenticationClass` references.
    pub async fn resolve(
        &self,
        client: &Client,
    ) -> Result<Vec<SupersetAuthenticationConfigResolved>> {
        let mut resolved = vec![];

        // TODO: Adapt if multiple authentication types are supported by Superset.
        // This is currently not possible due to the Flask-AppBuilder not supporting it,
        // see https://github.com/dpgaspar/Flask-AppBuilder/issues/1924.
        if self.authentication.len() > 1 {
            return Err(Error::MultipleAuthenticationClassesProvided);
        }

        for config in &self.authentication {
            let opt_auth_class = match &config.authentication_class {
                Some(auth_class_name) => Some(
                    AuthenticationClass::resolve(client, auth_class_name)
                        .await
                        .context(AuthenticationClassRetrievalSnafu {
                            authentication_class: ObjectRef::<AuthenticationClass>::new(
                                auth_class_name,
                            ),
                        })?,
                ),
                None => None,
            };

            let opt_auth_class_resolved = if let Some(auth_class) = &opt_auth_class {
                match &auth_class.spec.provider {
                    AuthenticationClassProvider::Ldap(ldap_authentication_provider) => {
                        Some(SupersetAuthenticationClassResolved::Ldap {
                            provider: ldap_authentication_provider.clone(),
                        })
                    }
                    AuthenticationClassProvider::Oidc(oidc_authentication_provider) => {
                        Some(SupersetAuthenticationClassResolved::Oidc {
                            provider: oidc_authentication_provider.clone(),
                            client_credentials_secret: config
                                .oidc_client_credentials_secret
                                .clone()
                                // TODO Throw error if not present
                                .unwrap(),
                            api_path: config.oidc_api_path.clone(),
                        })
                    }
                    _ => {
                        // Checking for supported AuthenticationClass here is a little out of place,
                        // but is does not make sense to iterate further after finding an unsupported
                        // AuthenticationClass.
                        return Err(Error::AuthenticationProviderNotSupported {
                            authentication_class: ObjectRef::from_obj(auth_class),
                            provider: auth_class.spec.provider.to_string(),
                        });
                    }
                }
            } else {
                None
            };

            resolved.push(SupersetAuthenticationConfigResolved {
                authentication_class: opt_auth_class_resolved,
                user_registration: config.user_registration,
                user_registration_role: config.user_registration_role.clone(),
                sync_roles_at: config.sync_roles_at.clone(),
            })
        }

        Ok(resolved)
    }
}
