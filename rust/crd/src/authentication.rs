use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::commons::authentication::AuthenticationClassProvider;
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

/// Resolved counter part for `SuperSetAuthenticationConfig`.
pub struct SuperSetAuthenticationConfigResolved {
    pub authentication_class: Option<AuthenticationClass>,
    pub user_registration: bool,
    pub user_registration_role: String,
    pub sync_roles_at: FlaskRolesSyncMoment,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetAuthentication {
    /// The Superset [authentication](DOCS_BASE_URL_PLACEHOLDER/superset/usage-guide/security) settings.
    /// Currently the underlying Flask App Builder only supports one authentication mechanism
    /// at a time. This means the operator will error out if multiple references to an
    /// AuthenticationClass are provided.
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
    /// Name of the [AuthenticationClass](DOCS_BASE_URL_PLACEHOLDER/concepts/authentication.html#authenticationclass) used to authenticate the users.
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
    pub sync_roles_at: FlaskRolesSyncMoment,
}

pub fn default_user_registration() -> bool {
    true
}

pub fn default_user_registration_role() -> String {
    "Public".to_string()
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
    ) -> Result<Vec<SuperSetAuthenticationConfigResolved>> {
        let mut resolved = vec![];

        // TODO: adapt if multiple authentication classes are supported by superset.
        //    This is currently not possible due to the Flask App Builder not supporting it.
        if self.authentication.len() > 1 {
            return Err(Error::MultipleAuthenticationClassesProvided);
        }

        for config in &self.authentication {
            let auth_class = if let Some(auth_class) = &config.authentication_class {
                let resolved = AuthenticationClass::resolve(client, auth_class)
                    .await
                    .context(AuthenticationClassRetrievalSnafu {
                        authentication_class: ObjectRef::<AuthenticationClass>::new(auth_class),
                    })?;

                // Checking for supported AuthenticationClass here is a little out of place, but is does not
                // make sense to iterate further after finding an unsupported AuthenticationClass.
                Some(match resolved.spec.provider {
                    AuthenticationClassProvider::Ldap(_) => resolved,
                    AuthenticationClassProvider::Tls(_)
                    | AuthenticationClassProvider::Static(_) => {
                        return Err(Error::AuthenticationProviderNotSupported {
                            authentication_class: ObjectRef::from_obj(&resolved),
                            provider: resolved.spec.provider.to_string(),
                        })
                    }
                })
            } else {
                None
            };

            resolved.push(SuperSetAuthenticationConfigResolved {
                authentication_class: auth_class,
                user_registration: config.user_registration,
                user_registration_role: config.user_registration_role.clone(),
                sync_roles_at: config.sync_roles_at.clone(),
            })
        }

        Ok(resolved)
    }
}
