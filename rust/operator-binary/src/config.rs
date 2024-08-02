use indoc::formatdoc;
use snafu::{ResultExt, Snafu};
use stackable_operator::commons::authentication::{ldap, oidc};
use stackable_superset_crd::{
    authentication::{
        FlaskRolesSyncMoment, SupersetAuthenticationClassResolved,
        SupersetClientAuthenticationDetailsResolved, DEFAULT_OIDC_PROVIDER,
    },
    SupersetConfigOptions,
};
use std::collections::BTreeMap;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to create LDAP endpoint url."))]
    FailedToCreateLdapEndpointUrl {
        source: stackable_operator::commons::authentication::ldap::Error,
    },
}

pub const PYTHON_IMPORTS: &[&str] = &[
    "import os",
    "from superset.stats_logger import StatsdStatsLogger",
    "from flask_appbuilder.security.manager import (AUTH_DB, AUTH_LDAP, AUTH_OAUTH, AUTH_OID, AUTH_REMOTE_USER)",
    "from log_config import StackableLoggingConfigurator",
    // Custom logout manager to securely logout while using Keycloak SSO. Issue: https://github.com/apache/superset/issues/24713
    "from superset.security.CustomKeycloakSecurityManager import CustomSsoSecurityManager",
    ];

pub fn add_superset_config(
    config: &mut BTreeMap<String, String>,
    authentication_config: &SupersetClientAuthenticationDetailsResolved,
) -> Result<(), Error> {
    config.insert(
        SupersetConfigOptions::SecretKey.to_string(),
        "os.environ.get('SECRET_KEY')".into(),
    );
    config.insert(
        SupersetConfigOptions::SqlalchemyDatabaseUri.to_string(),
        "os.environ.get('SQLALCHEMY_DATABASE_URI')".into(),
    );
    config.insert(
        SupersetConfigOptions::StatsLogger.to_string(),
        "StatsdStatsLogger(host='0.0.0.0', port=9125)".into(),
    );
    config.insert(
        SupersetConfigOptions::MapboxApiKey.to_string(),
        "os.environ.get('MAPBOX_API_KEY', '')".into(),
    );
    config.insert(
        SupersetConfigOptions::LoggingConfigurator.to_string(),
        "StackableLoggingConfigurator()".into(),
    );

    append_authentication_config(config, authentication_config)?;

    Ok(())
}

fn append_authentication_config(
    config: &mut BTreeMap<String, String>,
    auth_config: &SupersetClientAuthenticationDetailsResolved,
) -> Result<(), Error> {
    // SupersetClientAuthenticationDetailsResolved ensures that there
    // are either only LDAP or OIDC providers configured. It is not
    // necessary to check this here again.

    let ldap_providers = auth_config
        .authentication_classes_resolved
        .iter()
        .filter_map(|auth_class| {
            if let SupersetAuthenticationClassResolved::Ldap { provider } = auth_class {
                Some(provider)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let oidc_providers = auth_config
        .authentication_classes_resolved
        .iter()
        .filter_map(|auth_class| {
            if let SupersetAuthenticationClassResolved::Oidc { provider, oidc } = auth_class {
                Some((provider, oidc))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if let Some(ldap_provider) = ldap_providers.first() {
        append_ldap_config(config, ldap_provider)?;
    }

    if !oidc_providers.is_empty() {
        append_oidc_config(config, &oidc_providers);
    }

    config.insert(
        SupersetConfigOptions::AuthUserRegistration.to_string(),
        auth_config.user_registration.to_string(),
    );
    config.insert(
        SupersetConfigOptions::AuthUserRegistrationRole.to_string(),
        auth_config.user_registration_role.to_string(),
    );
    config.insert(
        SupersetConfigOptions::AuthRolesSyncAtLogin.to_string(),
        (auth_config.sync_roles_at == FlaskRolesSyncMoment::Login).to_string(),
    );

    Ok(())
}

fn append_ldap_config(
    config: &mut BTreeMap<String, String>,
    ldap: &ldap::AuthenticationProvider,
) -> Result<(), Error> {
    config.insert(
        SupersetConfigOptions::AuthType.to_string(),
        "AUTH_LDAP".into(),
    );
    config.insert(
        SupersetConfigOptions::AuthLdapServer.to_string(),
        ldap.endpoint_url()
            .context(FailedToCreateLdapEndpointUrlSnafu)?
            .into(),
    );
    config.insert(
        SupersetConfigOptions::AuthLdapSearch.to_string(),
        ldap.search_base.clone(),
    );
    config.insert(
        SupersetConfigOptions::AuthLdapSearchFilter.to_string(),
        ldap.search_filter.clone(),
    );
    config.insert(
        SupersetConfigOptions::AuthLdapUidField.to_string(),
        ldap.ldap_field_names.uid.clone(),
    );
    config.insert(
        SupersetConfigOptions::AuthLdapGroupField.to_string(),
        ldap.ldap_field_names.group.clone(),
    );
    config.insert(
        SupersetConfigOptions::AuthLdapFirstnameField.to_string(),
        ldap.ldap_field_names.given_name.clone(),
    );
    config.insert(
        SupersetConfigOptions::AuthLdapLastnameField.to_string(),
        ldap.ldap_field_names.surname.clone(),
    );

    config.insert(
        SupersetConfigOptions::AuthLdapTlsDemand.to_string(),
        ldap.tls.uses_tls().to_string(),
    );

    if ldap.tls.uses_tls() {
        if ldap.tls.uses_tls_verification() {
            if let Some(ca_cert_path) = ldap.tls.tls_ca_cert_mount_path() {
                config.insert(
                    SupersetConfigOptions::AuthLdapTlsCacertfile.to_string(),
                    ca_cert_path,
                );
            }
        } else {
            config.insert(
                SupersetConfigOptions::AuthLdapAllowSelfSigned.to_string(),
                true.to_string(),
            );
        }
    }

    if let Some((user_path, password_path)) = ldap.bind_credentials_mount_paths() {
        config.insert(
            SupersetConfigOptions::AuthLdapBindUser.to_string(),
            format!("open('{user_path}').read()"),
        );
        config.insert(
            SupersetConfigOptions::AuthLdapBindPassword.to_string(),
            format!("open('{password_path}').read()"),
        );
    }

    Ok(())
}

fn append_oidc_config(
    config: &mut BTreeMap<String, String>,
    providers: &[(
        &oidc::AuthenticationProvider,
        &oidc::ClientAuthenticationOptions<()>,
    )],
) {
    config.insert(
        SupersetConfigOptions::AuthType.to_string(),
        "AUTH_OAUTH".into(),
    );

    let mut oauth_providers_config = Vec::new();

    for (oidc, client_options) in providers {
        let (env_client_id, env_client_secret) =
            oidc::AuthenticationProvider::client_credentials_env_names(
                &client_options.client_credentials_secret_ref,
            );
        let mut scopes = oidc.scopes.clone();
        scopes.extend_from_slice(&client_options.extra_scopes);

        let oidc_provider = oidc
            .provider_hint
            .as_ref()
            .unwrap_or(&DEFAULT_OIDC_PROVIDER);

        let oauth_providers_config_entry = match oidc_provider {
            oidc::IdentityProviderHint::Keycloak => {
                formatdoc!(
                    "
                      {{ 'name': 'keycloak',
                        'icon': 'fa-key',
                        'token_key': 'access_token',
                        'remote_app': {{
                          'client_id': os.environ.get('{env_client_id}'),
                          'client_secret': os.environ.get('{env_client_secret}'),
                          'client_kwargs': {{
                            'scope': '{scopes}'
                          }},
                          'api_base_url': '{url}/protocol/',
                          'server_metadata_url': '{url}/.well-known/openid-configuration',
                        }},
                      }}",
                    url = oidc.endpoint_url().unwrap(),
                    scopes = scopes.join(" "),
                )
            }
        };

        oauth_providers_config.push(oauth_providers_config_entry);
    }

    config.insert(
        SupersetConfigOptions::OauthProviders.to_string(),
        formatdoc!(
            "[
             {joined_oauth_providers_config}
             ]
             ",
            joined_oauth_providers_config = oauth_providers_config.join(",\n")
        ),
    );
}
