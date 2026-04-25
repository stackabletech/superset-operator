use std::{collections::BTreeMap, io::Write, str::FromStr};

use indoc::formatdoc;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    commons::networking::{DomainName, HostName},
    crd::authentication::{ldap, oidc},
};

use crate::{
    crd::{
        SupersetConfigOptions,
        authentication::{
            self, DEFAULT_OIDC_PROVIDER, SupersetAuthenticationClassResolved,
            SupersetClientAuthenticationDetailsResolved,
        },
        databases::CeleryResultBackendConnection,
    },
    resources::{
        celery_broker_connection_details, celery_result_backend_connection_details,
        metadata_database_connection_details,
    },
    v1alpha1::SupersetCluster,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Failed to create LDAP endpoint url."))]
    FailedToCreateLdapEndpointUrl {
        source: stackable_operator::crd::authentication::ldap::v1alpha1::Error,
    },

    #[snafu(display("invalid OIDC endpoint"))]
    InvalidOidcEndpoint {
        source: stackable_operator::crd::authentication::oidc::v1alpha1::Error,
    },

    #[snafu(display("invalid well-known OIDC configuration URL"))]
    InvalidWellKnownConfigUrl {
        source: stackable_operator::crd::authentication::oidc::v1alpha1::Error,
    },
}

pub const PYTHON_IMPORTS: &[&str] = &[
    "import os",
    "from superset.stats_logger import StatsdStatsLogger",
    "from flask_appbuilder.security.manager import (AUTH_DB, AUTH_LDAP, AUTH_OAUTH, AUTH_REMOTE_USER)",
    "from log_config import StackableLoggingConfigurator",
];

pub fn add_superset_config(
    config: &mut BTreeMap<String, String>,
    superset: &SupersetCluster,
    authentication_config: &SupersetClientAuthenticationDetailsResolved,
) -> Result<(), Error> {
    let metadata_database_url_template =
        metadata_database_connection_details(superset).url_template;

    config.insert(
        SupersetConfigOptions::SecretKey.to_string(),
        "os.environ.get('SECRET_KEY')".to_owned(),
    );
    config.insert(
        SupersetConfigOptions::SqlalchemyDatabaseUri.to_string(),
        format!("os.path.expandvars('{metadata_database_url_template}')"),
    );
    config.insert(
        SupersetConfigOptions::StatsLogger.to_string(),
        "StatsdStatsLogger(host='0.0.0.0', port=9125)".to_owned(),
    );
    config.insert(
        SupersetConfigOptions::MapboxApiKey.to_string(),
        "os.environ.get('MAPBOX_API_KEY', '')".to_owned(),
    );
    config.insert(
        SupersetConfigOptions::LoggingConfigurator.to_string(),
        "StackableLoggingConfigurator()".to_owned(),
    );
    // Flask AppBuilder requires this to be set, otherwise the web ui cannot be used.
    // We chose to make it an expression in case the user wants to override it through
    // configurationOverrides (though it would require other settings like the private key too).
    config.insert(
        SupersetConfigOptions::RecaptchaPublicKey.to_string(),
        "''".to_owned(),
    );

    append_authentication_config(config, authentication_config)?;
    Ok(())
}

pub(crate) fn append_celery_worker_config(config_file: &mut Vec<u8>, superset: &SupersetCluster) {
    let Some(celery_result_backend_connection_details) =
        celery_result_backend_connection_details(superset)
    else {
        return;
    };

    let Some(celery_broker_connection_details) = celery_broker_connection_details(superset) else {
        return;
    };

    // TODO: remove, unwrap hacky, only for redis. For testing.
    let (celery_backend_host, celery_backend_port) =
        if let Some(CeleryResultBackendConnection::Redis(redis)) =
            &superset.spec.cluster_config.celery_result_backend
        {
            (redis.host.clone(), redis.port)
        } else {
            (
                HostName::DomainName(DomainName::from_str("redis").unwrap()),
                6379,
            )
        };

    let result_backend_username_env = celery_result_backend_connection_details
        .username_env
        .map(|env| env.name)
        .unwrap_or("".to_string());
    let result_backend_password_env = celery_result_backend_connection_details
        .password_env
        .map(|env| env.name)
        .unwrap_or("".to_string());
    let result_backend_url_template = celery_result_backend_connection_details.url_template;
    let broker_url_template = celery_broker_connection_details.url_template;

    let celery_config = formatdoc!(
        r#"
        # CELERY ASYNC
        from flask_caching.backends.rediscache import RedisCache
        RESULTS_BACKEND = RedisCache(host='{celery_backend_host}', port={celery_backend_port}, key_prefix='superset_results', username=os.path.expandvars('${{{result_backend_username_env}}}'), password=os.path.expandvars('${{{result_backend_password_env}}}'))
        class CeleryConfig(object):
          broker_url = os.path.expandvars('{broker_url_template}')
          imports = (
            "superset.sql_lab",
            "superset.tasks.scheduler",
          )
          result_backend = os.path.expandvars('{result_backend_url_template}')
          worker_prefetch_multiplier = 10
          task_acks_late = True
          task_annotations = {{
            "sql_lab.get_sql_results": {{
              "rate_limit": "100/s",
            }},
          }}

        CELERY_CONFIG = CeleryConfig
    "#,
    );

    writeln!(config_file, "{celery_config}").expect("Writing to vec always works.");
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
            if let SupersetAuthenticationClassResolved::Oidc {
                provider,
                client_auth_options: oidc,
            } = auth_class
            {
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
        append_oidc_config(config, &oidc_providers)?;
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
        (auth_config.sync_roles_at == authentication::v1alpha1::FlaskRolesSyncMoment::Login)
            .to_string(),
    );

    Ok(())
}

fn append_ldap_config(
    config: &mut BTreeMap<String, String>,
    ldap: &ldap::v1alpha1::AuthenticationProvider,
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
        &oidc::v1alpha1::AuthenticationProvider,
        &oidc::v1alpha1::ClientAuthenticationOptions<
            oidc::v1alpha1::ClientAuthenticationMethodOption,
        >,
    )],
) -> Result<(), Error> {
    config.insert(
        SupersetConfigOptions::AuthType.to_string(),
        "AUTH_OAUTH".into(),
    );

    let mut oauth_providers_config = Vec::new();

    for (oidc, client_options) in providers {
        let (env_client_id, env_client_secret) =
            oidc::v1alpha1::AuthenticationProvider::client_credentials_env_names(
                &client_options.client_credentials_secret_ref,
            );
        let mut scopes = oidc.scopes.clone();
        scopes.extend_from_slice(&client_options.extra_scopes);

        let oidc_provider = oidc
            .provider_hint
            .as_ref()
            .unwrap_or(&DEFAULT_OIDC_PROVIDER);

        let oauth_providers_config_entry = match oidc_provider {
            oidc::v1alpha1::IdentityProviderHint::Keycloak => {
                let endpoint_url = oidc.endpoint_url().context(InvalidOidcEndpointSnafu)?;
                let mut api_base_url = endpoint_url.as_str().trim_end_matches('/').to_owned();
                api_base_url.push_str("/protocol/");
                let well_known_config_url = oidc
                    .well_known_config_url()
                    .context(InvalidWellKnownConfigUrlSnafu)?;
                let client_auth_method = serde_json::to_value(
                    client_options
                        .product_specific_fields
                        .client_authentication_method,
                )
                .expect("ClientAuthenticationMethod should serialize to JSON");
                let client_auth_method = client_auth_method
                    .as_str()
                    .expect("ClientAuthenticationMethod should serialize to a string");

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
                          'api_base_url': '{api_base_url}',
                          'server_metadata_url': '{well_known_config_url}',
                          'token_endpoint_auth_method': '{client_auth_method}',
                        }},
                      }}",
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use stackable_operator::commons::tls_verification::{TlsClientDetails, TlsVerification};

    use super::*;

    #[rstest]
    #[case(
        "/",
        "https://keycloak.mycorp.org/protocol/",
        "https://keycloak.mycorp.org/.well-known/openid-configuration"
    )]
    #[case(
        "",
        "https://keycloak.mycorp.org/protocol/",
        "https://keycloak.mycorp.org/.well-known/openid-configuration"
    )]
    #[case(
        "/realms/sdp",
        "https://keycloak.mycorp.org/realms/sdp/protocol/",
        "https://keycloak.mycorp.org/realms/sdp/.well-known/openid-configuration"
    )]
    #[case(
        "/realms/sdp/",
        "https://keycloak.mycorp.org/realms/sdp/protocol/",
        "https://keycloak.mycorp.org/realms/sdp/.well-known/openid-configuration"
    )]
    #[case(
        "/realms/sdp/////",
        "https://keycloak.mycorp.org/realms/sdp/protocol/",
        "https://keycloak.mycorp.org/realms/sdp/.well-known/openid-configuration"
    )]
    fn test_append_oidc_config(
        #[case] root_path: String,
        #[case] expected_api_base_url: &str,
        #[case] expected_server_metadata_url: &str,
    ) {
        use stackable_operator::commons::tls_verification::{CaCert, Tls, TlsServerVerification};

        let mut properties = BTreeMap::new();
        let provider = oidc::v1alpha1::AuthenticationProvider::new(
            "keycloak.mycorp.org".to_owned().try_into().unwrap(),
            Some(443),
            root_path,
            TlsClientDetails {
                tls: Some(Tls {
                    verification: TlsVerification::Server(TlsServerVerification {
                        ca_cert: CaCert::WebPki {},
                    }),
                }),
            },
            "preferred_username".to_owned(),
            vec!["openid".to_owned()],
            None,
        );
        let oidc = oidc::v1alpha1::ClientAuthenticationOptions {
            client_credentials_secret_ref: "nifi-keycloak-client".to_owned(),
            extra_scopes: vec![],
            product_specific_fields: oidc::v1alpha1::ClientAuthenticationMethodOption {
                client_authentication_method: Default::default(),
            },
        };

        append_oidc_config(&mut properties, &[(&provider, &oidc)])
            .expect("OIDC config adding failed");

        assert_eq!(properties.get("AUTH_TYPE"), Some(&"AUTH_OAUTH".to_owned()));
        let oauth_providers = properties
            .get("OAUTH_PROVIDERS")
            .expect("OAUTH_PROVIDERS missing");

        // This is neither valid yaml or json (it's Python code), so we can not easily parse it and have nice assertions.
        // As we don't want to have a Python runtime just for this test, let's grep a bit...
        assert!(oauth_providers.contains("'name': 'keycloak'"));
        assert!(oauth_providers.contains("client_id': os.environ.get("));
        assert!(oauth_providers.contains("client_secret': os.environ.get("));
        assert!(oauth_providers.contains("'scope': 'openid'"));
        assert!(oauth_providers.contains("'token_endpoint_auth_method': 'client_secret_basic'"));
        assert!(oauth_providers.contains(&format!("'api_base_url': '{expected_api_base_url}'")));
        assert!(oauth_providers.contains(&format!(
            "'server_metadata_url': '{expected_server_metadata_url}'"
        )));
    }
}
