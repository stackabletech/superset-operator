use crate::superset_controller::{CERTS_DIR, SECRETS_DIR};
use stackable_operator::commons::{
    authentication::{AuthenticationClass, AuthenticationClassProvider},
    ldap::LdapAuthenticationProvider,
    tls::{CaCert, TlsVerification},
};
use stackable_superset_crd::{
    LdapRolesSyncMoment, SupersetClusterAuthenticationConfig, SupersetConfigOptions,
};
use std::collections::BTreeMap;

pub const PYTHON_IMPORTS: &[&str; 3] = &[
    "import os",
    "from superset.stats_logger import StatsdStatsLogger",
    "from flask_appbuilder.security.manager import (AUTH_DB, AUTH_LDAP, AUTH_OAUTH, AUTH_OID, AUTH_REMOTE_USER)",
    ];

pub fn add_superset_config(
    config: &mut BTreeMap<String, String>,
    authentication_config: Option<&SupersetClusterAuthenticationConfig>,
    authentication_class: Option<&AuthenticationClass>,
) {
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

    if let Some(authentication_config) = authentication_config {
        if let Some(authentication_class) = authentication_class {
            append_authentication_config(config, authentication_config, authentication_class);
        }
    }
}

fn append_authentication_config(
    config: &mut BTreeMap<String, String>,
    authentication_config: &SupersetClusterAuthenticationConfig,
    authentication_class: &AuthenticationClass,
) {
    let authentication_class_name = authentication_class.metadata.name.as_ref().unwrap();
    match &authentication_class.spec.provider {
        AuthenticationClassProvider::Ldap(ldap) => {
            append_ldap_config(config, ldap, authentication_class_name);
        }
    }

    config.insert(
        SupersetConfigOptions::AuthUserRegistration.to_string(),
        authentication_config.user_registration.to_string(),
    );
    config.insert(
        SupersetConfigOptions::AuthUserRegistrationRole.to_string(),
        authentication_config.user_registration_role.to_string(),
    );
    config.insert(
        SupersetConfigOptions::AuthRolesSyncAtLogin.to_string(),
        (authentication_config.sync_roles_at == LdapRolesSyncMoment::Login).to_string(),
    );
}

fn append_ldap_config(
    config: &mut BTreeMap<String, String>,
    ldap: &LdapAuthenticationProvider,
    authentication_class_name: &str,
) {
    config.insert(
        SupersetConfigOptions::AuthType.to_string(),
        "AUTH_LDAP".into(),
    );
    config.insert(
        SupersetConfigOptions::AuthLdapServer.to_string(),
        format!(
            "{protocol}{server_hostname}:{server_port}",
            protocol = match ldap.tls {
                None => "ldap://",
                Some(_) => "ldaps://",
            },
            server_hostname = ldap.hostname,
            server_port = ldap.port.unwrap_or_else(|| ldap.default_port()),
        ),
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

    // Possible TLS options, see https://github.com/dpgaspar/Flask-AppBuilder/blob/f6f66fc1bcc0163a213e4a2e6f960e91082d201f/flask_appbuilder/security/manager.py#L243-L250
    match &ldap.tls {
        None => {
            config.insert(
                SupersetConfigOptions::AuthLdapTlsDemand.to_string(),
                false.to_string(),
            );
        }
        Some(tls) => match &tls.verification {
            TlsVerification::None {} => {
                config.insert(
                    SupersetConfigOptions::AuthLdapTlsDemand.to_string(),
                    true.to_string(),
                );
                config.insert(
                    SupersetConfigOptions::AuthLdapAllowSelfSigned.to_string(),
                    true.to_string(),
                );
            }
            TlsVerification::Server(server_verification) => {
                append_server_ca_cert(
                    config,
                    authentication_class_name,
                    &server_verification.ca_cert,
                );
            }
            TlsVerification::Mutual(mutual_verification) => {
                append_server_ca_cert(
                    config,
                    authentication_class_name,
                    &CaCert::SecretClass(mutual_verification.cert_secret_class.to_string()),
                );
                config.insert(
                    SupersetConfigOptions::AuthLdapTlsCertfile.to_string(),
                    format!("{CERTS_DIR}{authentication_class_name}-tls-certificate/tls.crt"),
                );
                config.insert(
                    SupersetConfigOptions::AuthLdapTlsKeyfile.to_string(),
                    format!("{CERTS_DIR}{authentication_class_name}-tls-certificate/tls.key"),
                );
            }
        },
    }

    if ldap.bind_credentials.is_some() {
        config.insert(
            SupersetConfigOptions::AuthLdapBindUser.to_string(),
            format!(
                "open('{SECRETS_DIR}{authentication_class_name}-bind-credentials/user').read()"
            ),
        );
        config.insert(
            SupersetConfigOptions::AuthLdapBindPassword.to_string(),
            format!(
                "open('{SECRETS_DIR}{authentication_class_name}-bind-credentials/password').read()"
            ),
        );
    }
}

fn append_server_ca_cert(
    config: &mut BTreeMap<String, String>,
    authentication_class_name: &str,
    server_ca_cert: &CaCert,
) {
    config.insert(
        SupersetConfigOptions::AuthLdapTlsDemand.to_string(),
        true.to_string(),
    );
    config.insert(
        SupersetConfigOptions::AuthLdapAllowSelfSigned.to_string(),
        true.to_string(),
    );
    match server_ca_cert {
        CaCert::SecretClass(..) => {
            config.insert(
                SupersetConfigOptions::AuthLdapTlsCacertfile.to_string(),
                format!("{CERTS_DIR}{authentication_class_name}-tls-certificate/ca.crt"),
            );
        }
        CaCert::WebPki {} => {}
    }
}
