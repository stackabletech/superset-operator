use stackable_operator::commons::authentication::{
    ldap::LdapAuthenticationProvider, tls::TlsVerification, AuthenticationClassProvider,
};
use stackable_superset_crd::authentication::SuperSetAuthenticationConfigResolved;
use stackable_superset_crd::{authentication::FlaskRolesSyncMoment, SupersetConfigOptions};
use std::collections::BTreeMap;

pub const PYTHON_IMPORTS: &[&str] = &[
    "import os",
    "from superset.stats_logger import StatsdStatsLogger",
    "from flask_appbuilder.security.manager import (AUTH_DB, AUTH_LDAP, AUTH_OAUTH, AUTH_OID, AUTH_REMOTE_USER)",
    "from log_config import StackableLoggingConfigurator",
    ];

pub fn add_superset_config(
    config: &mut BTreeMap<String, String>,
    authentication_config: &Vec<SuperSetAuthenticationConfigResolved>,
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
    config.insert(
        SupersetConfigOptions::LoggingConfigurator.to_string(),
        "StackableLoggingConfigurator()".into(),
    );

    append_authentication_config(config, authentication_config);
}

fn append_authentication_config(
    config: &mut BTreeMap<String, String>,
    authentication_config: &Vec<SuperSetAuthenticationConfigResolved>,
) {
    // TODO: we make sure in crd/src/authentication.rs that currently there is only one
    //    AuthenticationClass provided. If the FlaskAppBuilder ever supports this we have
    //    to adapt the config here accordingly
    for auth_config in authentication_config {
        if let Some(auth_class) = &auth_config.authentication_class {
            if let AuthenticationClassProvider::Ldap(ldap) = &auth_class.spec.provider {
                append_ldap_config(config, ldap);
            }
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
    }
}

fn append_ldap_config(config: &mut BTreeMap<String, String>, ldap: &LdapAuthenticationProvider) {
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

    config.insert(
        SupersetConfigOptions::AuthLdapTlsDemand.to_string(),
        ldap.use_tls().to_string(),
    );

    if let Some(tls) = &ldap.tls {
        match &tls.verification {
            TlsVerification::None {} => {
                config.insert(
                    SupersetConfigOptions::AuthLdapAllowSelfSigned.to_string(),
                    true.to_string(),
                );
            }
            TlsVerification::Server(_) => {
                if let Some(ca_cert_path) = ldap.tls_ca_cert_mount_path() {
                    config.insert(
                        SupersetConfigOptions::AuthLdapTlsCacertfile.to_string(),
                        ca_cert_path,
                    );
                }
            }
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
}
