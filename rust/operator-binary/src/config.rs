use indoc::{formatdoc, indoc};
use stackable_operator::commons::{
    authentication::{AuthenticationClass, AuthenticationClassProvider},
    ldap::LdapAuthenticationProvider,
    tls::{CaCert, TlsVerification},
};
use stackable_superset_crd::{LdapRolesSyncMoment, SupersetClusterAuthenticationConfigMethod};

pub fn compute_superset_config(
    authentication_method: &Option<&SupersetClusterAuthenticationConfigMethod>,
    authentication_class: &Option<AuthenticationClass>,
) -> String {
    // We don't calculate the secrets here directly, as the operator should not be able to see the actual credentials.
    // Instead we add a env-var which gets it's value from the secret with the credentials and read that with Python.
    let mut config = indoc! {r#"
        # Common configs
        import os
        from superset.stats_logger import StatsdStatsLogger
        from flask_appbuilder.security.manager import (
            AUTH_DB,
            AUTH_LDAP,
            AUTH_OAUTH,
            AUTH_OID,
            AUTH_REMOTE_USER
        )

        SECRET_KEY = os.environ.get('SECRET_KEY')
        SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')
        STATS_LOGGER = StatsdStatsLogger(host='0.0.0.0', port=9125)
    "#}
    .to_string();

    if let Some(authentication_method) = authentication_method {
        if let Some(authentication_class) = authentication_class {
            append_authentication_config(&mut config, authentication_method, authentication_class);
        }
    }

    config
}

fn append_authentication_config(
    config: &mut String,
    authentication_method: &SupersetClusterAuthenticationConfigMethod,
    authentication_class: &AuthenticationClass,
) {
    match &authentication_class.spec.provider {
        AuthenticationClassProvider::Ldap(ldap) => {
            append_ldap_config(config, authentication_method, ldap);
        }
    }
}

fn append_ldap_config(
    config: &mut String,
    authentication_method: &SupersetClusterAuthenticationConfigMethod,
    ldap: &LdapAuthenticationProvider,
) {
    let authentication_class_name = &authentication_method.authentication_class;

    config.push_str(
        formatdoc! {r#"
                # Authentication configs
                AUTH_TYPE = AUTH_LDAP
                AUTH_LDAP_SERVER = "{protocol}{server_hostname}:{server_port}"

                AUTH_LDAP_SEARCH = "{search}"
                AUTH_LDAP_SEARCH_FILTER = "{search_filter}"
                AUTH_LDAP_UID_FIELD = "{uid_field}"
                AUTH_LDAP_GROUP_FIELD = "{group_field}"
                AUTH_LDAP_FIRSTNAME_FIELD = "{firstname_field}"
                AUTH_LDAP_LASTNAME_FIELD = "{lastname_field}"
                AUTH_LDAP_EMAIL_FIELD = "{email_field}"

                AUTH_USER_REGISTRATION = {user_registration}
                AUTH_USER_REGISTRATION_ROLE = "{user_registration_role}"
                AUTH_ROLES_SYNC_AT_LOGIN = {roles_sync_at_login}
            "#,
            protocol = match ldap.tls {
                None => "ldap://",
                Some(_) => "ldaps://",
            },
            server_hostname = ldap.hostname,
            server_port = ldap.port.unwrap_or_else(|| ldap.default_port()),
            search = ldap.search_base,
            search_filter = ldap.search_filter,
            uid_field = ldap.ldap_field_names.uid,
            group_field = ldap.ldap_field_names.group,
            firstname_field = ldap.ldap_field_names.given_name,
            lastname_field = ldap.ldap_field_names.surname,
            email_field = ldap.ldap_field_names.email,
            user_registration = to_python_bool(
                authentication_method
                    .ldap_extras
                    .as_ref()
                    .map(|extra| extra.user_registration)
                    .unwrap_or_else(stackable_superset_crd::default_user_registration)
            ),
            user_registration_role = authentication_method
                .ldap_extras
                .as_ref()
                .map(|extra| &extra.user_registration_role)
                .unwrap_or(&stackable_superset_crd::default_user_registration_role()),
            roles_sync_at_login = to_python_bool(
                authentication_method
                    .ldap_extras
                    .as_ref()
                    .map(|extra| &extra.sync_roles_at)
                    .unwrap_or(&stackable_superset_crd::default_sync_roles_at())
                == &LdapRolesSyncMoment::Login
            ),
        }
        .as_str(),
    );

    // Possible TLS options, see https://github.com/dpgaspar/Flask-AppBuilder/blob/f6f66fc1bcc0163a213e4a2e6f960e91082d201f/flask_appbuilder/security/manager.py#L243-L250
    match &ldap.tls {
        None => config.push_str("AUTH_LDAP_TLS_DEMAND = False\n"),
        Some(tls) => match &tls.verification {
            TlsVerification::None {} => {
                config.push_str(indoc! {r#"
                    AUTH_LDAP_TLS_DEMAND = True
                    AUTH_LDAP_ALLOW_SELF_SIGNED = True
                "#});
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
                config.push_str(formatdoc! {r#"
                    AUTH_LDAP_TLS_CERTFILE = "/certificates/{authentication_class_name}-tls-certificate/tls.crt"
                    AUTH_LDAP_TLS_KEYFILE = "/certificates/{authentication_class_name}-tls-certificate/tls.key"
                "#}
                .as_str());
            }
        },
    }

    if ldap.bind_credentials.is_some() {
        config.push_str(
        formatdoc! {r#"
                AUTH_LDAP_BIND_USER = open('/secrets/{authentication_class_name}-bind-credentials/user').read()
                AUTH_LDAP_BIND_PASSWORD = open('/secrets/{authentication_class_name}-bind-credentials/password').read()
            "#}
            .as_str()
        );
    }
}

fn append_server_ca_cert(
    config: &mut String,
    authentication_class_name: &str,
    server_ca_cert: &CaCert,
) {
    config.push_str(indoc! {r#"
            AUTH_LDAP_TLS_DEMAND = True
            AUTH_LDAP_ALLOW_SELF_SIGNED = False
        "#});
    match server_ca_cert {
        CaCert::SecretClass(..) => {
            config.push_str(format!("AUTH_LDAP_TLS_CACERTFILE = \"/certificates/{authentication_class_name}-tls-certificate/ca.crt\"\n").as_str());
        }
        CaCert::WebPki {} => {}
    }
}

fn to_python_bool(value: bool) -> &'static str {
    if value {
        "True"
    } else {
        "False"
    }
}
