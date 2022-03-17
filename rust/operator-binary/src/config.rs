use stackable_superset_crd::authentication::{
    AuthenticationClass, AuthenticationClassCaCert, AuthenticationClassLdap,
    AuthenticationClassProtocol, AuthenticationClassTls,
};
use stackable_superset_crd::SupersetClusterAuthenticationConfigMethod;

pub fn compute_superset_config(
    authentication_method: &Option<&SupersetClusterAuthenticationConfigMethod>,
    authentication_class: &Option<AuthenticationClass>,
) -> String {
    // We don't calculate the secrets here directly, as the operator should not be able to see the actual credentials.
    // Instead we add a env-var which gets it's value from the secret with the credentials and read that with Python.
    let mut config = r#"
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
"#
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
    match &authentication_class.spec.protocol {
        AuthenticationClassProtocol::Ldap(ldap) => {
            append_ldap_config(config, authentication_method, ldap);
        }
    }
}

fn append_ldap_config(
    config: &mut String,
    authentication_method: &SupersetClusterAuthenticationConfigMethod,
    ldap: &AuthenticationClassLdap,
) {
    let authentication_class_name = &authentication_method.authentication_class;

    config.push_str(
        format!(
            r#"
# Authentication configs
AUTH_TYPE = AUTH_LDAP
AUTH_LDAP_SERVER = "{}{}:{}"

AUTH_LDAP_SEARCH = "{}"
AUTH_LDAP_UID_FIELD = "{}"
AUTH_LDAP_GROUP_FIELD = "{}"
AUTH_LDAP_FIRSTNAME_FIELD = "{}"
AUTH_LDAP_LASTNAME_FIELD = "{}"
AUTH_LDAP_EMAIL_FIELD = "{}"

AUTH_USER_REGISTRATION = {}
AUTH_USER_REGISTRATION_ROLE = "{}"
AUTH_ROLES_SYNC_AT_LOGIN = {}

"#,
            match ldap.tls {
                None => "ldap://",
                Some(_) => "ldaps://",
            },
            ldap.hostname,
            ldap.port,
            ldap.search_base,
            ldap.uid_field,
            ldap.group_field,
            ldap.firstname_field,
            ldap.lastname_field,
            ldap.email_field,
            if authentication_method
                .ldap_extras
                .as_ref()
                .map(|extra| extra.user_registration)
                .unwrap_or_else(stackable_superset_crd::default_user_registration)
            {
                "True"
            } else {
                "False"
            },
            authentication_method
                .ldap_extras
                .as_ref()
                .map(|extra| &extra.user_registration_role)
                .unwrap_or(&stackable_superset_crd::default_user_registration_role()),
            if authentication_method
                .ldap_extras
                .as_ref()
                .map(|extra| extra.roles_sync_at_login)
                .unwrap_or_else(stackable_superset_crd::default_roles_sync_at_login)
            {
                "True"
            } else {
                "False"
            },
        )
        .as_str(),
    );

    // Possible TLS options, see https://github.com/dpgaspar/Flask-AppBuilder/blob/master/flask_appbuilder/security/manager.py
    // app.config.setdefault("AUTH_LDAP_USE_TLS", False)
    // app.config.setdefault("AUTH_LDAP_ALLOW_SELF_SIGNED", False)
    // app.config.setdefault("AUTH_LDAP_TLS_DEMAND", False)
    // app.config.setdefault("AUTH_LDAP_TLS_CACERTDIR", "")
    // app.config.setdefault("AUTH_LDAP_TLS_CACERTFILE", "")
    // app.config.setdefault("AUTH_LDAP_TLS_CERTFILE", "")
    // app.config.setdefault("AUTH_LDAP_TLS_KEYFILE", "")
    match &ldap.tls {
        None => config.push_str(
            r#"
AUTH_LDAP_USE_TLS = False
"#,
        ),
        Some(AuthenticationClassTls::Insecure {}) => {
            config.push_str(
                r#"
AUTH_LDAP_USE_TLS = False # Strangely we don't want True here because it will use TLS and we need to use SSL.
AUTH_LDAP_ALLOW_SELF_SIGNED = True
"#,
            );
        }
        Some(AuthenticationClassTls::ServerVerification(server_verification)) => {
            append_server_ca_cert(
                config,
                authentication_class_name,
                &server_verification.server_ca_cert,
            );
        }
        Some(AuthenticationClassTls::MutualVerification(mutual_verification)) => {
            append_server_ca_cert(
                config,
                authentication_class_name,
                &AuthenticationClassCaCert::SecretClass(
                    mutual_verification.secret_class.to_string(),
                ),
            );
            config.push_str(
                format!(
                    r#"
AUTH_LDAP_TLS_CERTFILE = "/certificates/{authentication_class_name}-tls-certificate/tls.crt"
AUTH_LDAP_TLS_KEYFILE = "/certificates/{authentication_class_name}-tls-certificate/tls.key"
"#
                )
                .as_str(),
            );
        }
    }

    if ldap.bind_credentials.is_some() {
        config.push_str(
            format!(
                r#"
AUTH_LDAP_BIND_USER = open('/secrets/{authentication_class_name}-bind-credentials/user').read()
AUTH_LDAP_BIND_PASSWORD = open('/secrets/{authentication_class_name}-bind-credentials/password').read()
"#
            )
                .as_str(),
        );
    }
}

fn append_server_ca_cert(
    config: &mut String,
    authentication_class_name: &str,
    server_ca_cert: &AuthenticationClassCaCert,
) {
    config.push_str(
        r#"
AUTH_LDAP_USE_TLS = False # Strangely we don't want True here because it will use TLS and we need to use SSL.
AUTH_LDAP_ALLOW_SELF_SIGNED = False
AUTH_LDAP_TLS_DEMAND = True
"#,
    );
    match server_ca_cert {
        AuthenticationClassCaCert::Path(path) => {
            config.push_str(format!("AUTH_LDAP_TLS_CACERTFILE = \"{}\"\n", path).as_str());
        }
        AuthenticationClassCaCert::Configmap(_)
        | AuthenticationClassCaCert::Secret(_)
        | AuthenticationClassCaCert::SecretClass(_) => {
            config.push_str(
                format!(
                    "AUTH_LDAP_TLS_CACERTFILE = \"/certificates/{authentication_class_name}-tls-certificate/ca.crt\"\n"
                )
                    .as_str(),
            );
        }
    }
}
