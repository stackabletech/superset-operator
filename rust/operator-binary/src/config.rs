use stackable_superset_crd::authentication::{
    AuthenticationClass, AuthenticationClassCaCert, AuthenticationClassProtocol,
    AuthenticationClassTls,
};
use stackable_superset_crd::SupersetClusterAuthenticationConfigMethod;

pub fn compute_superset_config(
    authentication_method: &Option<&SupersetClusterAuthenticationConfigMethod>,
    authentication_class: &Option<AuthenticationClass>,
) -> String {
    // We don't calculate the secrets here directly, as the operator should not be able to see the actual credentials.
    // Instead we add a env-var which gets it's value from the secret with the credentials and read that with Python.
    let common = r#"
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

    let authentication = match authentication_method {
        None => "".to_string(),
        Some(authentication_method) => match authentication_class {
            None => "".to_string(),
            Some(authentication_class) => {
                compute_authentication_config(authentication_method, authentication_class)
            }
        },
    };

    format!("{}{}", common, authentication)
}

fn compute_authentication_config(
    authentication_method: &SupersetClusterAuthenticationConfigMethod,
    authentication_class: &AuthenticationClass,
) -> String {
    let authentication_class_name = authentication_class.metadata.name.as_ref().unwrap();
    match &authentication_class.spec.protocol {
        AuthenticationClassProtocol::Ldap(ldap) => {
            let mut result = format!(
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
            );

            // See https://github.com/dpgaspar/Flask-AppBuilder/blob/master/flask_appbuilder/security/manager.py
            // # TLS possible options
            // app.config.setdefault("AUTH_LDAP_USE_TLS", False)
            // app.config.setdefault("AUTH_LDAP_ALLOW_SELF_SIGNED", False)
            // app.config.setdefault("AUTH_LDAP_TLS_DEMAND", False)
            // app.config.setdefault("AUTH_LDAP_TLS_CACERTDIR", "")
            // app.config.setdefault("AUTH_LDAP_TLS_CACERTFILE", "")
            // app.config.setdefault("AUTH_LDAP_TLS_CERTFILE", "")
            // app.config.setdefault("AUTH_LDAP_TLS_KEYFILE", "")
            match &ldap.tls {
                None => result.push_str(
                    r#"
AUTH_LDAP_USE_TLS = False
"#,
                ),
                Some(AuthenticationClassTls::Insecure(_)) => {
                    result.push_str(
                        r#"
AUTH_LDAP_USE_TLS = False # Strangely we don't want True here because it will use TLS and we need to use SSL.
AUTH_LDAP_ALLOW_SELF_SIGNED = True
"#,
                    );
                }
                Some(AuthenticationClassTls::ServerVerification(server_verification)) => {
                    result.push_str(
                        r#"
AUTH_LDAP_USE_TLS = False # Strangely we don't want True here because it will use TLS and we need to use SSL.
AUTH_LDAP_ALLOW_SELF_SIGNED = False
AUTH_LDAP_TLS_DEMAND = True
"#,
                    );
                    match &server_verification.server_ca_cert {
                        AuthenticationClassCaCert::Path(cacert_path) => {
                            result.push_str(
                                format!(
                                    r#"
AUTH_LDAP_TLS_CACERTFILE = "{}"
"#,
                                    cacert_path
                                )
                                .as_str(),
                            );
                        }
                    }
                }
                Some(AuthenticationClassTls::MutualVerification(_mutual_verification)) => {
                    todo!()
                }
            }

            if ldap.bind_credentials.is_some() {
                result.push_str(
                    format!(
                        r#"
AUTH_LDAP_BIND_USER = open('/secrets/{authentication_class_name}-bind-credentials/user').read()
AUTH_LDAP_BIND_PASSWORD = open('/secrets/{authentication_class_name}-bind-credentials/password').read()
"#
                    )
                    .as_str(),
                );
            }

            result
        }
    }
}
