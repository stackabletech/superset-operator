use stackable_superset_crd::authentication::{AuthenticationClass, AuthenticationClassType};

pub fn compute_superset_config(authentication_class: &Option<AuthenticationClass>) -> String {
    // We don't calculate the secrets here directly, as the operator should not be able to see the actual credentials.
    // Instead we add a env-var which gets it's value from the secret with the credentials and read that with Python.
    let common = r#"
# common configs
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

    let authentication = match authentication_class {
        None => "".to_string(),
        Some(authentication_class) => {
            let authentication_class_name = authentication_class.metadata.name.as_ref().unwrap();
            match &authentication_class.spec.protocol {
                AuthenticationClassType::Ldap(ldap) => {
                    format!(
                        r#"
# authentication configs
AUTH_TYPE = AUTH_LDAP
AUTH_LDAP_SERVER = "ldap://{}:{}"
AUTH_LDAP_USE_TLS = False

AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Admin"
AUTH_ROLES_SYNC_AT_LOGIN = True # If we should replace ALL the user's roles each login, or only on registration
AUTH_LDAP_FIRSTNAME_FIELD = "givenName"
AUTH_LDAP_LASTNAME_FIELD = "sn"
AUTH_LDAP_EMAIL_FIELD = "mail"

AUTH_LDAP_SEARCH = "{}"
AUTH_LDAP_UID_FIELD = "uid"
AUTH_LDAP_BIND_USER = open('/authentication-config-{authentication_class_name}/user').read()
AUTH_LDAP_BIND_PASSWORD = open('/authentication-config-{authentication_class_name}/password').read()
"#,
                        ldap.hostname, ldap.port, ldap.domain,
                    )
                }
            }
        }
    };

    format!("{}{}", common, authentication)
}
