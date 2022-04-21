use stackable_superset_crd::SupersetConfigOptions;
use std::collections::BTreeMap;

pub fn get_imports() -> &'static [&'static str] {
    &[
        "import os",
        "from superset.stats_logger import StatsdStatsLogger",
        "from flask_appbuilder.security.manager import (AUTH_DB, AUTH_LDAP, AUTH_OAUTH, AUTH_OID, AUTH_REMOTE_USER)",
    ]
}

pub fn add_superset_config(config: &mut BTreeMap<String, String>) {
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
}
