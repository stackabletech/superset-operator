//! Renders the OPA authorization properties (and required Python imports) for
//! `superset_config.py`.

use std::collections::BTreeMap;

use crate::crd::authorization::SupersetOpaConfigResolved;

/// Python imports injected into `superset_config.py` when OPA authorization is enabled.
pub const OPA_IMPORTS: &[&str] =
    &["from opa_authorizer.opa_manager import OpaSupersetSecurityManager"];

/// Renders the OPA-related key/value properties for `superset_config.py`.
pub fn opa_properties(opa_config: &SupersetOpaConfigResolved) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "CUSTOM_SECURITY_MANAGER".to_string(),
            "OpaSupersetSecurityManager".to_string(),
        ),
        (
            "AUTH_OPA_REQUEST_URL".to_string(),
            opa_config.opa_endpoint.to_owned(),
        ),
        (
            "AUTH_OPA_CACHE_MAX_ENTRIES".to_string(),
            opa_config.cache_max_entries.to_string(),
        ),
        (
            "AUTH_OPA_CACHE_TTL_IN_SEC".to_string(),
            opa_config.cache_ttl.as_secs().to_string(),
        ),
        ("AUTH_OPA_RULE".to_string(), "user_roles".to_string()),
    ])
}
