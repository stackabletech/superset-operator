use std::collections::BTreeMap;

use stackable_operator::{client::Client, commons::opa::OpaApiVersion, time::Duration};
use stackable_superset_crd::{SupersetCluster, SupersetOpaRoleMappingConfig};

pub struct SupersetOpaConfigResolved {
    opa_endpoint: String,
    cache_max_entries: u32,
    cache_ttl: Duration,
}

impl SupersetOpaConfigResolved {
    pub async fn from_opa_config(
        client: &Client,
        superset: &SupersetCluster,
        opa_config: &SupersetOpaRoleMappingConfig,
    ) -> Result<Self, stackable_operator::commons::opa::Error> {
        // Get opa_base_url for later use in CustomOpaSecurityManager
        let opa_endpoint = opa_config
            .opa
            .full_document_url_from_config_map(client, superset, None, OpaApiVersion::V1)
            .await?;

        Ok(SupersetOpaConfigResolved {
            opa_endpoint,
            cache_max_entries: opa_config.cache.max_entries.to_owned(),
            cache_ttl: opa_config.cache.entry_time_to_live.to_owned(),
        })
    }

    // Adding necessary configurations. Imports are solved in config.rs
    pub fn as_config(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "CUSTOM_SECURITY_MANAGER".to_string(),
                "OpaSupersetSecurityManager".to_string(),
            ),
            (
                "AUTH_OPA_REQUEST_URL".to_string(),
                self.opa_endpoint.to_owned(),
            ),
            (
                "AUTH_OPA_CACHE_MAX_ENTRIES".to_string(),
                self.cache_max_entries.to_string(),
            ),
            (
                "AUTH_OPA_CACHE_TTL_IN_SEC".to_string(),
                self.cache_ttl.as_secs().to_string(),
            ),
            ("AUTH_OPA_RULE".to_string(), "user_roles".to_string()),
        ])
    }
}
