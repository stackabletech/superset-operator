use stackable_operator::time::Duration;
use std::collections::BTreeMap;

use stackable_operator::{client::Client, commons::opa::OpaApiVersion};
use stackable_superset_crd::{SupersetCluster, SupersetOpaConfig};

pub struct SupersetOpaConfigResolved {
    opa_base_url: String,
    opa_package: Option<String>,
    cache_max_entries: u32,
    cache_ttl: Duration,
}

impl SupersetOpaConfigResolved {
    pub async fn from_opa_config(
        client: &Client,
        superset: &SupersetCluster,
        opa_config: &SupersetOpaConfig,
    ) -> Result<Self, stackable_operator::commons::opa::Error> {
        // Get opa_base_url for later use in CustomOpaSecurityManager
        let opa_endpoint = opa_config
            .opa
            .full_document_url_from_config_map(client, superset, None, OpaApiVersion::V1)
            .await?;

        // striping package path from base url. Needed by CustomOpaSecurityManager.
        let opa_base_url = match opa_config.opa.package.clone() {
            Some(opa_package_name) => {
                let opa_path = format!("/v1/data/{opa_package_name}");
                opa_endpoint.replace(&opa_path, "")
            }
            None => opa_endpoint.replace("/v1/data/", ""),
        };

        Ok(SupersetOpaConfigResolved {
            opa_base_url,
            opa_package: opa_config.opa.package.to_owned(),
            cache_max_entries: opa_config.cache.max_entries.to_owned(),
            cache_ttl: opa_config.cache.entry_time_to_live.to_owned(),
        })
    }

    // Adding necessary configurations. Imports are solved in config.rs
    pub fn as_config(&self) -> BTreeMap<String, String> {
        let mut config = BTreeMap::from([
            (
                "CUSTOM_SECURITY_MANAGER".to_string(),
                "OpaSupersetSecurityManager".to_string(),
            ),
            (
                "AUTH_OPA_REQUEST_URL".to_string(),
                self.opa_base_url.to_owned(),
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
        ]);

        if let Some(opa_package) = &self.opa_package {
            config.insert("AUTH_OPA_PACKAGE".to_string(), opa_package.to_owned());
        }

        config
    }
}
