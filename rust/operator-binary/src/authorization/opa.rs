use std::collections::BTreeMap;

use stackable_operator::{client::Client, commons::opa::OpaApiVersion};
use stackable_superset_crd::{SupersetCluster, SupersetOpaConfig};

pub struct SupersetOpaConfigResolved {
    opa_base_url: String,
    opa_package: Option<String>,
    rule_name: String,
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
            rule_name: opa_config.rule_name.to_owned(),
        })
    }

    // Adding necessary configurations. Imports are solved in config.rs
    pub fn as_config(&self) -> BTreeMap<String, Option<String>> {
        BTreeMap::from([
            (
                "CUSTOM_SECURITY_MANAGER".to_string(),
                Some("OpaSupersetSecurityManager".to_string()),
            ),
            // This is now a PythonType::Expression. Makes it easy to find a default.
            // EnvOverrides are supported.
            (
                "AUTH_USER_REGISTRATION_ROLE".to_string(),
                Some("os.getenv('AUTH_USER_REGISTRATION_ROLE', 'Public')".to_string()),
            ),
            // TODO: Documentation
            (
                "STACKABLE_OPA_RULE".to_string(),
                Some(self.rule_name.clone()),
            ),
            (
                "STACKABLE_OPA_BASE_URL".to_string(),
                Some(self.opa_base_url.clone()),
            ),
            (
                "STACKABLE_OPA_PACKAGE".to_string(),
                self.opa_package.clone(),
            ),
            (
                "OPA_ROLES_CACHE".to_string(),
                Some("os.getenv('OPA_ROLES_CACHE', '10')".to_string()),
            ),
        ])
    }
}
