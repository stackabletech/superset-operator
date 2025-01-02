use std::collections::BTreeMap;

use stackable_operator::{
    client::Client,
    commons::opa::{OpaApiVersion, OpaConfig},
};
use stackable_superset_crd::SupersetCluster;

pub struct SupersetOpaConfig {
    opa_base_url: String,
    opa_package: Option<String>,
}

impl SupersetOpaConfig {
    pub async fn from_opa_config(
        client: &Client,
        superset: &SupersetCluster,
        opa_config: &OpaConfig,
    ) -> Result<Self, stackable_operator::commons::opa::Error> {
        // Get opa_base_url for later use in CustomOpaSecurityManager
        let opa_endpoint = opa_config
            .full_document_url_from_config_map(client, superset, None, OpaApiVersion::V1)
            .await?;

        // striping package path from base url. Needed by CustomOpaSecurityManager. TODO: <Path/to/manager.py>
        let opa_base_url = match opa_config.package.clone() {
            Some(opa_package_name) => {
                let opa_path = format!("/v1/data/{opa_package_name}");
                opa_endpoint.replace(&opa_path, "")
            }
            None => opa_endpoint.replace("/v1/data/", ""),
        };

        Ok(SupersetOpaConfig {
            opa_base_url,
            opa_package: opa_config.package.clone(),
        })
    }

    // Adding necessary configurations. Imports are solved in config.rs
    // TODO: Currently: .unwrap_or_default() which ends in e.g. :
    // CUSTOM_SECURITY_MANAGER = None => CUSTOM_SECURITY_MANAGER = ""
    // Could be better if not set.
    pub fn as_config(&self) -> BTreeMap<String, Option<String>> {
        let config = BTreeMap::from([
            (
                "CUSTOM_SECURITY_MANAGER".to_string(),
                Some("OpaSupersetSecurityManager".to_string()),
            ),
            // This is now a PythonType::Expression. Makes it easy to find a default.
            // only necessary when opa role mapping is activated, as the user
            // has to have a role to be valid.
            (
                "AUTH_USER_REGISTRATION_ROLE".to_string(),
                Some("os.getenv('AUTH_USER_REGISTRATION_ROLE', 'Public')".to_string()),
            ),
            // There is no proper way to interfere this without changing e.g. CRD's.
            // Thus, we go for an default and make it accessible through envOverrides.
            (
                "STACKABLE_OPA_RULE".to_string(),
                Some("os.getenv('STACKABLE_OPA_RULE', 'user_roles')".to_string()),
            ),
            (
                "STACKABLE_OPA_BASE_URL".to_string(),
                Some(self.opa_base_url.clone()),
            ),
            (
                "STACKABLE_OPA_PACKAGE".to_string(),
                self.opa_package.clone(),
            ),
        ]);
        config
    }
}
