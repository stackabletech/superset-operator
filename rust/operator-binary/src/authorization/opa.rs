use std::collections::BTreeMap;

use stackable_operator::{
    client::Client,
    commons::opa::{OpaApiVersion, OpaConfig},
};
use stackable_superset_crd::SupersetCluster;

pub struct SupersetOpaConfig {
    opa_endpoint: String,
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
            .await?
            // Not pretty.
            // Need to remove the resource name. Appended by default.
            // TODO: Decide where to handle this
            // could be better in security manager!
            .replace("/v1/data/superset", "");

        let opa_package = opa_config.package.clone();

        Ok(SupersetOpaConfig {
            opa_endpoint,
            opa_package,
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
            // TODO: Figure out how to tell a what are the
            // rule names used.
            (
                "STACKABLE_OPA_RULE".to_string(),
                Some("os.getenv('STACKABLE_OPA_RULE', 'user_roles')".to_string()),
            ),
            (
                "STACKABLE_OPA_ENDPOINT".to_string(),
                Some(self.opa_endpoint.clone()),
            ),
            (
                "STACKABLE_OPA_PACKAGE".to_string(),
                self.opa_package.clone(),
            ),
        ]);
        config
    }
}
