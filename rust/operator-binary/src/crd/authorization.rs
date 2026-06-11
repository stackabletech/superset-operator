//! The resolved OPA authorization config, dereferenced against the Kubernetes API.
//!
//! The rendering into `superset_config.py` properties lives in
//! [`crate::controller::build::properties::authorization`], mirroring how
//! [`crate::crd::authentication`] pairs with `build::properties::authentication`.

use stackable_operator::{client::Client, commons::opa::OpaApiVersion, shared::time::Duration};

use crate::crd::v1alpha1;

#[derive(Clone, Debug)]
pub struct SupersetOpaConfigResolved {
    pub opa_endpoint: String,
    pub cache_max_entries: u32,
    pub cache_ttl: Duration,
}

impl SupersetOpaConfigResolved {
    pub async fn from_opa_config(
        client: &Client,
        superset: &v1alpha1::SupersetCluster,
        opa_config: &v1alpha1::SupersetOpaRoleMappingConfig,
    ) -> Result<Self, stackable_operator::commons::opa::Error> {
        let opa_endpoint = opa_config
            .opa
            .full_document_url_from_config_map(client, superset, None, &OpaApiVersion::V1)
            .await?;

        Ok(SupersetOpaConfigResolved {
            opa_endpoint,
            cache_max_entries: opa_config.cache.max_entries.to_owned(),
            cache_ttl: opa_config.cache.entry_time_to_live.to_owned(),
        })
    }
}
