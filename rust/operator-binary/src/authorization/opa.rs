use stackable_operator::{
    client::Client,
    commons::opa::{OpaApiVersion, OpaConfig},
};
use stackable_superset_crd::SupersetCluster;

pub struct SupersetOpaConfig {
    opa_role_mapping: bool,
}

impl SupersetOpaConfig {
    pub async fn from_opa_config(
        client: &Client,
        superset: &SupersetCluster,
        opa_config: &OpaConfig,
    ) -> Result<Self, stackable_operator::commons::opa::Error> {
        Ok(SupersetOpaConfig {
            opa_role_mapping: true,
        })
    }
}
