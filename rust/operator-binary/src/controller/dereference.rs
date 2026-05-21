use snafu::{ResultExt, Snafu};

use crate::{
    authorization::opa::SupersetOpaConfigResolved,
    crd::{authentication::SupersetClientAuthenticationDetailsResolved, v1alpha1::SupersetCluster},
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("invalid authentication configuration"))]
    AuthenticationConfig {
        source: crate::crd::authentication::Error,
    },

    #[snafu(display("invalid OPA configuration"))]
    OpaConfig {
        source: stackable_operator::commons::opa::Error,
    },
}

/// External references resolved against the Kubernetes API during the dereference step.
///
/// Only externally referenced objects belong here. Pure-spec validation lives in
/// [`crate::controller::validate`].
pub struct DereferencedObjects {
    pub authentication_config: SupersetClientAuthenticationDetailsResolved,
    pub opa_config: Option<SupersetOpaConfigResolved>,
}

pub async fn dereference(
    client: &stackable_operator::client::Client,
    superset: &SupersetCluster,
) -> Result<DereferencedObjects, Error> {
    let authentication_config = SupersetClientAuthenticationDetailsResolved::from(
        &superset.spec.cluster_config.authentication,
        client,
    )
    .await
    .context(AuthenticationConfigSnafu)?;

    let opa_config = match superset.get_opa_config() {
        Some(opa_config) => Some(
            SupersetOpaConfigResolved::from_opa_config(client, superset, opa_config)
                .await
                .context(OpaConfigSnafu)?,
        ),
        None => None,
    };

    Ok(DereferencedObjects {
        authentication_config,
        opa_config,
    })
}
