use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::pdb::PodDisruptionBudgetBuilder, client::Client, cluster_resources::ClusterResources,
    commons::pdb::PdbConfig, kube::ResourceExt,
};

use crate::{
    OPERATOR_NAME,
    crd::{APP_NAME, SupersetRole, v1alpha1},
    superset_controller::SUPERSET_CONTROLLER_NAME,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Cannot create PodDisruptionBudget for role [{role}]"))]
    CreatePdb {
        source: stackable_operator::builder::pdb::Error,
        role: String,
    },
    #[snafu(display("Cannot apply PodDisruptionBudget [{name}]"))]
    ApplyPdb {
        source: stackable_operator::cluster_resources::Error,
        name: String,
    },
}

pub async fn add_pdbs(
    pdb: &PdbConfig,
    superset: &v1alpha1::SupersetCluster,
    role: &SupersetRole,
    client: &Client,
    cluster_resources: &mut ClusterResources<'_>,
) -> Result<(), Error> {
    if !pdb.enabled {
        return Ok(());
    }
    let max_unavailable = pdb.max_unavailable.unwrap_or(match role {
        SupersetRole::Node => max_unavailable_nodes(),
    });
    let pdb = PodDisruptionBudgetBuilder::new_with_role(
        superset,
        APP_NAME,
        &role.to_string(),
        OPERATOR_NAME,
        SUPERSET_CONTROLLER_NAME,
    )
    .with_context(|_| CreatePdbSnafu {
        role: role.to_string(),
    })?
    .with_max_unavailable(max_unavailable)
    .build();
    let pdb_name = pdb.name_any();
    cluster_resources
        .add(client, pdb)
        .await
        .with_context(|_| ApplyPdbSnafu { name: pdb_name })?;

    Ok(())
}

fn max_unavailable_nodes() -> u16 {
    1
}
