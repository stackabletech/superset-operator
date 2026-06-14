use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::pdb::PodDisruptionBudgetBuilder, commons::pdb::PdbConfig,
    k8s_openapi::api::policy::v1::PodDisruptionBudget,
};

use crate::{
    OPERATOR_NAME,
    controller::{SUPERSET_CONTROLLER_NAME, ValidatedCluster},
    crd::{APP_NAME, SupersetRole},
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Cannot create PodDisruptionBudget for role [{role}]"))]
    CreatePdb {
        source: stackable_operator::builder::pdb::Error,
        role: String,
    },
}

/// Builds the [`PodDisruptionBudget`] for the given `role`, or `None` if PDBs are disabled.
pub fn build_pdb(
    pdb: &PdbConfig,
    validated: &ValidatedCluster,
    role: &SupersetRole,
) -> Result<Option<PodDisruptionBudget>, Error> {
    if !pdb.enabled {
        return Ok(None);
    }
    let max_unavailable = pdb.max_unavailable.unwrap_or(match role {
        SupersetRole::Node => max_unavailable_nodes(),
        SupersetRole::Worker => max_unavailable_workers(),
        SupersetRole::Beat => max_unavailable_beat(),
    });
    let pdb = PodDisruptionBudgetBuilder::new_with_role(
        validated,
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

    Ok(Some(pdb))
}

fn max_unavailable_nodes() -> u16 {
    1
}

fn max_unavailable_workers() -> u16 {
    1
}

fn max_unavailable_beat() -> u16 {
    1
}
