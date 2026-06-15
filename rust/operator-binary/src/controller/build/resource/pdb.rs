use stackable_operator::{
    commons::pdb::PdbConfig, k8s_openapi::api::policy::v1::PodDisruptionBudget,
    v2::builder::pdb::pod_disruption_budget_builder_with_role,
};

use crate::{
    controller::{ValidatedCluster, controller_name, operator_name, product_name},
    crd::SupersetRole,
};

/// Builds the [`PodDisruptionBudget`] for the given `role`, or `None` if PDBs are disabled.
pub fn build_pdb(
    pdb: &PdbConfig,
    validated: &ValidatedCluster,
    role: &SupersetRole,
) -> Option<PodDisruptionBudget> {
    if !pdb.enabled {
        return None;
    }
    let max_unavailable = pdb.max_unavailable.unwrap_or(match role {
        SupersetRole::Node => max_unavailable_nodes(),
        SupersetRole::Worker => max_unavailable_workers(),
        SupersetRole::Beat => max_unavailable_beat(),
    });
    let pdb = pod_disruption_budget_builder_with_role(
        validated,
        &product_name(),
        &role.role_name(),
        &operator_name(),
        &controller_name(),
    )
    .with_max_unavailable(max_unavailable)
    .build();

    Some(pdb)
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
