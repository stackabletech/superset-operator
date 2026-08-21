//! The update_status step in the SupersetCluster controller.

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    client::Client,
    status::condition::{
        compute_conditions, deployment::DeploymentConditionBuilder,
        operations::ClusterOperationsConditionBuilder, statefulset::StatefulSetConditionBuilder,
    },
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    SUPERSET_OPERATOR_NAME,
    controller::{Applied, KubernetesResources},
    crd::v1alpha1::{SupersetCluster, SupersetClusterStatus},
};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to update status"))]
    ApplyStatus {
        source: stackable_operator::client::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Computes the cluster status from the applied resources and patches it onto the
/// [`SupersetCluster`].
///
/// Takes [`KubernetesResources<Applied>`], so the type system proves that the conditions are
/// derived from the resources the API server returned rather than from the ones that were merely
/// built. The `Node` role contributes StatefulSet conditions and the `Worker`/`Beat` Celery roles
/// contribute Deployment conditions.
pub async fn update_status(
    client: &Client,
    superset: &SupersetCluster,
    applied: &KubernetesResources<Applied>,
) -> Result<()> {
    let mut stateful_set_cond_builder = StatefulSetConditionBuilder::default();
    for stateful_set in &applied.stateful_sets {
        stateful_set_cond_builder.add(stateful_set.clone());
    }

    let mut deployment_cond_builder = DeploymentConditionBuilder::default();
    for deployment in &applied.deployments {
        deployment_cond_builder.add(deployment.clone());
    }

    let cluster_operation_cond_builder =
        ClusterOperationsConditionBuilder::new(&superset.spec.cluster_config.cluster_operation);

    let status = SupersetClusterStatus {
        conditions: compute_conditions(
            superset,
            &[
                &stateful_set_cond_builder,
                &deployment_cond_builder,
                &cluster_operation_cond_builder,
            ],
        ),
    };

    client
        .apply_patch_status(SUPERSET_OPERATOR_NAME, superset, &status)
        .await
        .context(ApplyStatusSnafu)?;

    Ok(())
}
