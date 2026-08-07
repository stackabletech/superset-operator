//! The apply step in the SupersetCluster controller.

use std::{collections::BTreeMap, marker::PhantomData};

use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    client::Client,
    cluster_resources::{ClusterResource, ClusterResourceApplyStrategy, ClusterResources},
    commons::random_secret_creation,
    deep_merger::ObjectOverrides,
    k8s_openapi::api::core::v1::Secret,
    v2::{builder::meta::ownerreference_from_resource, cluster_resources::cluster_resources_new},
};
use strum::{EnumDiscriminants, IntoStaticStr};
use tracing::instrument;

use crate::{
    controller::{
        Applied, KubernetesResources, Prepared, ValidatedCluster, controller_name, operator_name,
        product_name,
    },
    crd::INTERNAL_SECRET_SECRET_KEY,
};

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("failed to apply Kubernetes resource"))]
    ApplyResource {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to delete orphaned resources"))]
    DeleteOrphanedResources {
        source: stackable_operator::cluster_resources::Error,
    },

    #[snafu(display("failed to create SECRET_KEY Secret"))]
    CreateSecretKeySecret {
        source: random_secret_creation::Error,
    },

    #[snafu(display("failed to retrieve Secret {secret_name:?}"))]
    RetrieveSecret {
        source: stackable_operator::client::Error,
        secret_name: String,
    },

    #[snafu(display("failed to create SECRET_KEY Secret from the migrated value"))]
    CreateMigratedSecretKeySecret {
        source: stackable_operator::client::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Applier for the Kubernetes resource specifications produced by this controller.
///
/// The implementation is not tied to this controller and could theoretically be moved to
/// stackable_operator if [`KubernetesResources`] would contain all possible resource types.
pub struct Applier<'a> {
    client: &'a Client,
    cluster_resources: ClusterResources<'a>,
}

impl<'a> Applier<'a> {
    pub fn new(
        client: &'a Client,
        cluster: &ValidatedCluster,
        apply_strategy: ClusterResourceApplyStrategy,
        object_overrides: &'a ObjectOverrides,
    ) -> Applier<'a> {
        let cluster_resources = cluster_resources_new(
            &product_name(),
            &operator_name(),
            &controller_name(),
            &cluster.name,
            &cluster.namespace,
            &cluster.uid,
            apply_strategy,
            object_overrides,
        );

        Applier {
            client,
            cluster_resources,
        }
    }

    /// Applies the given Kubernetes resources, deletes the ones that are no longer part of the
    /// cluster and marks the result as applied.
    pub async fn apply(
        mut self,
        resources: KubernetesResources<Prepared>,
    ) -> Result<KubernetesResources<Applied>> {
        // Destructured without `..`, so adding a field to [`KubernetesResources`] fails to compile
        // here instead of the new resource silently never being applied.
        let KubernetesResources {
            stateful_sets,
            deployments,
            services,
            listeners,
            config_maps,
            pod_disruption_budgets,
            service_accounts,
            role_bindings,
            status: _,
        } = resources;

        // The ServiceAccount and its RoleBinding come first, because the Pods reference them at
        // creation time. The StatefulSets and Deployments come last, so that every ConfigMap and
        // Secret they mount already exists, otherwise a changed mount would restart the Pods.
        // See https://github.com/stackabletech/commons-operator/issues/111 for details.
        let service_accounts = self.add_resources(service_accounts).await?;
        let role_bindings = self.add_resources(role_bindings).await?;
        let services = self.add_resources(services).await?;
        let config_maps = self.add_resources(config_maps).await?;
        let listeners = self.add_resources(listeners).await?;
        let pod_disruption_budgets = self.add_resources(pod_disruption_budgets).await?;
        let stateful_sets = self.add_resources(stateful_sets).await?;
        let deployments = self.add_resources(deployments).await?;

        self.cluster_resources
            .delete_orphaned_resources(self.client)
            .await
            .context(DeleteOrphanedResourcesSnafu)?;

        Ok(KubernetesResources {
            stateful_sets,
            deployments,
            services,
            listeners,
            config_maps,
            pod_disruption_budgets,
            service_accounts,
            role_bindings,
            status: PhantomData,
        })
    }

    async fn add_resources<T: ClusterResource + Sync>(
        &mut self,
        resources: Vec<T>,
    ) -> Result<Vec<T>> {
        let mut applied_resources = vec![];

        for resource in resources {
            let applied_resource = self
                .cluster_resources
                .add(self.client, resource)
                .await
                .context(ApplyResourceSnafu)?;
            applied_resources.push(applied_resource);
        }

        Ok(applied_resources)
    }
}

/// Ensures that the Secret holding the Flask `SECRET_KEY` exists, creating it with a random value
/// if it does not.
///
/// This is a read-or-create client operation, so it cannot be part of the client-free `build()`
/// step. It is also deliberately not tracked in [`ClusterResources`], so that it survives orphan
/// deletion and an existing Secret is never overwritten (rotating the `SECRET_KEY` would
/// invalidate every session).
pub async fn ensure_secrets(client: &Client, cluster: &ValidatedCluster) -> Result<()> {
    // The migration runs first, so that an existing key from the old Secret is carried over
    // instead of a fresh random one being generated below.
    migrate_legacy_secret_key_secret_from_26_3(client, cluster).await?;

    random_secret_creation::create_random_secret_if_not_exists(
        &cluster.cluster_config.secret_key_secret_name,
        INTERNAL_SECRET_SECRET_KEY,
        256,
        cluster,
        client,
    )
    .await
    .context(CreateSecretKeySecretSnafu)?;

    Ok(())
}

/// Copies the Flask `SECRET_KEY` out of the user-provided credentials Secret (where SDP 26.3 kept
/// it, under the key `connections.secretKey`) into the operator-owned Secret that SDP 26.7 uses.
///
/// Does nothing if the new Secret already exists or if the old one carries no key, in which case
/// [`ensure_secrets`] generates a fresh random value.
///
// TODO: Can be removed after SDP 26.7 is released (it's only a migration from 26.3 - 26.7)
// (don't forget about the snafu Error variants).
// Removal is tracked in https://github.com/stackabletech/superset-operator/issues/755
#[instrument(skip_all)]
async fn migrate_legacy_secret_key_secret_from_26_3(
    client: &Client,
    cluster: &ValidatedCluster,
) -> Result<()> {
    let old_secret_name = &cluster.cluster_config.credentials_secret_name;
    let new_secret_name = &cluster.cluster_config.secret_key_secret_name;
    let secret_namespace = &cluster.namespace;

    let new_secret = client
        .get_opt::<Secret>(new_secret_name, secret_namespace.as_ref())
        .await
        .with_context(|_| RetrieveSecretSnafu {
            secret_name: new_secret_name,
        })?;
    if new_secret.is_some() {
        tracing::debug!("SECRET_KEY Secret already exists, nothing to migrate");
        return Ok(());
    }

    let old_secret = client
        .get_opt::<Secret>(old_secret_name, secret_namespace.as_ref())
        .await
        .with_context(|_| RetrieveSecretSnafu {
            secret_name: old_secret_name,
        })?;
    let old_secret_key = old_secret
        .and_then(|secret| secret.data)
        // Note: We remove the key to take ownership
        .and_then(|mut data| data.remove("connections.secretKey"))
        .and_then(|key| String::from_utf8(key.0).ok());
    if let Some(old_secret_key) = old_secret_key {
        tracing::info!(
            old.secret.name = old_secret_name,
            old.secret.namespace = %secret_namespace,
            new.secret.name = new_secret_name,
            new.secret.namespace = %secret_namespace,
            "Migrating old SECRET_KEY to new Secret"
        );

        let secret = Secret {
            metadata: ObjectMetaBuilder::new()
                .name(new_secret_name)
                .namespace(secret_namespace)
                .ownerreference(ownerreference_from_resource(cluster, None, Some(true)))
                .build(),
            string_data: Some(BTreeMap::from([(
                INTERNAL_SECRET_SECRET_KEY.to_string(),
                old_secret_key,
            )])),
            ..Secret::default()
        };
        client
            .create(&secret)
            .await
            .context(CreateMigratedSecretKeySecretSnafu)?;
    }

    Ok(())
}
