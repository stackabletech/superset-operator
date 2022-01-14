use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::{
        api::{
            core::v1::{EnvVar, EnvVarSource, SecretKeySelector},
        },
    },
    kube::{
        runtime::{
            reflector::ObjectRef,
        },
    },
};
use stackable_superset_crd::{
    SupersetCluster, SupersetClusterRef,
};

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object does not refer to SupersetCluster"))]
    InvalidSupersetReference,
    #[snafu(display("could not find {}", superset))]
    FindSuperset {
        source: stackable_operator::error::Error,
        superset: ObjectRef<SupersetCluster>,
    },
    #[snafu(display("object defines no version"))]
    ObjectHasNoVersion,
}

pub async fn find_superset_cluster_by_ref(
    client: &stackable_operator::client::Client,
    cluster_ref: &SupersetClusterRef,
) -> Result<SupersetCluster, Error> {
    if let SupersetClusterRef {
        name: Some(superset_name),
        namespace: maybe_superset_ns,
    } = &cluster_ref
    {
        let superset_ns = maybe_superset_ns.as_deref().unwrap_or("default");
        client
            .get::<SupersetCluster>(superset_name, Some(superset_ns))
            .await
            .with_context(|| FindSuperset {
                superset: ObjectRef::new(superset_name).within(superset_ns),
            })
    } else {
        InvalidSupersetReference.fail()
    }
}

pub fn superset_version(superset: &SupersetCluster) -> Result<&str, Error> {
    superset.spec.version.as_deref().context(ObjectHasNoVersion)
}

pub fn env_var_from_secret(var_name: &str, secret: &str, secret_key: &str) -> EnvVar {
    EnvVar {
        name: String::from(var_name),
        value_from: Some(EnvVarSource {
            secret_key_ref: Some(SecretKeySelector {
                name: Some(String::from(secret)),
                key: String::from(secret_key),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}
