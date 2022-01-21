use snafu::{OptionExt, Snafu};
use stackable_operator::{
    k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, SecretKeySelector},
};
use stackable_superset_crd::{SupersetCluster};

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object defines no version"))]
    ObjectHasNoVersion,
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
