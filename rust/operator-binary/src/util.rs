use snafu::{OptionExt, Snafu};
use stackable_operator::k8s_openapi::api::batch::v1::Job;
use stackable_operator::k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, SecretKeySelector};
use stackable_superset_crd::SupersetCluster;

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
#[snafu(context(suffix(false)))]
pub enum Error {
    #[snafu(display("object defines no version"))]
    ObjectHasNoVersion,
    #[snafu(display("object defines no stats exporter version"))]
    ObjectHasNoStatsdExporterVersion,
}

pub enum JobState {
    InProgress,
    Complete,
    Failed,
}

pub fn get_job_state(job: &Job) -> JobState {
    let conditions = job
        .status
        .as_ref()
        .and_then(|status| status.conditions.clone())
        .unwrap_or_default();

    if conditions
        .iter()
        .any(|condition| condition.type_ == "Failed" && condition.status == "True")
    {
        JobState::Failed
    } else if conditions
        .iter()
        .any(|condition| condition.type_ == "Complete" && condition.status == "True")
    {
        JobState::Complete
    } else {
        JobState::InProgress
    }
}

pub fn superset_version(superset: &SupersetCluster) -> Result<&str, Error> {
    superset.spec.version.as_deref().context(ObjectHasNoVersion)
}

pub fn statsd_exporter_version(superset: &SupersetCluster) -> Result<&str, Error> {
    superset
        .spec
        .statsd_exporter_version
        .as_deref()
        .context(ObjectHasNoStatsdExporterVersion)
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
