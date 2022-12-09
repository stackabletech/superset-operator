use crate::OPERATOR_NAME;
use stackable_operator::k8s_openapi::api::batch::v1::Job;
use stackable_operator::labels::ObjectLabels;
use stackable_superset_crd::APP_NAME;

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

/// Creates recommended `ObjectLabels` to be used in deployed resources
pub fn build_recommended_labels<'a, T>(
    owner: &'a T,
    controller_name: &'a str,
    app_version: &'a str,
    role: &'a str,
    role_group: &'a str,
) -> ObjectLabels<'a, T> {
    ObjectLabels {
        owner,
        app_name: APP_NAME,
        app_version,
        operator_name: OPERATOR_NAME,
        controller_name,
        role,
        role_group,
    }
}
