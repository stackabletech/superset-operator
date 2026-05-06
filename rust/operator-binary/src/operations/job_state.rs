use stackable_operator::k8s_openapi::api::batch::v1::Job;

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
