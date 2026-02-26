use stackable_operator::kvp::ObjectLabels;

use crate::{OPERATOR_NAME, crd::APP_NAME};

pub mod configmap;
pub mod deployment;
pub mod listener;
pub mod rbac;
pub mod service;
pub mod statefulset;

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
