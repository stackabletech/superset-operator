//! Builders that assemble Kubernetes resources for superset rolegroups.

use std::str::FromStr;

use stackable_operator::v2::types::operator::RoleGroupName;

pub mod command;
pub mod properties;
pub mod resource;

// Placeholder role-group name used for the recommended labels of the role-level `Listener`
// (which is not tied to a single role group).
stackable_operator::constant!(pub(crate) PLACEHOLDER_LISTENER_ROLE_GROUP: RoleGroupName = "none");
