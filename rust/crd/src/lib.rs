pub mod commands;
pub mod error;

use crate::commands::{Restart, Start, Stop};

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use k8s_openapi::schemars::_serde_json::Value;
use kube::api::ApiResource;
use kube::CustomResource;
use kube::CustomResourceExt;
use schemars::JsonSchema;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
use stackable_operator::command::{CommandRef, HasCommands, HasRoleRestartOrder};
use stackable_operator::controller::HasOwned;
use stackable_operator::crd::HasApplication;
use stackable_operator::identity::PodToNodeMapping;
use stackable_operator::product_config_utils::{ConfigError, Configuration};
use stackable_operator::role_utils::Role;
use stackable_operator::status::{
    ClusterExecutionStatus, Conditions, HasClusterExecutionStatus, HasCurrentCommand, Status,
    Versioned,
};
use stackable_operator::versioning::{ProductVersion, Versioning, VersioningState};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use strum_macros::Display;
use strum_macros::EnumIter;

pub const APP_NAME: &str = "superset";
pub const MANAGED_BY: &str = "superset-operator";

pub const CONFIG_MAP_TYPE_DATA: &str = "data";
pub const CONFIG_MAP_TYPE_ID: &str = "id";

pub const HTTP_PORT: &str = "http";

#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[kube(
    group = "superset.stackable.tech",
    version = "v1alpha1",
    kind = "SupersetCluster",
    plural = "supersetclusters",
    shortname = "superset",
    namespaced
)]
#[kube(status = "SupersetClusterStatus")]
pub struct SupersetClusterSpec {
    pub version: SupersetVersion,
    pub servers: Role<SupersetConfig>,
}

#[derive(
    Clone, Debug, Deserialize, Display, EnumIter, Eq, Hash, JsonSchema, PartialEq, Serialize,
)]
pub enum SupersetRole {
    #[strum(serialize = "node")]
    Node,
}

impl Status<SupersetClusterStatus> for SupersetCluster {
    fn status(&self) -> &Option<SupersetClusterStatus> {
        &self.status
    }
    fn status_mut(&mut self) -> &mut Option<SupersetClusterStatus> {
        &mut self.status
    }
}

impl HasRoleRestartOrder for SupersetCluster {
    fn get_role_restart_order() -> Vec<String> {
        vec![SupersetRole::Node.to_string()]
    }
}

impl HasCommands for SupersetCluster {
    fn get_command_types() -> Vec<ApiResource> {
        vec![
            Start::api_resource(),
            Stop::api_resource(),
            Restart::api_resource(),
        ]
    }
}

impl HasOwned for SupersetCluster {
    fn owned_objects() -> Vec<&'static str> {
        vec![Restart::crd_name(), Start::crd_name(), Stop::crd_name()]
    }
}

impl HasApplication for SupersetCluster {
    fn get_application_name() -> &'static str {
        APP_NAME
    }
}

impl HasClusterExecutionStatus for SupersetCluster {
    fn cluster_execution_status(&self) -> Option<ClusterExecutionStatus> {
        self.status
            .as_ref()
            .and_then(|status| status.cluster_execution_status.clone())
    }

    fn cluster_execution_status_patch(&self, execution_status: &ClusterExecutionStatus) -> Value {
        json!({ "clusterExecutionStatus": execution_status })
    }
}

// TODO: These all should be "Property" Enums that can be either simple or complex where complex allows forcing/ignoring errors and/or warnings
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetConfig {}

impl Configuration for SupersetConfig {
    type Configurable = SupersetCluster;

    fn compute_env(
        &self,
        _resource: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let mut result = BTreeMap::new();

        // TODO: Readd if we want jmx metrics gathered
        //if let Some(metrics_port) = self.metrics_port {
        //    result.insert(METRICS_PORT.to_string(), Some(metrics_port.to_string()));
        // }
        Ok(result)
    }

    fn compute_cli(
        &self,
        _resource: &Self::Configurable,
        _role_name: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        Ok(BTreeMap::new())
    }

    fn compute_files(
        &self,
        _resource: &Self::Configurable,
        _role_name: &str,
        _file: &str,
    ) -> Result<BTreeMap<String, Option<String>>, ConfigError> {
        let mut result = BTreeMap::new();

        // TODO: Insert configs here

        Ok(result)
    }
}

#[allow(non_camel_case_types)]
#[derive(
    Clone,
    Debug,
    Deserialize,
    Eq,
    JsonSchema,
    PartialEq,
    Serialize,
    strum_macros::Display,
    strum_macros::EnumString,
)]
pub enum SupersetVersion {
    #[serde(rename = "1.0.0")]
    #[strum(serialize = "1.0.0")]
    v1_0_0,

    #[serde(rename = "2.0.0")]
    #[strum(serialize = "2.0.0")]
    v2_0_0,
}

impl SupersetVersion {
    pub fn package_name(&self) -> String {
        format!("superset-server-{}", self.to_string())
    }
}

impl Versioning for SupersetVersion {
    fn versioning_state(&self, other: &Self) -> VersioningState {
        let from_version = match Version::parse(&self.to_string()) {
            Ok(v) => v,
            Err(e) => {
                return VersioningState::Invalid(format!(
                    "Could not parse [{}] to SemVer: {}",
                    self.to_string(),
                    e.to_string()
                ))
            }
        };

        let to_version = match Version::parse(&other.to_string()) {
            Ok(v) => v,
            Err(e) => {
                return VersioningState::Invalid(format!(
                    "Could not parse [{}] to SemVer: {}",
                    other.to_string(),
                    e.to_string()
                ))
            }
        };

        match to_version.cmp(&from_version) {
            Ordering::Greater => VersioningState::ValidUpgrade,
            Ordering::Less => VersioningState::ValidDowngrade,
            Ordering::Equal => VersioningState::NoOp,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersetClusterStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ProductVersion<SupersetVersion>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<PodToNodeMapping>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_command: Option<CommandRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_execution_status: Option<ClusterExecutionStatus>,
}

impl Versioned<SupersetVersion> for SupersetClusterStatus {
    fn version(&self) -> &Option<ProductVersion<SupersetVersion>> {
        &self.version
    }
    fn version_mut(&mut self) -> &mut Option<ProductVersion<SupersetVersion>> {
        &mut self.version
    }
}

impl Conditions for SupersetClusterStatus {
    fn conditions(&self) -> &[Condition] {
        self.conditions.as_slice()
    }
    fn conditions_mut(&mut self) -> &mut Vec<Condition> {
        &mut self.conditions
    }
}

impl HasCurrentCommand for SupersetClusterStatus {
    fn current_command(&self) -> Option<CommandRef> {
        self.current_command.clone()
    }
    fn set_current_command(&mut self, command: CommandRef) {
        self.current_command = Some(command);
    }
    fn clear_current_command(&mut self) {
        self.current_command = None
    }
    fn tracking_location() -> &'static str {
        "/status/currentCommand"
    }
}

#[cfg(test)]
mod tests {
    use crate::SupersetVersion;
    use stackable_operator::versioning::{Versioning, VersioningState};
    use std::str::FromStr;

    #[test]
    fn test_superset_version_versioning() {
        assert_eq!(
            SupersetVersion::v1_0_0.versioning_state(&SupersetVersion::v2_0_0),
            VersioningState::ValidUpgrade
        );
        assert_eq!(
            SupersetVersion::v2_0_0.versioning_state(&SupersetVersion::v1_0_0),
            VersioningState::ValidDowngrade
        );
        assert_eq!(
            SupersetVersion::v1_0_0.versioning_state(&SupersetVersion::v1_0_0),
            VersioningState::NoOp
        );
    }

    #[test]
    fn test_version_conversion() {
        SupersetVersion::from_str("1.0.0").unwrap();
    }

    #[test]
    fn test_package_name() {
        assert_eq!(
            SupersetVersion::v1_0_0.package_name(),
            format!("superset-server-{}", SupersetVersion::v1_0_0.to_string())
        );
    }
}
