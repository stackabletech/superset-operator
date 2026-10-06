use stackable_operator::{
    commons::{
        affinity::{StackableAffinityFragment, affinity_between_role_pods},
        opa::OpaConfig,
    },
    k8s_openapi::api::core::v1::{PodAffinity, PodAntiAffinity},
};

use crate::crd::{APP_NAME, SupersetRole};

/// `opa_config` is only passed for roles that send requests to OPA.
pub fn get_affinity(
    cluster_name: &str,
    role: &SupersetRole,
    opa_config: Option<&OpaConfig>,
) -> StackableAffinityFragment {
    // With the role mapping from OPA configured, the role sends its requests to OPA, so prefer to
    // place it next to the OPA Pods.
    let pod_affinity = opa_config.map(|opa_config| PodAffinity {
        preferred_during_scheduling_ignored_during_execution: Some(vec![
            affinity_between_role_pods(
                "opa",
                &opa_config.config_map_name, // The discovery cm has the same name as the OpaCluster itself
                "server",
                50,
            ),
        ]),
        required_during_scheduling_ignored_during_execution: None,
    });

    StackableAffinityFragment {
        pod_affinity,
        pod_anti_affinity: Some(PodAntiAffinity {
            preferred_during_scheduling_ignored_during_execution: Some(vec![
                affinity_between_role_pods(APP_NAME, cluster_name, &role.to_string(), 70),
            ]),
            required_during_scheduling_ignored_during_execution: None,
        }),
        node_affinity: None,
        node_selector: None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rstest::rstest;
    use stackable_operator::{
        commons::affinity::StackableAffinity,
        config::fragment,
        k8s_openapi::{
            api::core::v1::{
                PodAffinity, PodAffinityTerm, PodAntiAffinity, WeightedPodAffinityTerm,
            },
            apimachinery::pkg::apis::meta::v1::LabelSelector,
        },
        kube::ResourceExt,
        utils::yaml_from_str_singleton_map,
    };

    use super::*;
    use crate::crd::v1alpha1;

    #[rstest]
    #[case(SupersetRole::Node)]
    #[case(SupersetRole::Worker)]
    #[case(SupersetRole::Beat)]
    fn test_affinity_defaults(#[case] role: SupersetRole) {
        let input = r#"
        apiVersion: superset.stackable.tech/v1alpha1
        kind: SupersetCluster
        metadata:
          name: simple-superset
        spec:
          image:
            productVersion: 6.1.0
          clusterConfig:
            credentialsSecret: superset-admin-credentials
            metadataDatabase:
              postgresql:
                host: superset-postgresql
                database: superset
                credentialsSecretName: superset-postgresql-credentials
            authorization:
              roleMappingFromOpa:
                configMapName: simple-opa
                package: superset
          nodes:
            roleGroups:
              default:
                replicas: 1
        "#;
        let superset: v1alpha1::SupersetCluster =
            yaml_from_str_singleton_map(input).expect("illegal test input");
        // The role group carries no resource/affinity overrides, so the merged config is just the
        // validated default config.
        let merged_config: v1alpha1::SupersetConfig =
            fragment::validate(v1alpha1::SupersetConfig::default_config(
                &superset.name_any(),
                &role,
                superset.get_opa_config().map(|opa_config| &opa_config.opa),
            ))
            .expect("default config should validate");

        assert_eq!(
            merged_config.affinity,
            StackableAffinity {
                pod_affinity: match role {
                    // Only the web server (node) is known to request the role mapping from OPA.
                    SupersetRole::Node => Some(PodAffinity {
                        preferred_during_scheduling_ignored_during_execution: Some(vec![
                            WeightedPodAffinityTerm {
                                pod_affinity_term: PodAffinityTerm {
                                    label_selector: Some(LabelSelector {
                                        match_expressions: None,
                                        match_labels: Some(BTreeMap::from([
                                            (
                                                "app.kubernetes.io/name".to_string(),
                                                "opa".to_string()
                                            ),
                                            (
                                                "app.kubernetes.io/instance".to_string(),
                                                "simple-opa".to_string(),
                                            ),
                                            (
                                                "app.kubernetes.io/component".to_string(),
                                                "server".to_string(),
                                            ),
                                        ])),
                                    }),
                                    topology_key: "kubernetes.io/hostname".to_string(),
                                    ..PodAffinityTerm::default()
                                },
                                weight: 50,
                            }
                        ]),
                        required_during_scheduling_ignored_during_execution: None,
                    }),
                    SupersetRole::Worker | SupersetRole::Beat => None,
                },
                pod_anti_affinity: Some(PodAntiAffinity {
                    preferred_during_scheduling_ignored_during_execution: Some(vec![
                        WeightedPodAffinityTerm {
                            pod_affinity_term: PodAffinityTerm {
                                label_selector: Some(LabelSelector {
                                    match_expressions: None,
                                    match_labels: Some(BTreeMap::from([
                                        (
                                            "app.kubernetes.io/name".to_string(),
                                            "superset".to_string(),
                                        ),
                                        (
                                            "app.kubernetes.io/instance".to_string(),
                                            "simple-superset".to_string(),
                                        ),
                                        (
                                            "app.kubernetes.io/component".to_string(),
                                            role.to_string(),
                                        )
                                    ]))
                                }),
                                topology_key: "kubernetes.io/hostname".to_string(),
                                ..PodAffinityTerm::default()
                            },
                            weight: 70
                        }
                    ]),
                    required_during_scheduling_ignored_during_execution: None,
                }),
                node_affinity: None,
                node_selector: None,
            }
        );
    }
}
