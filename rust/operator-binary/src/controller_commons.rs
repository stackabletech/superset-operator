use stackable_operator::{
    builder::VolumeBuilder,
    k8s_openapi::{
        api::core::v1::{ConfigMapVolumeSource, EmptyDirVolumeSource, Volume},
        apimachinery::pkg::api::resource::Quantity,
    },
    product_logging::spec::{
        ConfigMapLogConfig, ContainerLogConfig, ContainerLogConfigChoice, CustomContainerLogConfig,
    },
};
use stackable_superset_crd::LOG_VOLUME_SIZE_IN_MIB;

pub const CONFIG_VOLUME_NAME: &str = "config";
pub const LOG_CONFIG_VOLUME_NAME: &str = "log-config";
pub const LOG_VOLUME_NAME: &str = "log";

pub fn create_volumes(
    config_map_name: &str,
    log_config: Option<&ContainerLogConfig>,
) -> Vec<Volume> {
    let mut volumes = Vec::new();

    volumes.push(
        VolumeBuilder::new(CONFIG_VOLUME_NAME)
            .with_config_map(config_map_name)
            .build(),
    );
    volumes.push(Volume {
        name: LOG_VOLUME_NAME.into(),
        empty_dir: Some(EmptyDirVolumeSource {
            medium: None,
            size_limit: Some(Quantity(format!("{LOG_VOLUME_SIZE_IN_MIB}Mi"))),
        }),
        ..Volume::default()
    });

    if let Some(ContainerLogConfig {
        choice:
            Some(ContainerLogConfigChoice::Custom(CustomContainerLogConfig {
                custom: ConfigMapLogConfig { config_map },
            })),
    }) = log_config
    {
        volumes.push(Volume {
            name: LOG_CONFIG_VOLUME_NAME.into(),
            config_map: Some(ConfigMapVolumeSource {
                name: Some(config_map.into()),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        });
    } else {
        volumes.push(Volume {
            name: LOG_CONFIG_VOLUME_NAME.into(),
            config_map: Some(ConfigMapVolumeSource {
                name: Some(config_map_name.into()),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        });
    }

    volumes
}
