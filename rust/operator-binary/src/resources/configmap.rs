use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
};

use product_config::{
    flask_app_config_writer::{self},
    types::PropertyNameKind,
};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::{configmap::ConfigMapBuilder, meta::ObjectMetaBuilder},
    commons::product_image_selection::ResolvedProductImage,
    k8s_openapi::api::core::v1::ConfigMap,
    product_config_utils::{CONFIG_OVERRIDE_FILE_FOOTER_KEY, CONFIG_OVERRIDE_FILE_HEADER_KEY},
    product_logging::spec::Logging,
    role_utils::RoleGroupRef,
};

use crate::{
    authorization::opa::{OPA_IMPORTS, SupersetOpaConfigResolved},
    config::{self, PYTHON_IMPORTS},
    crd::{
        SUPERSET_CONFIG_FILENAME, SupersetConfigOptions,
        authentication::SupersetClientAuthenticationDetailsResolved,
        v1alpha1::{Container, SupersetCluster},
    },
    product_logging::extend_config_map_with_log_config,
    superset_controller::SUPERSET_CONTROLLER_NAME,
    util::build_recommended_labels,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to add Superset config settings"))]
    AddSupersetConfig { source: crate::config::Error },

    #[snafu(display(
        "failed to write to String (Vec<u8> to be precise) containing superset config"
    ))]
    WriteToConfigFileString { source: std::io::Error },

    #[snafu(display("failed to build Metadata"))]
    BuildMetadata {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to build config file for {rolegroup}"))]
    BuildRoleGroupConfigFile {
        source: flask_app_config_writer::FlaskAppConfigWriterError,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },

    #[snafu(display("failed to build ConfigMap for {rolegroup}"))]
    BuildRoleGroupConfig {
        source: stackable_operator::builder::configmap::Error,
        rolegroup: RoleGroupRef<SupersetCluster>,
    },

    #[snafu(display("failed to add the logging configuration to the ConfigMap [{cm_name}]"))]
    InvalidLoggingConfig {
        source: crate::product_logging::Error,
        cm_name: String,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// The rolegroup [`ConfigMap`] configures the rolegroup based on the configuration given by the administrator
#[allow(clippy::too_many_arguments)]
pub fn build_rolegroup_config_map(
    superset: &SupersetCluster,
    resolved_product_image: &ResolvedProductImage,
    rolegroup: &RoleGroupRef<SupersetCluster>,
    rolegroup_config: &HashMap<PropertyNameKind, BTreeMap<String, String>>,
    authentication_config: &SupersetClientAuthenticationDetailsResolved,
    superset_opa_config: &Option<SupersetOpaConfigResolved>,
    logging: &Logging<Container>,
) -> Result<ConfigMap, Error> {
    let mut config_properties = BTreeMap::new();
    let mut imports = PYTHON_IMPORTS.to_vec();
    // TODO: this is true per default for versions 3.0.0 and up.
    //    We deactivate it here to keep existing functionality.
    //    However this is a security issue and should be configured properly
    //    Issue: https://github.com/stackabletech/superset-operator/issues/416
    config_properties.insert("TALISMAN_ENABLED".to_string(), "False".to_string());

    config::add_superset_config(&mut config_properties, authentication_config)
        .context(AddSupersetConfigSnafu)?;

    // Adding opa configuration properties to config_properties.
    // This will be injected as key/value pair in superset_config.py
    if let Some(opa_config) = superset_opa_config {
        // If opa role mapping is configured, insert CustomOpaSecurityManager import
        imports.extend(OPA_IMPORTS);

        config_properties.extend(opa_config.as_config());
    }

    // The order here should be kept in order to preserve overrides.
    // No properties should be added after this extend.
    config_properties.extend(
        rolegroup_config
            .get(&PropertyNameKind::File(
                SUPERSET_CONFIG_FILENAME.to_string(),
            ))
            .cloned()
            .unwrap_or_default(),
    );

    let mut config_file = Vec::new();

    // By removing the keys from `config_properties`, we avoid pasting the Python code into a Python variable as well
    // (which would be bad)
    if let Some(header) = config_properties.remove(CONFIG_OVERRIDE_FILE_HEADER_KEY) {
        writeln!(config_file, "{}", header).context(WriteToConfigFileStringSnafu)?;
    }
    let temp_file_footer = config_properties.remove(CONFIG_OVERRIDE_FILE_FOOTER_KEY);

    flask_app_config_writer::write::<SupersetConfigOptions, _, _>(
        &mut config_file,
        config_properties.iter(),
        &imports,
    )
    .with_context(|_| BuildRoleGroupConfigFileSnafu {
        rolegroup: rolegroup.clone(),
    })?;

    if let Some(footer) = temp_file_footer {
        writeln!(config_file, "{}", footer).context(WriteToConfigFileStringSnafu)?;
    }

    let mut cm_builder = ConfigMapBuilder::new();

    cm_builder
        .metadata(
            ObjectMetaBuilder::new()
                .name_and_namespace(superset)
                .name(rolegroup.object_name())
                .ownerreference_from_resource(superset, None, Some(true))
                .context(ObjectMissingMetadataForOwnerRefSnafu)?
                .with_recommended_labels(build_recommended_labels(
                    superset,
                    SUPERSET_CONTROLLER_NAME,
                    &resolved_product_image.app_version_label_value,
                    &rolegroup.role,
                    &rolegroup.role_group,
                ))
                .context(BuildMetadataSnafu)?
                .build(),
        )
        .add_data(
            SUPERSET_CONFIG_FILENAME,
            String::from_utf8(config_file).unwrap(),
        );

    extend_config_map_with_log_config(
        rolegroup,
        logging,
        &Container::Superset,
        &Container::Vector,
        &mut cm_builder,
    )
    .context(InvalidLoggingConfigSnafu {
        cm_name: rolegroup.object_name(),
    })?;

    cm_builder
        .build()
        .with_context(|_| BuildRoleGroupConfigSnafu {
            rolegroup: rolegroup.clone(),
        })
}
