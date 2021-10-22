use clap::{crate_version, App, AppSettings, SubCommand};
use stackable_operator::{cli, logging};
use stackable_operator::{client, error};
use stackable_superset_crd::commands::{Restart, Start, Stop};
use stackable_superset_crd::SupersetCluster;

mod built_info {
    // The file has been placed there by the build script.
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[tokio::main]
async fn main() -> Result<(), error::Error> {
    logging::initialize_logging("SUPERSET_OPERATOR_LOG");

    // Handle CLI arguments
    let matches = App::new(built_info::PKG_DESCRIPTION)
        .author("Stackable GmbH - info@stackable.de")
        .about(built_info::PKG_DESCRIPTION)
        .version(crate_version!())
        .arg(cli::generate_productconfig_arg())
        .subcommand(
            SubCommand::with_name("crd")
                .setting(AppSettings::ArgRequiredElseHelp)
                .subcommand(cli::generate_crd_subcommand::<SupersetCluster>()),
        )
        .get_matches();

    if let ("crd", Some(subcommand)) = matches.subcommand() {
        if cli::handle_crd_subcommand::<SupersetCluster>(subcommand)? {
            return Ok(());
        };
    }

    let paths = vec![
        "deploy/config-spec/properties.yaml",
        "/etc/stackable/superset-operator/config-spec/properties.yaml",
    ];
    let product_config_path = cli::handle_productconfig_arg(&matches, paths)?;

    stackable_operator::utils::print_startup_string(
        built_info::PKG_DESCRIPTION,
        built_info::PKG_VERSION,
        built_info::GIT_VERSION,
        built_info::TARGET,
        built_info::BUILT_TIME_UTC,
        built_info::RUSTC_VERSION,
    );

    let client = client::create_client(Some("superset.stackable.tech".to_string())).await?;

    tokio::try_join!(
        stackable_superset_operator::create_controller(client.clone(), &product_config_path),
        stackable_operator::command_controller::create_command_controller::<Restart, SupersetCluster>(
            client.clone()
        ),
        stackable_operator::command_controller::create_command_controller::<Start, SupersetCluster>(
            client.clone()
        ),
        stackable_operator::command_controller::create_command_controller::<Stop, SupersetCluster>(
            client.clone()
        )
    )?;

    Ok(())
}
