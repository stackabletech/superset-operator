use stackable_operator::crd::CustomResourceExt;
use stackable_superset_crd::commands::{Init, Restart, Start, Stop};
use stackable_superset_crd::{SupersetCluster, SupersetCredentials};

fn main() -> Result<(), stackable_operator::error::Error> {
    built::write_built_file().expect("Failed to acquire build-time information");

    SupersetCluster::write_yaml_schema("../../deploy/crd/supersetcluster.crd.yaml")?;
    SupersetCredentials::write_yaml_schema("../../deploy/crd/supersetcredentials.crd.yaml")?;
    Init::write_yaml_schema("../../deploy/crd/init.crd.yaml")?;
    Restart::write_yaml_schema("../../deploy/crd/restart.crd.yaml")?;
    Start::write_yaml_schema("../../deploy/crd/start.crd.yaml")?;
    Stop::write_yaml_schema("../../deploy/crd/stop.crd.yaml")?;

    Ok(())
}
