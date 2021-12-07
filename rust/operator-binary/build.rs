use stackable_operator::crd::CustomResourceExt;
use stackable_superset_crd::commands::Init;
use stackable_superset_crd::SupersetCluster;

fn main() {
    built::write_built_file().expect("Failed to acquire build-time information");

    SupersetCluster::write_yaml_schema("../../deploy/crd/supersetcluster.crd.yaml").unwrap();
    Init::write_yaml_schema("../../deploy/crd/init.crd.yaml").unwrap();
}
