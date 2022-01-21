use stackable_operator::crd::CustomResourceExt;
use stackable_superset_crd::commands::{AddDruids, SupersetDB};
use stackable_superset_crd::SupersetCluster;

fn main() {
    built::write_built_file().expect("Failed to acquire build-time information");

    SupersetCluster::write_yaml_schema("../../deploy/crd/supersetcluster.crd.yaml").unwrap();
    SupersetDB::write_yaml_schema("../../deploy/crd/supersetdb.crd.yaml").unwrap();
    AddDruids::write_yaml_schema("../../deploy/crd/adddruids.crd.yaml").unwrap();
}
