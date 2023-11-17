/// Adds a CA file from `cert_file` into a truststore named `truststore.p12` in `destination_directory`
/// under the alias `alias_name`.
pub fn add_cert_to_system_truststore_command(cert_file: &str) -> String {
    format!(
        "mkdir -p /stackable/certs/
HASH=$(openssl x509 -subject_hash -in /stackable/secrets/tls/ca.crt -nocert)
cp {cert_file} /stackable/certs/${{HASH}}.0
# cp {cert_file} /stackable/certs/${{HASH}}.0
# TODO call python -c \"import ssl; print(ssl.get_default_verify_paths())\"
cat {cert_file} >> \"$(python -c 'import certifi; print(certifi.where())')\""
    )
}
