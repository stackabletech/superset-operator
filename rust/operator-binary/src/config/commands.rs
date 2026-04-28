/// Adds a CA file from `cert_file` to the root certificates of Python Certifi
pub fn add_cert_to_python_certifi_command(cert_file: &str) -> String {
    format!("cat {cert_file} >> \"$(python -c 'import certifi; print(certifi.where())')\"")
}
