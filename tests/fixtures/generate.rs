//! Test fixture generator
//!
//! This module generates test certificates and EST protocol responses
//! for use in integration tests.

use base64::prelude::*;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair};
use std::fs;
use std::path::Path;

/// Stored certificates and keys for testing
struct TestCerts {
    ca_cert: Certificate,
    ca_key: KeyPair,
    client_cert: Certificate,
    client_key: KeyPair,
    server_cert: Certificate,
    server_key: KeyPair,
}

/// Generate all test fixtures
pub fn generate_all_fixtures() -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating test fixtures...");

    // Create output directories
    let base_dir = Path::new("tests/fixtures");
    fs::create_dir_all(base_dir.join("pkcs7"))?;
    fs::create_dir_all(base_dir.join("multipart"))?;
    fs::create_dir_all(base_dir.join("cmc"))?;
    fs::create_dir_all(base_dir.join("certs"))?;

    // Generate all certificates
    println!("  Generating certificates...");
    let certs = generate_test_certs()?;

    // Save CA certificate and key
    fs::write(base_dir.join("certs/ca.pem"), certs.ca_cert.pem())?;
    fs::write(
        base_dir.join("certs/ca-key.pem"),
        certs.ca_key.serialize_pem(),
    )?;

    // Save client certificate and key
    fs::write(base_dir.join("certs/client.pem"), certs.client_cert.pem())?;
    fs::write(
        base_dir.join("certs/client-key.pem"),
        certs.client_key.serialize_pem(),
    )?;

    // Save server certificate and key
    fs::write(base_dir.join("certs/server.pem"), certs.server_cert.pem())?;
    fs::write(
        base_dir.join("certs/server-key.pem"),
        certs.server_key.serialize_pem(),
    )?;

    // Generate PKCS#7 fixtures
    println!("  Generating PKCS#7 fixtures...");
    generate_pkcs7_fixtures(&certs, base_dir)?;

    // Generate multipart fixtures
    println!("  Generating multipart fixtures...");
    generate_multipart_fixtures(&certs, base_dir)?;

    // Generate malformed fixtures
    println!("  Generating malformed fixtures...");
    generate_malformed_fixtures(base_dir)?;

    println!("All fixtures generated successfully!");
    Ok(())
}

fn generate_test_certs() -> Result<TestCerts, Box<dyn std::error::Error>> {
    // Generate CA
    let (ca_cert, ca_key) = generate_ca_cert()?;

    // Generate client cert signed by CA
    let (client_cert, client_key) = generate_client_cert(&ca_cert, &ca_key)?;

    // Generate server cert signed by CA
    let (server_cert, server_key) = generate_server_cert(&ca_cert, &ca_key)?;

    Ok(TestCerts {
        ca_cert,
        ca_key,
        client_cert,
        client_key,
        server_cert,
        server_key,
    })
}

fn generate_ca_cert() -> Result<(Certificate, KeyPair), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "EST Test CA");
    dn.push(DnType::OrganizationName, "EST Test Organization");
    dn.push(DnType::CountryName, "US");
    params.distinguished_name = dn;

    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((cert, key_pair))
}

fn generate_client_cert(
    ca: &Certificate,
    ca_key: &KeyPair,
) -> Result<(Certificate, KeyPair), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test-client.example.com");
    dn.push(DnType::OrganizationName, "EST Test Organization");
    params.distinguished_name = dn;

    params.subject_alt_names = vec![rcgen::SanType::DnsName(rcgen::Ia5String::try_from(
        "test-client.example.com",
    )?)];

    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];

    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, ca, ca_key)?;

    Ok((cert, key_pair))
}

fn generate_server_cert(
    ca: &Certificate,
    ca_key: &KeyPair,
) -> Result<(Certificate, KeyPair), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "est.example.com");
    dn.push(DnType::OrganizationName, "EST Test Organization");
    params.distinguished_name = dn;

    params.subject_alt_names = vec![rcgen::SanType::DnsName(rcgen::Ia5String::try_from(
        "est.example.com",
    )?)];

    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];

    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, ca, ca_key)?;

    Ok((cert, key_pair))
}

fn generate_pkcs7_fixtures(
    certs: &TestCerts,
    base_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // For now, we'll create a simple base64-encoded certificate as a placeholder
    // Real PKCS#7 generation would require the cms crate's builder API

    // Valid CA certs response (just the CA cert in PEM, base64 encoded)
    let ca_pem = certs.ca_cert.pem();
    let ca_base64 = BASE64_STANDARD.encode(ca_pem.as_bytes());
    fs::write(base_dir.join("pkcs7/valid-cacerts.b64"), ca_base64)?;

    // Valid enrollment response (client cert in PEM, base64 encoded)
    let client_pem = certs.client_cert.pem();
    let client_base64 = BASE64_STANDARD.encode(client_pem.as_bytes());
    fs::write(base_dir.join("pkcs7/valid-enroll.b64"), client_base64)?;

    // Empty PKCS#7 structure for error testing
    let empty_pkcs7 = vec![
        0x30, 0x0b, // SEQUENCE length 11
        0x02, 0x01, 0x01, // version = 1
        0x31, 0x00, // SET (digestAlgorithms) - empty
        0x30, 0x03, 0x06, 0x01, 0x00, // contentInfo placeholder
    ];
    fs::write(
        base_dir.join("pkcs7/empty.b64"),
        BASE64_STANDARD.encode(&empty_pkcs7),
    )?;

    Ok(())
}

fn generate_multipart_fixtures(
    certs: &TestCerts,
    base_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let boundary = "----=_Part_0_123456789.123456789";

    let cert_pem = certs.client_cert.pem();
    let key_pem = certs.client_key.serialize_pem();

    let multipart_body = format!(
        "--{boundary}\r\n\
         Content-Type: application/pkcs7-mime\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {cert_base64}\r\n\
         --{boundary}\r\n\
         Content-Type: application/pkcs8\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {key_base64}\r\n\
         --{boundary}--\r\n",
        boundary = boundary,
        cert_base64 = BASE64_STANDARD.encode(cert_pem.as_bytes()),
        key_base64 = BASE64_STANDARD.encode(key_pem.as_bytes())
    );

    fs::write(
        base_dir.join("multipart/serverkeygen-response.txt"),
        multipart_body,
    )?;

    fs::write(base_dir.join("multipart/boundary.txt"), boundary)?;

    // Malformed multipart (missing boundary)
    let malformed = "Content-Type: application/pkcs7-mime\r\nsome data\r\n";
    fs::write(base_dir.join("multipart/malformed.txt"), malformed)?;

    Ok(())
}

fn generate_malformed_fixtures(base_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Invalid base64
    fs::write(
        base_dir.join("pkcs7/invalid-base64.txt"),
        "This is not valid base64!!!",
    )?;

    // Empty file
    fs::write(base_dir.join("pkcs7/empty.txt"), "")?;

    // Generate CSR attributes fixture
    // SEQUENCE containing one OID: challengePassword (1.2.840.113549.1.9.7)
    let csrattrs_der = vec![
        0x30, 0x0b, // SEQUENCE length 11
        0x06, 0x09, // OID length 9
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x07, // challengePassword OID
    ];
    fs::write(
        base_dir.join("pkcs7/csrattrs.b64"),
        BASE64_STANDARD.encode(&csrattrs_der),
    )?;

    Ok(())
}

fn main() {
    if let Err(e) = generate_all_fixtures() {
        eprintln!("Error generating fixtures: {}", e);
        std::process::exit(1);
    }
}
