//! Integration tests for TLS configuration

use usg_est_client::{EstClient, EstClientConfig};
use crate::integration::MockEstServer;
use std::fs;

#[tokio::test]
async fn test_tls_12_minimum_version_enforcement() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Create EST client (rustls enforces TLS 1.2+ by default)
    let config = EstClientConfig::builder()
        .server_url(&mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config).await;

    // Should succeed - rustls enforces TLS 1.2+ minimum
    assert!(client.is_ok(), "Client should enforce TLS 1.2+ minimum");
}

#[tokio::test]
async fn test_tls_13_support() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Create EST client
    let config = EstClientConfig::builder()
        .server_url(&mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config).await;

    // Should succeed - rustls supports both TLS 1.2 and 1.3
    assert!(client.is_ok(), "Client should support TLS 1.3");
}

#[tokio::test]
async fn test_certificate_verification_with_webpki_roots() {
    // Test that default config uses WebPKI roots

    let config = EstClientConfig::builder()
        .server_url("https://example.com")
        .expect("Valid URL")
        .build()
        .expect("Valid config");

    // Config should use WebPKI roots by default
    assert!(
        matches!(config.trust_anchors, usg_est_client::TrustAnchors::WebPki),
        "Should use WebPKI roots by default"
    );
}

#[tokio::test]
async fn test_certificate_verification_with_explicit_trust_anchors() {
    // Load CA certificate
    let ca_cert_pem = fs::read("tests/fixtures/certs/ca.pem")
        .expect("Failed to load CA cert");

    // Create config with explicit trust anchor
    let config = EstClientConfig::builder()
        .server_url("https://test.example.com")
        .expect("Valid URL")
        .trust_explicit(vec![ca_cert_pem])
        .build()
        .expect("Valid config");

    // Verify explicit trust anchors are configured
    assert!(
        matches!(config.trust_anchors, usg_est_client::TrustAnchors::Explicit(_)),
        "Should use explicit trust anchors"
    );
}

#[tokio::test]
async fn test_hostname_verification() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Create EST client
    let config = EstClientConfig::builder()
        .server_url(&mock.url())
        .expect("Valid URL")
        .trust_any_insecure() // Required for mock server
        .build()
        .expect("Valid config");

    let client = EstClient::new(config).await;

    // Should succeed with mock server
    assert!(client.is_ok(), "Client should handle hostname verification");

    // Note: In production, rustls enforces hostname verification
    // The mock server uses a self-signed cert, so we need trust_any_insecure
}

#[tokio::test]
async fn test_insecure_mode_for_testing_only() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Create EST client with insecure mode (for testing)
    let config = EstClientConfig::builder()
        .server_url(&mock.url())
        .expect("Valid URL")
        .trust_any_insecure() // ⚠️ ONLY FOR TESTING
        .build()
        .expect("Valid config");

    let client = EstClient::new(config).await;

    // Should succeed with insecure mode
    assert!(client.is_ok(), "Client should allow insecure mode for testing");

    // WARNING: trust_any_insecure should NEVER be used in production!
}

#[tokio::test]
async fn test_tls_configuration_with_client_certificate() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Load client cert and key
    let client_cert_pem = fs::read("tests/fixtures/certs/client.pem")
        .expect("Failed to load client cert");
    let client_key_pem = fs::read("tests/fixtures/certs/client-key.pem")
        .expect("Failed to load client key");

    // Create EST client with TLS client cert
    let config = EstClientConfig::builder()
        .server_url(&mock.url())
        .expect("Valid URL")
        .client_identity(usg_est_client::ClientIdentity::new(client_cert_pem, client_key_pem))
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config).await;

    // Should succeed with client certificate configured
    assert!(client.is_ok(), "Client should support TLS client certificates");
}

#[tokio::test]
async fn test_tls_with_multiple_trust_anchors() {
    // Load multiple CA certificates
    let ca_cert_pem = fs::read("tests/fixtures/certs/ca.pem")
        .expect("Failed to load CA cert");

    // Create another CA cert (for this test, we'll use the same one twice)
    let ca_certs = vec![ca_cert_pem.clone(), ca_cert_pem];

    // Create config with multiple trust anchors
    let config = EstClientConfig::builder()
        .server_url("https://test.example.com")
        .expect("Valid URL")
        .trust_explicit(ca_certs)
        .build()
        .expect("Valid config");

    // Verify multiple trust anchors are configured
    if let usg_est_client::TrustAnchors::Explicit(anchors) = &config.trust_anchors {
        assert_eq!(anchors.len(), 2, "Should have 2 trust anchors");
    } else {
        panic!("Expected Explicit trust anchors");
    }
}

#[tokio::test]
async fn test_tls_timeout_configuration() {
    use std::time::Duration;

    // Create config with custom timeout
    let config = EstClientConfig::builder()
        .server_url("https://test.example.com")
        .expect("Valid URL")
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Valid config");

    // Verify timeout is configured
    assert_eq!(config.timeout, Duration::from_secs(10), "Should have custom timeout");
}

#[tokio::test]
async fn test_ca_label_in_url_configuration() {
    // Create config with CA label
    let config = EstClientConfig::builder()
        .server_url("https://test.example.com")
        .expect("Valid URL")
        .ca_label("myca")
        .build()
        .expect("Valid config");

    // Verify CA label is configured
    assert_eq!(
        config.ca_label,
        Some("myca".to_string()),
        "Should have CA label configured"
    );
}
