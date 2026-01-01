//! Integration tests for GET /csrattrs operation

use usg_est_client::{EstClient, EstClientConfig};
use crate::integration::MockEstServer;
use std::fs;

#[tokio::test]
async fn test_successful_csrattrs_retrieval() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Load CSR attributes fixture
    let csrattrs_base64 = fs::read_to_string("tests/fixtures/pkcs7/csrattrs.b64")
        .expect("Failed to load csrattrs fixture");

    // Mock CSR attributes response
    mock.mock_csrattrs(&csrattrs_base64).await;

    // Create EST client
    let config = EstClientConfig::builder()
        .server_url(&mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config).await.expect("Client creation failed");

    // Test: Get CSR attributes
    let result = client.get_csr_attributes().await;

    // Assert: Should succeed
    assert!(result.is_ok(), "get_csr_attributes failed: {:?}", result.err());
    let attrs = result.unwrap();

    // Should have at least one OID
    assert!(!attrs.oids().is_empty(), "CSR attributes should contain OIDs");
}

#[tokio::test]
async fn test_csrattrs_not_supported() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock not supported response (HTTP 404)
    mock.mock_csrattrs_not_supported().await;

    // Create EST client
    let config = EstClientConfig::builder()
        .server_url(&mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config).await.expect("Client creation failed");

    // Test: Get CSR attributes when not supported
    let result = client.get_csr_attributes().await;

    // Assert: Should fail with NotSupported error
    assert!(result.is_err(), "Should fail when CSR attributes not supported");
    let err = result.unwrap_err();
    assert!(
        matches!(err, usg_est_client::EstError::NotSupported { .. }),
        "Wrong error type: {:?}",
        err
    );
}

#[tokio::test]
async fn test_malformed_csrattrs_response() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock malformed response
    mock.mock_malformed_body("/.well-known/est/csrattrs", "application/csrattrs").await;

    // Create EST client
    let config = EstClientConfig::builder()
        .server_url(&mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config).await.expect("Client creation failed");

    // Test: Get CSR attributes with malformed response
    let result = client.get_csr_attributes().await;

    // Assert: Should fail with parsing error
    assert!(result.is_err(), "Should fail with malformed response");
}
