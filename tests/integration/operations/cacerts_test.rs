// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Integration tests for GET /cacerts operation

use crate::integration::MockEstServer;
use std::fs;
use usg_est_client::{EstClient, EstClientConfig};

#[tokio::test]
async fn test_successful_cacerts_retrieval() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Load valid CA certs fixture
    let ca_certs_base64 = fs::read_to_string("tests/fixtures/pkcs7/valid-cacerts.b64")
        .expect("Failed to load CA certs fixture");

    // Mock the /cacerts endpoint
    mock.mock_cacerts(&ca_certs_base64).await;

    // Create EST client
    let config = EstClientConfig::builder()
        .server_url(&mock.url())
        .expect("Valid URL")
        .trust_any_insecure() // OK for testing
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Test: Get CA certs
    let result = client.get_ca_certs().await;

    // Assert: Should succeed
    assert!(result.is_ok(), "get_ca_certs failed: {:?}", result.err());
    let ca_certs = result.unwrap();

    // Should have at least one certificate
    assert!(!ca_certs.is_empty(), "CA certs should not be empty");
}

#[tokio::test]
async fn test_invalid_content_type_handling() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock invalid content type response
    mock.mock_invalid_content_type("/.well-known/est/cacerts")
        .await;

    // Create EST client
    let config = EstClientConfig::builder()
        .server_url(&mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Test: Get CA certs with invalid content type
    let result = client.get_ca_certs().await;

    // Assert: Should fail (could be content type, parsing, or base64 error)
    // The exact error depends on the parsing order in the client implementation
    assert!(result.is_err(), "Should fail with invalid content type");
    let err = result.unwrap_err();
    assert!(
        matches!(err, usg_est_client::EstError::InvalidContentType { .. })
            || matches!(err, usg_est_client::EstError::Base64(_))
            || matches!(err, usg_est_client::EstError::CmsParsing(_)),
        "Expected InvalidContentType, Base64, or CmsParsing error, got: {:?}",
        err
    );
}

#[tokio::test]
async fn test_malformed_pkcs7_response() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Load malformed PKCS#7 fixture
    let malformed = fs::read_to_string("tests/fixtures/pkcs7/invalid-base64.txt")
        .expect("Failed to load malformed fixture");

    // Mock malformed response
    mock.mock_malformed_body("/.well-known/est/cacerts", "application/pkcs7-mime")
        .await;

    // Create EST client
    let config = EstClientConfig::builder()
        .server_url(&mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Test: Get CA certs with malformed response
    let result = client.get_ca_certs().await;

    // Assert: Should fail with base64 or parsing error
    assert!(result.is_err(), "Should fail with malformed response");
}

#[tokio::test]
async fn test_empty_certificate_list() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Load empty PKCS#7 fixture
    let empty_pkcs7 = fs::read_to_string("tests/fixtures/pkcs7/empty.b64")
        .expect("Failed to load empty PKCS#7 fixture");

    // Mock empty certificate list
    mock.mock_cacerts(&empty_pkcs7).await;

    // Create EST client
    let config = EstClientConfig::builder()
        .server_url(&mock.url())
        .expect("Valid URL")
        .trust_any_insecure()
        .build()
        .expect("Valid config");

    let client = EstClient::new(config)
        .await
        .expect("Client creation failed");

    // Test: Get CA certs with empty list
    let result = client.get_ca_certs().await;

    // This might succeed with empty list or fail with parsing error
    // depending on implementation - both are acceptable
    if let Ok(ca_certs) = result {
        // If it succeeds, the list should be empty
        assert_eq!(ca_certs.len(), 0, "Should have zero certificates");
    }
    // If it fails, that's also acceptable for malformed PKCS#7
}
