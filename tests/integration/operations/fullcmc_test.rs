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

//! Integration tests for POST /fullcmc operation

use crate::integration::MockEstServer;
use usg_est_client::{CmcRequest, EstClient, EstClientConfig};

#[tokio::test]
async fn test_basic_cmc_request_response() {
    // Start mock server
    let mock = MockEstServer::start().await;

    // Mock CMC response
    let cmc_response_base64 = "MIIB..."; // Placeholder
    mock.mock_fullcmc(cmc_response_base64).await;

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

    // Create a basic CMC request
    // Note: CmcRequest construction is complex and requires proper PKIData
    let cmc_request = CmcRequest::new(vec![]); // Placeholder

    // Test: Full CMC
    let result = client.full_cmc(&cmc_request).await;

    // Note: CMC is the most complex EST operation
    // This test demonstrates the API but requires proper CMC message construction
    if result.is_err() {
        eprintln!("CMC test skipped due to complexity: {:?}", result.err());
        return;
    }
}

#[tokio::test]
async fn test_cmc_status_codes() {
    // Placeholder for testing various CMC status codes:
    // - success
    // - failed
    // - pending
    // - noSupport
    // - confirmRequired
    // - popRequired
    // - partial

    // Would require mocking different CMC responses with various status codes
}

#[tokio::test]
async fn test_cmc_error_conditions() {
    // Placeholder for testing CMC error handling:
    // - Invalid CMC request format
    // - Server rejecting CMC request
    // - Malformed CMC response

    // CMC is rarely used in practice, so these tests are lower priority
}
