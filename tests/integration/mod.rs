//! Integration test utilities and helpers
//!
//! This module provides common test infrastructure for EST client integration tests,
//! including mock server setup, fixture loading, and test helpers.

use base64::prelude::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Content types used in EST protocol
pub const CONTENT_TYPE_PKCS7: &str = "application/pkcs7-mime";
pub const CONTENT_TYPE_PKCS10: &str = "application/pkcs10";
pub const CONTENT_TYPE_CSRATTRS: &str = "application/csrattrs";
pub const CONTENT_TYPE_MULTIPART: &str = "multipart/mixed";

/// EST operation paths
pub const PATH_CACERTS: &str = "/.well-known/est/cacerts";
pub const PATH_SIMPLEENROLL: &str = "/.well-known/est/simpleenroll";
pub const PATH_SIMPLEREENROLL: &str = "/.well-known/est/simplereenroll";
pub const PATH_CSRATTRS: &str = "/.well-known/est/csrattrs";
pub const PATH_SERVERKEYGEN: &str = "/.well-known/est/serverkeygen";
pub const PATH_FULLCMC: &str = "/.well-known/est/fullcmc";

/// Mock EST server builder for integration tests
pub struct MockEstServer {
    server: MockServer,
}

impl MockEstServer {
    /// Create a new mock EST server
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        Self { server }
    }

    /// Get the base URL of the mock server
    pub fn url(&self) -> String {
        self.server.uri()
    }

    /// Get a reference to the inner MockServer for custom mocking
    pub fn inner(&self) -> &MockServer {
        &self.server
    }

    /// Mock a successful CA certificates response
    pub async fn mock_cacerts(&self, pkcs7_base64: &str) {
        Mock::given(method("GET"))
            .and(path(PATH_CACERTS))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(pkcs7_base64)
                    .insert_header("Content-Type", CONTENT_TYPE_PKCS7)
                    .insert_header("Content-Transfer-Encoding", "base64"),
            )
            .mount(&self.server)
            .await;
    }

    /// Mock a successful enrollment response (HTTP 200)
    pub async fn mock_enroll_success(&self, cert_pkcs7_base64: &str) {
        Mock::given(method("POST"))
            .and(path(PATH_SIMPLEENROLL))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(cert_pkcs7_base64)
                    .insert_header("Content-Type", CONTENT_TYPE_PKCS7)
                    .insert_header("Content-Transfer-Encoding", "base64"),
            )
            .mount(&self.server)
            .await;
    }

    /// Mock a pending enrollment response (HTTP 202)
    pub async fn mock_enroll_pending(&self, retry_after: u64) {
        Mock::given(method("POST"))
            .and(path(PATH_SIMPLEENROLL))
            .respond_with(
                ResponseTemplate::new(202)
                    .insert_header("Retry-After", retry_after.to_string()),
            )
            .mount(&self.server)
            .await;
    }

    /// Mock an authentication required response (HTTP 401)
    pub async fn mock_enroll_auth_required(&self) {
        Mock::given(method("POST"))
            .and(path(PATH_SIMPLEENROLL))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header("WWW-Authenticate", "Basic realm=\"EST\""),
            )
            .mount(&self.server)
            .await;
    }

    /// Mock a server error response
    pub async fn mock_server_error(&self, status: u16, message: &str) {
        Mock::given(method("POST"))
            .and(path(PATH_SIMPLEENROLL))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_string(message)
                    .insert_header("Content-Type", "text/plain"),
            )
            .mount(&self.server)
            .await;
    }

    /// Mock a successful re-enrollment response
    pub async fn mock_reenroll_success(&self, cert_pkcs7_base64: &str) {
        Mock::given(method("POST"))
            .and(path(PATH_SIMPLEREENROLL))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(cert_pkcs7_base64)
                    .insert_header("Content-Type", CONTENT_TYPE_PKCS7)
                    .insert_header("Content-Transfer-Encoding", "base64"),
            )
            .mount(&self.server)
            .await;
    }

    /// Mock a CSR attributes response
    pub async fn mock_csrattrs(&self, attrs_base64: &str) {
        Mock::given(method("GET"))
            .and(path(PATH_CSRATTRS))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(attrs_base64)
                    .insert_header("Content-Type", CONTENT_TYPE_CSRATTRS)
                    .insert_header("Content-Transfer-Encoding", "base64"),
            )
            .mount(&self.server)
            .await;
    }

    /// Mock a CSR attributes not supported response (HTTP 404)
    pub async fn mock_csrattrs_not_supported(&self) {
        Mock::given(method("GET"))
            .and(path(PATH_CSRATTRS))
            .respond_with(ResponseTemplate::new(404))
            .mount(&self.server)
            .await;
    }

    /// Mock a server key generation response (multipart)
    pub async fn mock_serverkeygen(&self, multipart_body: &str, boundary: &str) {
        Mock::given(method("POST"))
            .and(path(PATH_SERVERKEYGEN))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(multipart_body)
                    .insert_header(
                        "Content-Type",
                        format!("{}; boundary={}", CONTENT_TYPE_MULTIPART, boundary),
                    ),
            )
            .mount(&self.server)
            .await;
    }

    /// Mock a full CMC response
    pub async fn mock_fullcmc(&self, cmc_response_base64: &str) {
        Mock::given(method("POST"))
            .and(path(PATH_FULLCMC))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(cmc_response_base64)
                    .insert_header("Content-Type", "application/pkcs7-mime; smime-type=CMC-response")
                    .insert_header("Content-Transfer-Encoding", "base64"),
            )
            .mount(&self.server)
            .await;
    }

    /// Mock an invalid content type response
    pub async fn mock_invalid_content_type(&self, operation_path: &str) {
        Mock::given(method("GET"))
            .and(path(operation_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("invalid")
                    .insert_header("Content-Type", "text/plain"),
            )
            .mount(&self.server)
            .await;
    }

    /// Mock a malformed response body
    pub async fn mock_malformed_body(&self, operation_path: &str, content_type: &str) {
        Mock::given(method("GET"))
            .and(path(operation_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("not-valid-base64!!!")
                    .insert_header("Content-Type", content_type)
                    .insert_header("Content-Transfer-Encoding", "base64"),
            )
            .mount(&self.server)
            .await;
    }
}

/// Test fixture helpers
pub mod fixtures {
    use super::*;

    /// Generate a minimal valid PKCS#7 certs-only structure (base64)
    ///
    /// This creates a basic SignedData structure with no actual certificates
    /// for testing error conditions.
    pub fn empty_pkcs7_base64() -> String {
        // Minimal PKCS#7 SignedData structure (certs-only)
        // SEQUENCE { version, digestAlgorithms, contentInfo, certificates (empty) }
        let der = vec![
            0x30, 0x0b, // SEQUENCE length 11
            0x02, 0x01, 0x01, // version = 1
            0x31, 0x00, // SET (digestAlgorithms) - empty
            0x30, 0x03, 0x06, 0x01, 0x00, // contentInfo placeholder
        ];
        BASE64_STANDARD.encode(&der)
    }

    /// Generate a simple CSR attributes response (base64)
    /// Contains a single OID for challenge password
    pub fn simple_csrattrs_base64() -> String {
        // SEQUENCE containing one OID: challengePassword (1.2.840.113549.1.9.7)
        let der = vec![
            0x30, 0x0b, // SEQUENCE length 11
            0x06, 0x09, // OID length 9
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x07, // challengePassword OID
        ];
        BASE64_STANDARD.encode(&der)
    }

    /// Generate a simple multipart response for serverkeygen
    pub fn simple_multipart_response(boundary: &str, cert_pem: &str, key_pem: &str) -> String {
        format!(
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
            cert_base64 = BASE64_STANDARD.encode(cert_pem),
            key_base64 = BASE64_STANDARD.encode(key_pem)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_server_starts() {
        let mock_server = MockEstServer::start().await;
        assert!(!mock_server.url().is_empty());
        assert!(mock_server.url().starts_with("http://"));
    }

    #[tokio::test]
    async fn test_fixtures_generate_valid_base64() {
        let pkcs7 = fixtures::empty_pkcs7_base64();
        assert!(BASE64_STANDARD.decode(&pkcs7).is_ok());

        let csrattrs = fixtures::simple_csrattrs_base64();
        assert!(BASE64_STANDARD.decode(&csrattrs).is_ok());
    }
}
