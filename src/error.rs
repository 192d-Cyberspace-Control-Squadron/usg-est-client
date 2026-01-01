//! Error types for the EST client.
//!
//! This module defines all error types that can occur during EST operations,
//! including TLS errors, HTTP errors, parsing errors, and EST-specific errors.

use thiserror::Error;

/// Result type alias using [`EstError`].
pub type Result<T> = std::result::Result<T, EstError>;

/// Errors that can occur during EST client operations.
#[derive(Debug, Error)]
pub enum EstError {
    /// TLS configuration or connection error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// HTTP request or response error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Response Content-Type header does not match expected value.
    #[error("Invalid content-type: expected '{expected}', got '{actual}'")]
    InvalidContentType {
        /// Expected content-type.
        expected: String,
        /// Actual content-type received.
        actual: String,
    },

    /// Failed to parse X.509 certificate.
    #[error("Certificate parsing error: {0}")]
    CertificateParsing(String),

    /// Failed to parse CMS/PKCS#7 structure.
    #[error("CMS/PKCS#7 parsing error: {0}")]
    CmsParsing(String),

    /// Failed to generate or parse CSR.
    #[error("CSR error: {0}")]
    Csr(String),

    /// EST server returned an error response.
    #[error("Server error {status}: {message}")]
    ServerError {
        /// HTTP status code.
        status: u16,
        /// Error message from server.
        message: String,
    },

    /// Enrollment request is pending manual approval (HTTP 202).
    ///
    /// The client should wait for `retry_after` seconds before retrying.
    #[error("Enrollment pending, retry after {retry_after} seconds")]
    EnrollmentPending {
        /// Number of seconds to wait before retrying.
        retry_after: u64,
    },

    /// Server requires authentication (HTTP 401).
    #[error("Authentication required: {challenge}")]
    AuthenticationRequired {
        /// WWW-Authenticate challenge from server.
        challenge: String,
    },

    /// Base64 decoding error.
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// DER encoding/decoding error.
    #[error("DER error: {0}")]
    Der(#[from] der::Error),

    /// URL parsing error.
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),

    /// Bootstrap fingerprint verification failed.
    #[error("Bootstrap verification failed: {0}")]
    BootstrapVerification(String),

    /// Required HTTP header is missing from response.
    #[error("Missing required header: {0}")]
    MissingHeader(String),

    /// Invalid multipart response format.
    #[error("Invalid multipart response: {0}")]
    InvalidMultipart(String),

    /// Invalid PEM data.
    #[error("Invalid PEM data: {0}")]
    InvalidPem(String),

    /// Operation not supported by server.
    #[error("Operation not supported: {0}")]
    NotSupported(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl EstError {
    /// Create a TLS error with the given message.
    pub fn tls(msg: impl Into<String>) -> Self {
        Self::Tls(msg.into())
    }

    /// Create a certificate parsing error with the given message.
    pub fn certificate_parsing(msg: impl Into<String>) -> Self {
        Self::CertificateParsing(msg.into())
    }

    /// Create a CMS parsing error with the given message.
    pub fn cms_parsing(msg: impl Into<String>) -> Self {
        Self::CmsParsing(msg.into())
    }

    /// Create a CSR error with the given message.
    pub fn csr(msg: impl Into<String>) -> Self {
        Self::Csr(msg.into())
    }

    /// Create a server error with status and message.
    pub fn server_error(status: u16, message: impl Into<String>) -> Self {
        Self::ServerError {
            status,
            message: message.into(),
        }
    }

    /// Create an enrollment pending error.
    pub fn enrollment_pending(retry_after: u64) -> Self {
        Self::EnrollmentPending { retry_after }
    }

    /// Create an authentication required error.
    pub fn authentication_required(challenge: impl Into<String>) -> Self {
        Self::AuthenticationRequired {
            challenge: challenge.into(),
        }
    }

    /// Create an invalid content-type error.
    pub fn invalid_content_type(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::InvalidContentType {
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Create a bootstrap verification error.
    pub fn bootstrap_verification(msg: impl Into<String>) -> Self {
        Self::BootstrapVerification(msg.into())
    }

    /// Create a missing header error.
    pub fn missing_header(header: impl Into<String>) -> Self {
        Self::MissingHeader(header.into())
    }

    /// Create an invalid multipart error.
    pub fn invalid_multipart(msg: impl Into<String>) -> Self {
        Self::InvalidMultipart(msg.into())
    }

    /// Create an invalid PEM error.
    pub fn invalid_pem(msg: impl Into<String>) -> Self {
        Self::InvalidPem(msg.into())
    }

    /// Create a not supported error.
    pub fn not_supported(operation: impl Into<String>) -> Self {
        Self::NotSupported(operation.into())
    }

    /// Returns true if this is a retryable error.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::EnrollmentPending { .. } | Self::Http(_) | Self::Tls(_)
        )
    }

    /// Returns the retry-after value if this is an EnrollmentPending error.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::EnrollmentPending { retry_after } => Some(*retry_after),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = EstError::server_error(400, "Bad Request");
        assert_eq!(err.to_string(), "Server error 400: Bad Request");

        let err = EstError::enrollment_pending(30);
        assert_eq!(
            err.to_string(),
            "Enrollment pending, retry after 30 seconds"
        );
    }

    #[test]
    fn test_is_retryable() {
        assert!(EstError::enrollment_pending(30).is_retryable());
        assert!(!EstError::server_error(400, "Bad").is_retryable());
    }

    #[test]
    fn test_retry_after() {
        assert_eq!(EstError::enrollment_pending(60).retry_after(), Some(60));
        assert_eq!(EstError::server_error(400, "Bad").retry_after(), None);
    }
}
