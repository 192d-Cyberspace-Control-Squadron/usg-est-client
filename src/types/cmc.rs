//! CMC (Certificate Management over CMS) message types.
//!
//! This module provides types for Full CMC requests and responses
//! as defined in RFC 5272 and used by EST in RFC 7030 Section 4.3.

use x509_cert::Certificate;

use crate::error::{EstError, Result};

/// CMC request message (PKIData).
///
/// A Full CMC request allows for more complex PKI operations than
/// the simple enrollment endpoints.
#[derive(Debug, Clone)]
pub struct CmcRequest {
    /// DER-encoded CMC PKIData.
    pub data: Vec<u8>,
}

impl CmcRequest {
    /// Create a new CMC request from raw DER data.
    pub fn from_der(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a CMC request from a pre-built message.
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self { data: data.into() }
    }

    /// Get the raw DER-encoded data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Encode the request for transmission (base64).
    pub fn encode_base64(&self) -> String {
        use base64::prelude::*;
        BASE64_STANDARD.encode(&self.data)
    }
}

/// CMC response message (PKIResponse/ResponseBody).
///
/// Contains the server's response to a Full CMC request.
#[derive(Debug, Clone)]
pub struct CmcResponse {
    /// DER-encoded CMC PKIResponse.
    pub data: Vec<u8>,

    /// Certificates extracted from the response, if any.
    pub certificates: Vec<Certificate>,

    /// Status of the CMC operation.
    pub status: CmcStatus,
}

impl CmcResponse {
    /// Parse a CMC response from base64-encoded DER data.
    pub fn parse(body: &[u8]) -> Result<Self> {
        use base64::prelude::*;

        // Decode base64
        let cleaned: Vec<u8> = body
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();

        let data = BASE64_STANDARD
            .decode(&cleaned)
            .map_err(EstError::Base64)?;

        // For now, we don't fully parse the CMC structure
        // This is a placeholder for complete CMC implementation
        Ok(Self {
            data,
            certificates: Vec::new(),
            status: CmcStatus::Success,
        })
    }

    /// Get the raw DER-encoded response data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns true if the CMC operation was successful.
    pub fn is_success(&self) -> bool {
        matches!(self.status, CmcStatus::Success)
    }
}

/// CMC operation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmcStatus {
    /// Operation completed successfully.
    Success,

    /// Operation failed.
    Failed,

    /// Operation is pending.
    Pending,

    /// No support for the requested operation.
    NoSupport,

    /// Confirmation is required.
    ConfirmRequired,

    /// Request was rejected by policy.
    PopRequired,

    /// Partial success.
    Partial,
}

impl CmcStatus {
    /// Convert from CMC status code.
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => Self::Success,
            2 => Self::Failed,
            3 => Self::Pending,
            4 => Self::NoSupport,
            5 => Self::ConfirmRequired,
            6 => Self::PopRequired,
            7 => Self::Partial,
            _ => Self::Failed,
        }
    }

    /// Convert to CMC status code.
    pub fn to_code(self) -> u32 {
        match self {
            Self::Success => 0,
            Self::Failed => 2,
            Self::Pending => 3,
            Self::NoSupport => 4,
            Self::ConfirmRequired => 5,
            Self::PopRequired => 6,
            Self::Partial => 7,
        }
    }
}

/// CMC control attribute types.
pub mod controls {
    use const_oid::ObjectIdentifier;

    /// CMC Status Info V2 (1.3.6.1.5.5.7.7.25)
    pub const CMC_STATUS_INFO_V2: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.25");

    /// Identity Proof V2 (1.3.6.1.5.5.7.7.34)
    pub const IDENTITY_PROOF_V2: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.34");

    /// POP Link Random (1.3.6.1.5.5.7.7.22)
    pub const POP_LINK_RANDOM: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.22");

    /// POP Link Witness V2 (1.3.6.1.5.5.7.7.33)
    pub const POP_LINK_WITNESS_V2: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.33");

    /// Revocation Request (1.3.6.1.5.5.7.7.17)
    pub const REVOCATION_REQUEST: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.17");

    /// Modify Cert Request (1.3.6.1.5.5.7.7.16)
    pub const MODIFY_CERT_REQUEST: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.7.16");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmc_status_codes() {
        assert_eq!(CmcStatus::from_code(0), CmcStatus::Success);
        assert_eq!(CmcStatus::from_code(2), CmcStatus::Failed);
        assert_eq!(CmcStatus::Success.to_code(), 0);
    }

    #[test]
    fn test_cmc_request_creation() {
        let req = CmcRequest::new(vec![1, 2, 3]);
        assert_eq!(req.as_bytes(), &[1, 2, 3]);
    }
}
