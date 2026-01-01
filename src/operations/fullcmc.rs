//! Full CMC operation (POST /fullcmc).
//!
//! This module provides utilities for the Full CMC operation
//! defined in RFC 7030 Section 4.3.
//!
//! Full CMC allows for complex PKI operations that are not possible
//! with the simple enrollment endpoints, such as:
//! - Certificate revocation requests
//! - Key update requests
//! - Certificate status queries

use crate::error::{EstError, Result};
use crate::types::{CmcRequest, CmcResponse, CmcStatus};

/// Build a simple CMC certification request.
///
/// This wraps a PKCS#10 CSR in a CMC PKIData structure.
pub fn build_cmc_certification_request(_csr_der: &[u8]) -> Result<CmcRequest> {
    // Full implementation would:
    // 1. Create a TaggedRequest containing the CSR
    // 2. Wrap in PKIData with appropriate control attributes
    // 3. Optionally sign with CMS SignedData

    Err(EstError::not_supported(
        "CMC request building not yet implemented",
    ))
}

/// Build a CMC key update request.
///
/// Used for updating the key pair associated with an existing certificate.
pub fn build_key_update_request(
    _old_cert: &x509_cert::Certificate,
    _new_csr_der: &[u8],
) -> Result<CmcRequest> {
    Err(EstError::not_supported(
        "CMC key update request not yet implemented",
    ))
}

/// Build a CMC revocation request.
///
/// Used for requesting revocation of a certificate.
pub fn build_revocation_request(
    _cert: &x509_cert::Certificate,
    _reason: RevocationReason,
) -> Result<CmcRequest> {
    Err(EstError::not_supported(
        "CMC revocation request not yet implemented",
    ))
}

/// Parse CMC status from response.
pub fn parse_cmc_status(response: &CmcResponse) -> CmcStatus {
    response.status
}

/// Check if a CMC response indicates success.
pub fn is_cmc_success(response: &CmcResponse) -> bool {
    response.is_success()
}

/// Certificate revocation reasons per RFC 5280.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    /// Unspecified reason.
    Unspecified = 0,
    /// Key has been compromised.
    KeyCompromise = 1,
    /// CA has been compromised.
    CaCompromise = 2,
    /// Affiliation has changed.
    AffiliationChanged = 3,
    /// Certificate has been superseded.
    Superseded = 4,
    /// Certificate is no longer needed.
    CessationOfOperation = 5,
    /// Certificate is on hold.
    CertificateHold = 6,
    /// Removed from CRL (no longer revoked).
    RemoveFromCrl = 8,
    /// Privilege has been withdrawn.
    PrivilegeWithdrawn = 9,
    /// AA has been compromised.
    AaCompromise = 10,
}

impl RevocationReason {
    /// Convert from RFC 5280 reason code.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Unspecified),
            1 => Some(Self::KeyCompromise),
            2 => Some(Self::CaCompromise),
            3 => Some(Self::AffiliationChanged),
            4 => Some(Self::Superseded),
            5 => Some(Self::CessationOfOperation),
            6 => Some(Self::CertificateHold),
            8 => Some(Self::RemoveFromCrl),
            9 => Some(Self::PrivilegeWithdrawn),
            10 => Some(Self::AaCompromise),
            _ => None,
        }
    }

    /// Convert to RFC 5280 reason code.
    pub fn to_code(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_reason_codes() {
        assert_eq!(RevocationReason::from_code(1), Some(RevocationReason::KeyCompromise));
        assert_eq!(RevocationReason::KeyCompromise.to_code(), 1);
        assert_eq!(RevocationReason::from_code(7), None); // 7 is not used
    }

    #[test]
    fn test_cmc_status() {
        let response = CmcResponse {
            data: vec![],
            certificates: vec![],
            status: CmcStatus::Success,
        };
        assert!(is_cmc_success(&response));
    }
}
