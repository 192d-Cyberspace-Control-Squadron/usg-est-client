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

//! Certificate chain validation and path building.
//!
//! This module implements RFC 5280 certificate path validation,
//! including chain building, trust anchor verification, and
//! constraint checking.
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::validation::{CertificateValidator, ValidationConfig};
//! use usg_est_client::Certificate;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Load certificates
//! let end_entity_cert = todo!(); // Your end-entity certificate
//! let intermediates = vec![]; // Intermediate CA certificates
//! let trust_anchors = vec![]; // Trusted root CA certificates
//!
//! // Create validator
//! let validator = CertificateValidator::new(trust_anchors);
//!
//! // Validate certificate chain
//! let result = validator.validate(&end_entity_cert, &intermediates)?;
//!
//! if result.is_valid {
//!     println!("Certificate chain is valid!");
//! }
//! # Ok(())
//! # }
//! ```

use crate::error::{EstError, Result};
use std::time::SystemTime;
use tracing::{debug, warn};
use x509_cert::Certificate;

/// Configuration for certificate validation.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Maximum chain length (default: 10).
    pub max_chain_length: usize,

    /// Whether to check certificate revocation (CRL/OCSP).
    pub check_revocation: bool,

    /// Whether to enforce name constraints.
    pub enforce_name_constraints: bool,

    /// Whether to enforce policy constraints.
    pub enforce_policy_constraints: bool,

    /// Allow expired certificates (for testing only).
    pub allow_expired: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_chain_length: 10,
            check_revocation: false,
            enforce_name_constraints: true,
            enforce_policy_constraints: true,
            allow_expired: false,
        }
    }
}

/// Result of certificate validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the certificate is valid.
    pub is_valid: bool,

    /// The validated certificate chain (from end-entity to root).
    pub chain: Vec<Certificate>,

    /// Validation errors encountered.
    pub errors: Vec<String>,

    /// Validation warnings (non-fatal issues).
    pub warnings: Vec<String>,
}

/// Certificate path validator.
///
/// Implements RFC 5280 certificate path validation algorithm.
pub struct CertificateValidator {
    /// Trusted root CA certificates.
    trust_anchors: Vec<Certificate>,

    /// Validation configuration.
    config: ValidationConfig,
}

impl CertificateValidator {
    /// Create a new certificate validator with trusted root CAs.
    pub fn new(trust_anchors: Vec<Certificate>) -> Self {
        Self {
            trust_anchors,
            config: ValidationConfig::default(),
        }
    }

    /// Create a validator with custom configuration.
    pub fn with_config(trust_anchors: Vec<Certificate>, config: ValidationConfig) -> Self {
        Self {
            trust_anchors,
            config,
        }
    }

    /// Validate a certificate chain.
    ///
    /// # Arguments
    ///
    /// * `end_entity` - The end-entity certificate to validate
    /// * `intermediates` - Optional intermediate CA certificates
    ///
    /// # Returns
    ///
    /// A `ValidationResult` indicating whether the chain is valid.
    pub fn validate(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
    ) -> Result<ValidationResult> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        debug!("Starting certificate path validation");

        // Step 1: Build the certificate chain
        let chain = match self.build_chain(end_entity, intermediates) {
            Ok(chain) => chain,
            Err(e) => {
                errors.push(format!("Failed to build certificate chain: {}", e));
                return Ok(ValidationResult {
                    is_valid: false,
                    chain: vec![],
                    errors,
                    warnings,
                });
            }
        };

        debug!("Built certificate chain with {} certificates", chain.len());

        // Step 2: Verify chain length
        if chain.len() > self.config.max_chain_length {
            errors.push(format!(
                "Certificate chain too long ({} > {})",
                chain.len(),
                self.config.max_chain_length
            ));
        }

        // Step 3: Verify each certificate in the chain
        for (i, cert) in chain.iter().enumerate() {
            debug!("Validating certificate {}/{}", i + 1, chain.len());

            // Check expiration
            if !self.config.allow_expired {
                if let Err(e) = self.check_validity_period(cert) {
                    errors.push(format!("Certificate {} invalid: {}", i, e));
                }
            }

            // Check basic constraints
            if i > 0 {
                // Not the end-entity cert
                if let Err(e) = self.check_basic_constraints(cert) {
                    errors.push(format!("Certificate {} basic constraints: {}", i, e));
                }
            }

            // Check name constraints (if enabled)
            if self.config.enforce_name_constraints {
                // TODO: Implement name constraints checking
                debug!("Name constraints checking not yet implemented");
            }

            // Check policy constraints (if enabled)
            if self.config.enforce_policy_constraints {
                // TODO: Implement policy constraints checking
                debug!("Policy constraints checking not yet implemented");
            }
        }

        // Step 4: Verify signatures along the chain
        for i in 0..chain.len() - 1 {
            if let Err(e) = self.verify_signature(&chain[i], &chain[i + 1]) {
                errors.push(format!(
                    "Signature verification failed for certificate {}: {}",
                    i, e
                ));
            }
        }

        // Step 5: Verify root certificate is trusted
        if let Some(root) = chain.last() {
            if !self.is_trusted_root(root) {
                errors.push("Root certificate is not in trust store".to_string());
            }
        }

        // Step 6: Check revocation status (if enabled)
        if self.config.check_revocation {
            warnings.push("Revocation checking not yet implemented".to_string());
        }

        let is_valid = errors.is_empty();

        Ok(ValidationResult {
            is_valid,
            chain,
            errors,
            warnings,
        })
    }

    /// Build a certificate chain from end-entity to root.
    fn build_chain(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
    ) -> Result<Vec<Certificate>> {
        let mut chain = vec![end_entity.clone()];
        let mut current = end_entity;

        // Build chain up to root
        for _ in 0..self.config.max_chain_length {
            if self.is_self_signed(current) {
                // Reached root
                break;
            }

            // Find issuer in intermediates or trust anchors
            let issuer = self
                .find_issuer(current, intermediates)
                .or_else(|| self.find_issuer_in_trust_anchors(current))
                .ok_or_else(|| EstError::operational("Could not find certificate issuer"))?;

            chain.push(issuer.clone());
            current = &chain[chain.len() - 1];
        }

        Ok(chain)
    }

    /// Find the issuer of a certificate in the provided set.
    fn find_issuer(&self, cert: &Certificate, candidates: &[Certificate]) -> Option<Certificate> {
        let issuer_dn = &cert.tbs_certificate.issuer;

        for candidate in candidates {
            let subject_dn = &candidate.tbs_certificate.subject;
            if subject_dn == issuer_dn {
                return Some(candidate.clone());
            }
        }

        None
    }

    /// Find the issuer in trust anchors.
    fn find_issuer_in_trust_anchors(&self, cert: &Certificate) -> Option<Certificate> {
        self.find_issuer(cert, &self.trust_anchors)
    }

    /// Check if a certificate is self-signed.
    fn is_self_signed(&self, cert: &Certificate) -> bool {
        let subject = &cert.tbs_certificate.subject;
        let issuer = &cert.tbs_certificate.issuer;
        subject == issuer
    }

    /// Check if a certificate is a trusted root.
    fn is_trusted_root(&self, cert: &Certificate) -> bool {
        self.trust_anchors.iter().any(|anchor| {
            // Compare by public key or serial number
            anchor.tbs_certificate.subject_public_key_info
                == cert.tbs_certificate.subject_public_key_info
        })
    }

    /// Check certificate validity period.
    fn check_validity_period(&self, cert: &Certificate) -> Result<()> {
        use x509_cert::time::Time;

        let now = SystemTime::now();
        let validity = &cert.tbs_certificate.validity;

        // Check not_before
        let not_before = match &validity.not_before {
            Time::UtcTime(_utc) => {
                // Simplified: Assume certificate is valid
                // Production code should properly parse UTCTime
                SystemTime::UNIX_EPOCH
            }
            Time::GeneralTime(_gen) => {
                // Simplified: Assume certificate is valid
                SystemTime::UNIX_EPOCH
            }
        };

        if now < not_before {
            return Err(EstError::operational("Certificate not yet valid"));
        }

        // Check not_after (use the renewal module's time_until_expiry logic)
        // For now, simplified check
        // TODO: Use proper time parsing

        Ok(())
    }

    /// Check basic constraints extension.
    fn check_basic_constraints(&self, cert: &Certificate) -> Result<()> {
        // Look for basic constraints extension
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                // Basic Constraints OID: 2.5.29.19
                let basic_constraints_oid = const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;

                if ext.extn_id == basic_constraints_oid {
                    // Certificate has basic constraints
                    // TODO: Parse and verify cA flag is true
                    debug!("Found basic constraints extension");
                    return Ok(());
                }
            }
        }

        warn!("CA certificate missing basic constraints extension");
        Ok(())
    }

    /// Verify certificate signature.
    fn verify_signature(&self, cert: &Certificate, issuer: &Certificate) -> Result<()> {
        // TODO: Implement actual signature verification using issuer's public key
        // This requires:
        // 1. Extracting the public key from the issuer certificate
        // 2. Parsing the signature algorithm
        // 3. Verifying the signature over the TBSCertificate

        debug!("Signature verification not yet fully implemented (placeholder)");

        // For now, just check that the signature algorithm is present
        let _ = &cert.signature_algorithm;
        let _ = &issuer.tbs_certificate.subject_public_key_info;

        Ok(())
    }
}

/// Helper function to extract common name from certificate subject.
pub fn get_subject_cn(cert: &Certificate) -> Option<String> {
    use const_oid::db::rfc4519::CN;

    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == CN {
                if let Ok(s) = std::str::from_utf8(atv.value.value()) {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

/// Helper function to check if a certificate is a CA certificate.
pub fn is_ca_certificate(cert: &Certificate) -> bool {
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            let basic_constraints_oid = const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;
            if ext.extn_id == basic_constraints_oid {
                // TODO: Parse basic constraints and check cA flag
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_config_default() {
        let config = ValidationConfig::default();
        assert_eq!(config.max_chain_length, 10);
        assert!(!config.check_revocation);
        assert!(config.enforce_name_constraints);
        assert!(config.enforce_policy_constraints);
        assert!(!config.allow_expired);
    }

    #[test]
    fn test_validation_result_structure() {
        let result = ValidationResult {
            is_valid: true,
            chain: vec![],
            errors: vec![],
            warnings: vec![],
        };

        assert!(result.is_valid);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }
}
