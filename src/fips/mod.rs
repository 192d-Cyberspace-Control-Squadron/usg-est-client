// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! FIPS 140-2 Cryptographic Compliance
//!
//! This module provides FIPS 140-2 validated cryptography support for DoD deployments.
//!
//! # Overview
//!
//! The Federal Information Processing Standard (FIPS) 140-2 is a U.S. government computer
//! security standard that specifies the security requirements for cryptographic modules.
//! For deployment on DoD networks, systems must use FIPS 140-2 validated cryptographic
//! modules.
//!
//! ## FIPS Mode
//!
//! When FIPS mode is enabled, this library:
//!
//! - Uses OpenSSL with FIPS module instead of rustls
//! - Enforces FIPS-approved algorithms only
//! - Blocks non-FIPS algorithms (3DES, MD5, SHA-1, RC4, etc.)
//! - Validates minimum key sizes (RSA 2048+, ECC P-256+)
//! - Performs FIPS self-tests on startup
//!
//! ## Requirements
//!
//! FIPS mode requires:
//!
//! - OpenSSL 3.0 or later with FIPS module installed
//! - FIPS module configuration file (`fipsmodule.cnf`)
//! - System-wide OpenSSL configuration enabling FIPS
//!
//! ## Example
//!
//! ```no_run
//! use usg_est_client::{EstClient, EstClientConfig};
//! use usg_est_client::fips::FipsConfig;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create FIPS-compliant configuration
//! let fips_config = FipsConfig::builder()
//!     .enforce_fips_mode(true)
//!     .min_rsa_key_size(2048)
//!     .min_ecc_key_size(256)
//!     .build()?;
//!
//! let config = EstClientConfig::builder()
//!     .server_url("https://est.example.mil")?
//!     .fips_config(fips_config)
//!     .build()?;
//!
//! let client = EstClient::new(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## FIPS Caveat Certificates
//!
//! The OpenSSL FIPS module is validated under CMVP certificate #4282 (OpenSSL 3.0.0).
//! Ensure your deployment uses a FIPS-validated version of OpenSSL.
//!
//! See: <https://csrc.nist.gov/projects/cryptographic-module-validation-program>
//!
//! ## References
//!
//! - [FIPS 140-2 Standard](https://csrc.nist.gov/pubs/fips/140-2/upd2/final)
//! - [OpenSSL FIPS Module](https://www.openssl.org/docs/fips.html)
//! - [NIST CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program)

pub mod algorithms;

use crate::error::{EstError, Result};
use std::fmt;

/// FIPS 140-2 configuration for cryptographic operations
///
/// Controls FIPS mode enforcement and algorithm restrictions.
#[derive(Debug, Clone)]
pub struct FipsConfig {
    /// Require FIPS mode to be enabled
    pub enforce_fips_mode: bool,

    /// Minimum RSA key size in bits (default: 2048)
    pub min_rsa_key_size: u32,

    /// Minimum ECC key size in bits (default: 256 for P-256)
    pub min_ecc_key_size: u32,

    /// Block non-FIPS algorithms
    pub block_non_fips_algorithms: bool,

    /// Require TLS 1.2 minimum (FIPS requirement)
    pub require_tls_12_minimum: bool,

    /// Path to OpenSSL FIPS configuration file (optional override)
    pub fips_config_path: Option<String>,
}

impl Default for FipsConfig {
    fn default() -> Self {
        Self {
            enforce_fips_mode: false,
            min_rsa_key_size: 2048,
            min_ecc_key_size: 256,
            block_non_fips_algorithms: true,
            require_tls_12_minimum: true,
            fips_config_path: None,
        }
    }
}

impl FipsConfig {
    /// Create a new FIPS configuration builder
    pub fn builder() -> FipsConfigBuilder {
        FipsConfigBuilder::default()
    }

    /// Validate that FIPS mode is properly configured
    ///
    /// This checks that:
    /// - OpenSSL FIPS module is available
    /// - FIPS mode is enabled if required
    /// - Self-tests have passed
    pub fn validate(&self) -> Result<()> {
        #[cfg(feature = "fips")]
        {
            // Validate minimum key sizes (always required for FIPS compliance)
            if self.min_rsa_key_size < 2048 {
                return Err(EstError::FipsInvalidConfig(
                    "FIPS requires RSA key size >= 2048 bits".to_string(),
                ));
            }

            if self.min_ecc_key_size < 256 {
                return Err(EstError::FipsInvalidConfig(
                    "FIPS requires ECC key size >= 256 bits (P-256)".to_string(),
                ));
            }

            // Only check FIPS availability and mode when enforcement is required
            if self.enforce_fips_mode {
                // Check if OpenSSL FIPS module is available
                if !is_fips_capable()? {
                    return Err(EstError::FipsNotAvailable(
                        "OpenSSL FIPS module is not available".to_string(),
                    ));
                }

                // Check if FIPS mode is enabled
                let fips_enabled = is_fips_enabled()?;

                if !fips_enabled {
                    return Err(EstError::FipsNotEnabled(
                        "FIPS mode is required but not enabled".to_string(),
                    ));
                }
            }

            Ok(())
        }

        #[cfg(not(feature = "fips"))]
        {
            if self.enforce_fips_mode {
                Err(EstError::FipsNotAvailable(
                    "FIPS mode requires 'fips' feature flag".to_string(),
                ))
            } else {
                Ok(())
            }
        }
    }
}

/// Builder for FIPS configuration
#[derive(Debug, Default)]
pub struct FipsConfigBuilder {
    enforce_fips_mode: bool,
    min_rsa_key_size: u32,
    min_ecc_key_size: u32,
    block_non_fips_algorithms: bool,
    require_tls_12_minimum: bool,
    fips_config_path: Option<String>,
}

impl FipsConfigBuilder {
    /// Enforce FIPS mode (default: false)
    ///
    /// When enabled, operations will fail if FIPS mode is not active.
    pub fn enforce_fips_mode(mut self, enforce: bool) -> Self {
        self.enforce_fips_mode = enforce;
        self
    }

    /// Set minimum RSA key size in bits (default: 2048)
    ///
    /// FIPS 140-2 requires RSA keys to be at least 2048 bits.
    pub fn min_rsa_key_size(mut self, bits: u32) -> Self {
        self.min_rsa_key_size = bits;
        self
    }

    /// Set minimum ECC key size in bits (default: 256)
    ///
    /// FIPS 140-2 requires ECC keys to be at least 256 bits (P-256 curve).
    pub fn min_ecc_key_size(mut self, bits: u32) -> Self {
        self.min_ecc_key_size = bits;
        self
    }

    /// Block non-FIPS algorithms (default: true)
    ///
    /// When enabled, attempts to use non-FIPS algorithms will fail.
    pub fn block_non_fips_algorithms(mut self, block: bool) -> Self {
        self.block_non_fips_algorithms = block;
        self
    }

    /// Require TLS 1.2 minimum (default: true)
    ///
    /// FIPS 140-2 requires TLS 1.2 or higher.
    pub fn require_tls_12_minimum(mut self, require: bool) -> Self {
        self.require_tls_12_minimum = require;
        self
    }

    /// Set path to OpenSSL FIPS configuration file
    ///
    /// If not specified, OpenSSL will use system-wide configuration.
    pub fn fips_config_path(mut self, path: impl Into<String>) -> Self {
        self.fips_config_path = Some(path.into());
        self
    }

    /// Build the FIPS configuration
    pub fn build(self) -> Result<FipsConfig> {
        let config = FipsConfig {
            enforce_fips_mode: self.enforce_fips_mode,
            min_rsa_key_size: if self.min_rsa_key_size == 0 {
                2048
            } else {
                self.min_rsa_key_size
            },
            min_ecc_key_size: if self.min_ecc_key_size == 0 {
                256
            } else {
                self.min_ecc_key_size
            },
            block_non_fips_algorithms: self.block_non_fips_algorithms,
            require_tls_12_minimum: self.require_tls_12_minimum,
            fips_config_path: self.fips_config_path,
        };

        // Validate configuration
        config.validate()?;

        Ok(config)
    }
}

impl fmt::Display for FipsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FipsConfig {{ enforce: {}, min_rsa: {}, min_ecc: {}, block_non_fips: {} }}",
            self.enforce_fips_mode,
            self.min_rsa_key_size,
            self.min_ecc_key_size,
            self.block_non_fips_algorithms
        )
    }
}

/// Check if OpenSSL FIPS module is available
#[cfg(feature = "fips")]
fn is_fips_capable() -> Result<bool> {
    use openssl::version;

    // OpenSSL 3.0+ is required for FIPS module support
    let version_text = version::version();
    tracing::debug!("OpenSSL version: {}", version_text);

    // Check if FIPS provider is available
    match openssl::provider::Provider::try_load(None, "fips", true) {
        Ok(_) => Ok(true),
        Err(e) => {
            tracing::warn!("FIPS provider not available: {}", e);
            Ok(false)
        }
    }
}

/// Check if FIPS mode is currently enabled
#[cfg(feature = "fips")]
fn is_fips_enabled() -> Result<bool> {
    // In OpenSSL 3.0+, FIPS mode is controlled by the configuration file
    // and the FIPS provider being loaded
    #[cfg(ossl300)]
    {
        match openssl::fips::enabled() {
            true => {
                tracing::info!("FIPS mode is enabled");
                Ok(true)
            }
            false => {
                tracing::warn!("FIPS mode is NOT enabled");
                Ok(false)
            }
        }
    }

    #[cfg(not(ossl300))]
    {
        // For OpenSSL < 3.0, FIPS mode detection is not available
        tracing::warn!("FIPS mode detection requires OpenSSL 3.0+");
        Ok(false)
    }
}

/// Enable FIPS mode (requires appropriate OpenSSL configuration)
///
/// # Errors
///
/// Returns an error if FIPS mode cannot be enabled.
///
/// # Note
///
/// In OpenSSL 3.0+, FIPS mode is typically enabled via configuration file
/// rather than programmatically. This function validates that FIPS mode
/// is properly configured.
#[cfg(feature = "fips")]
pub fn enable_fips_mode() -> Result<()> {
    #[cfg(ossl300)]
    {
        if openssl::fips::enabled() {
            tracing::info!("FIPS mode already enabled");
            return Ok(());
        }

        // In OpenSSL 3.0+, we need to ensure the FIPS provider is loaded
        // This is typically done via openssl.cnf configuration
        match openssl::provider::Provider::load(None, "fips") {
            Ok(_) => {
                if openssl::fips::enabled() {
                    tracing::info!("FIPS mode successfully enabled");
                    Ok(())
                } else {
                    Err(EstError::FipsNotEnabled(
                        "FIPS provider loaded but mode not enabled. Check openssl.cnf configuration."
                            .to_string(),
                    ))
                }
            }
            Err(e) => Err(EstError::FipsNotAvailable(format!(
                "Failed to load FIPS provider: {}",
                e
            ))),
        }
    }

    #[cfg(not(ossl300))]
    {
        Err(EstError::FipsNotAvailable(
            "FIPS mode requires OpenSSL 3.0+".to_string(),
        ))
    }
}

/// Get FIPS module information
#[cfg(feature = "fips")]
pub fn fips_module_info() -> FipsModuleInfo {
    #[cfg(ossl300)]
    let fips_enabled = openssl::fips::enabled();

    #[cfg(not(ossl300))]
    let fips_enabled = false;

    FipsModuleInfo {
        openssl_version: openssl::version::version().to_string(),
        fips_enabled,
        fips_capable: is_fips_capable().unwrap_or(false),
    }
}

/// FIPS module information
#[derive(Debug, Clone)]
pub struct FipsModuleInfo {
    /// OpenSSL version string
    pub openssl_version: String,
    /// Whether FIPS mode is currently enabled
    pub fips_enabled: bool,
    /// Whether FIPS module is available
    pub fips_capable: bool,
}

impl fmt::Display for FipsModuleInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "OpenSSL Version: {}", self.openssl_version)?;
        writeln!(f, "FIPS Capable: {}", self.fips_capable)?;
        writeln!(f, "FIPS Enabled: {}", self.fips_enabled)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_config_builder() {
        let config = FipsConfig::builder()
            .enforce_fips_mode(false)
            .min_rsa_key_size(2048)
            .min_ecc_key_size(256)
            .build();

        #[cfg(feature = "fips")]
        {
            // With FIPS feature enabled, building should succeed
            assert!(config.is_ok());
            let config = config.unwrap();
            assert_eq!(config.min_rsa_key_size, 2048);
            assert_eq!(config.min_ecc_key_size, 256);
        }

        #[cfg(not(feature = "fips"))]
        {
            // Without FIPS feature, should succeed if not enforcing
            assert!(config.is_ok());
        }
    }

    #[test]
    fn test_fips_config_enforced_without_feature() {
        let config = FipsConfig::builder().enforce_fips_mode(true).build();

        #[cfg(not(feature = "fips"))]
        {
            // Should fail when enforcing FIPS without feature
            assert!(config.is_err());
        }
    }

    #[test]
    fn test_fips_config_minimum_key_sizes() {
        // RSA key size below 2048 should fail
        let config = FipsConfig::builder()
            .enforce_fips_mode(false)
            .min_rsa_key_size(1024)
            .build();

        assert!(config.is_err());

        // ECC key size below 256 should fail
        let config = FipsConfig::builder()
            .enforce_fips_mode(false)
            .min_ecc_key_size(192)
            .build();

        assert!(config.is_err());
    }

    #[test]
    fn test_fips_config_display() {
        let config = FipsConfig::default();
        let display = format!("{}", config);
        assert!(display.contains("enforce: false"));
        assert!(display.contains("min_rsa: 2048"));
        assert!(display.contains("min_ecc: 256"));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn test_fips_module_info() {
        let info = fips_module_info();
        assert!(!info.openssl_version.is_empty());
        println!("{}", info);
    }
}
