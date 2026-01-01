//! Certificate revocation checking (CRL and OCSP).
//!
//! This module provides support for checking certificate revocation status
//! using Certificate Revocation Lists (CRL) and Online Certificate Status
//! Protocol (OCSP).
//!
//! # Example
//!
//! ```no_run
//! use usg_est_client::revocation::{RevocationChecker, RevocationConfig};
//! use usg_est_client::Certificate;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create revocation checker
//! let config = RevocationConfig::builder()
//!     .enable_crl(true)
//!     .enable_ocsp(true)
//!     .crl_cache_duration(std::time::Duration::from_secs(3600))
//!     .build();
//!
//! let checker = RevocationChecker::new(config);
//!
//! // Check certificate revocation status
//! let cert = todo!(); // Your certificate
//! let issuer = todo!(); // Issuer certificate
//! let status = checker.check_revocation(&cert, &issuer).await?;
//!
//! if status.is_revoked() {
//!     println!("Certificate has been revoked!");
//! }
//! # Ok(())
//! # }
//! ```

use crate::error::{EstError, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use x509_cert::Certificate;

/// Configuration for revocation checking.
#[derive(Debug, Clone)]
pub struct RevocationConfig {
    /// Enable CRL checking.
    pub enable_crl: bool,

    /// Enable OCSP checking.
    pub enable_ocsp: bool,

    /// How long to cache CRL data.
    pub crl_cache_duration: Duration,

    /// Maximum size of CRL cache (number of entries).
    pub crl_cache_max_entries: usize,

    /// Timeout for OCSP requests.
    pub ocsp_timeout: Duration,

    /// Whether to fail if revocation status cannot be determined.
    pub fail_on_unknown: bool,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        Self {
            enable_crl: true,
            enable_ocsp: true,
            crl_cache_duration: Duration::from_secs(3600), // 1 hour
            crl_cache_max_entries: 100,
            ocsp_timeout: Duration::from_secs(10),
            fail_on_unknown: false,
        }
    }
}

impl RevocationConfig {
    /// Create a new configuration builder.
    pub fn builder() -> RevocationConfigBuilder {
        RevocationConfigBuilder::default()
    }
}

/// Builder for `RevocationConfig`.
#[derive(Default)]
pub struct RevocationConfigBuilder {
    enable_crl: Option<bool>,
    enable_ocsp: Option<bool>,
    crl_cache_duration: Option<Duration>,
    crl_cache_max_entries: Option<usize>,
    ocsp_timeout: Option<Duration>,
    fail_on_unknown: Option<bool>,
}

impl RevocationConfigBuilder {
    /// Enable or disable CRL checking.
    pub fn enable_crl(mut self, enable: bool) -> Self {
        self.enable_crl = Some(enable);
        self
    }

    /// Enable or disable OCSP checking.
    pub fn enable_ocsp(mut self, enable: bool) -> Self {
        self.enable_ocsp = Some(enable);
        self
    }

    /// Set CRL cache duration.
    pub fn crl_cache_duration(mut self, duration: Duration) -> Self {
        self.crl_cache_duration = Some(duration);
        self
    }

    /// Set maximum CRL cache entries.
    pub fn crl_cache_max_entries(mut self, max: usize) -> Self {
        self.crl_cache_max_entries = Some(max);
        self
    }

    /// Set OCSP request timeout.
    pub fn ocsp_timeout(mut self, timeout: Duration) -> Self {
        self.ocsp_timeout = Some(timeout);
        self
    }

    /// Set whether to fail on unknown revocation status.
    pub fn fail_on_unknown(mut self, fail: bool) -> Self {
        self.fail_on_unknown = Some(fail);
        self
    }

    /// Build the configuration.
    pub fn build(self) -> RevocationConfig {
        let default = RevocationConfig::default();
        RevocationConfig {
            enable_crl: self.enable_crl.unwrap_or(default.enable_crl),
            enable_ocsp: self.enable_ocsp.unwrap_or(default.enable_ocsp),
            crl_cache_duration: self.crl_cache_duration.unwrap_or(default.crl_cache_duration),
            crl_cache_max_entries: self
                .crl_cache_max_entries
                .unwrap_or(default.crl_cache_max_entries),
            ocsp_timeout: self.ocsp_timeout.unwrap_or(default.ocsp_timeout),
            fail_on_unknown: self.fail_on_unknown.unwrap_or(default.fail_on_unknown),
        }
    }
}

/// Certificate revocation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    /// Certificate is valid (not revoked).
    Valid,

    /// Certificate has been revoked.
    Revoked,

    /// Revocation status is unknown.
    Unknown,
}

impl RevocationStatus {
    /// Check if the certificate is revoked.
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked)
    }

    /// Check if the certificate is valid.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Check if the status is unknown.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// Detailed revocation check result.
#[derive(Debug, Clone)]
pub struct RevocationCheckResult {
    /// Overall revocation status.
    pub status: RevocationStatus,

    /// Whether CRL was checked.
    pub crl_checked: bool,

    /// Whether OCSP was checked.
    pub ocsp_checked: bool,

    /// CRL revocation status (if checked).
    pub crl_status: Option<RevocationStatus>,

    /// OCSP revocation status (if checked).
    pub ocsp_status: Option<RevocationStatus>,

    /// Any errors encountered during checking.
    pub errors: Vec<String>,
}

impl RevocationCheckResult {
    /// Check if the certificate is revoked.
    pub fn is_revoked(&self) -> bool {
        self.status.is_revoked()
    }
}

/// CRL cache entry.
#[derive(Debug, Clone)]
struct CrlCacheEntry {
    /// The CRL data (placeholder - would be actual CRL structure).
    #[allow(dead_code)]
    data: Vec<u8>,

    /// When this entry was cached.
    cached_at: SystemTime,

    /// When this CRL expires.
    #[allow(dead_code)]
    next_update: Option<SystemTime>,
}

/// Certificate revocation checker.
pub struct RevocationChecker {
    config: RevocationConfig,
    crl_cache: Arc<RwLock<HashMap<String, CrlCacheEntry>>>,
}

impl RevocationChecker {
    /// Create a new revocation checker with the given configuration.
    pub fn new(config: RevocationConfig) -> Self {
        Self {
            config,
            crl_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check the revocation status of a certificate.
    ///
    /// # Arguments
    ///
    /// * `cert` - The certificate to check
    /// * `issuer` - The issuer certificate (needed for CRL/OCSP)
    ///
    /// # Returns
    ///
    /// A `RevocationCheckResult` with the revocation status and details.
    pub async fn check_revocation(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<RevocationCheckResult> {
        let mut result = RevocationCheckResult {
            status: RevocationStatus::Unknown,
            crl_checked: false,
            ocsp_checked: false,
            crl_status: None,
            ocsp_status: None,
            errors: Vec::new(),
        };

        debug!("Checking revocation status for certificate");

        // Check CRL if enabled
        if self.config.enable_crl {
            match self.check_crl(cert, issuer).await {
                Ok(status) => {
                    result.crl_checked = true;
                    result.crl_status = Some(status);
                    info!("CRL check result: {:?}", status);

                    if status.is_revoked() {
                        result.status = RevocationStatus::Revoked;
                        return Ok(result);
                    } else if status.is_valid() {
                        result.status = RevocationStatus::Valid;
                    }
                }
                Err(e) => {
                    warn!("CRL check failed: {}", e);
                    result.errors.push(format!("CRL check failed: {}", e));
                }
            }
        }

        // Check OCSP if enabled and CRL didn't give a definitive answer
        if self.config.enable_ocsp && !result.status.is_revoked() {
            match self.check_ocsp(cert, issuer).await {
                Ok(status) => {
                    result.ocsp_checked = true;
                    result.ocsp_status = Some(status);
                    info!("OCSP check result: {:?}", status);

                    if status.is_revoked() {
                        result.status = RevocationStatus::Revoked;
                        return Ok(result);
                    } else if status.is_valid() {
                        result.status = RevocationStatus::Valid;
                    }
                }
                Err(e) => {
                    warn!("OCSP check failed: {}", e);
                    result.errors.push(format!("OCSP check failed: {}", e));
                }
            }
        }

        // Handle unknown status
        if result.status.is_unknown() && self.config.fail_on_unknown {
            return Err(EstError::operational(
                "Certificate revocation status could not be determined",
            ));
        }

        Ok(result)
    }

    /// Check revocation status using CRL.
    async fn check_crl(
        &self,
        cert: &Certificate,
        _issuer: &Certificate,
    ) -> Result<RevocationStatus> {
        debug!("Performing CRL check");

        // Extract CRL distribution points from certificate
        let crl_urls = self.extract_crl_urls(cert)?;

        if crl_urls.is_empty() {
            debug!("No CRL distribution points found in certificate");
            return Ok(RevocationStatus::Unknown);
        }

        for url in crl_urls {
            // Check cache first
            if let Some(status) = self.check_crl_cache(&url).await? {
                return Ok(status);
            }

            // Download and check CRL
            // TODO: Implement actual CRL download and parsing
            debug!("Would download CRL from: {}", url);
        }

        Ok(RevocationStatus::Unknown)
    }

    /// Extract CRL distribution point URLs from a certificate.
    fn extract_crl_urls(&self, cert: &Certificate) -> Result<Vec<String>> {
        let urls = Vec::new();

        // Look for CRL Distribution Points extension
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                // CRL Distribution Points OID: 2.5.29.31
                let crl_dist_points_oid = const_oid::db::rfc5280::ID_CE_CRL_DISTRIBUTION_POINTS;

                if ext.extn_id == crl_dist_points_oid {
                    // TODO: Parse CRL Distribution Points extension
                    // For now, return empty list
                    debug!("Found CRL Distribution Points extension (parsing not implemented)");
                }
            }
        }

        Ok(urls)
    }

    /// Check CRL cache for revocation status.
    async fn check_crl_cache(&self, url: &str) -> Result<Option<RevocationStatus>> {
        let cache = self.crl_cache.read().await;

        if let Some(entry) = cache.get(url) {
            let age = SystemTime::now()
                .duration_since(entry.cached_at)
                .unwrap_or(Duration::from_secs(0));

            if age < self.config.crl_cache_duration {
                debug!("Using cached CRL for {}", url);
                // TODO: Check certificate against cached CRL
                return Ok(Some(RevocationStatus::Unknown));
            } else {
                debug!("Cached CRL expired for {}", url);
            }
        }

        Ok(None)
    }

    /// Check revocation status using OCSP.
    async fn check_ocsp(
        &self,
        cert: &Certificate,
        _issuer: &Certificate,
    ) -> Result<RevocationStatus> {
        debug!("Performing OCSP check");

        // Extract OCSP responder URL from certificate
        let ocsp_url = self.extract_ocsp_url(cert)?;

        if let Some(url) = ocsp_url {
            debug!("Would send OCSP request to: {}", url);
            // TODO: Implement actual OCSP request/response
            Ok(RevocationStatus::Unknown)
        } else {
            debug!("No OCSP responder URL found in certificate");
            Ok(RevocationStatus::Unknown)
        }
    }

    /// Extract OCSP responder URL from certificate.
    fn extract_ocsp_url(&self, cert: &Certificate) -> Result<Option<String>> {
        // Look for Authority Information Access extension
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                // Authority Information Access OID: 1.3.6.1.5.5.7.1.1
                let aia_oid = const_oid::db::rfc5280::ID_PE_AUTHORITY_INFO_ACCESS;

                if ext.extn_id == aia_oid {
                    // TODO: Parse AIA extension and extract OCSP URL
                    debug!("Found Authority Information Access extension (parsing not implemented)");
                }
            }
        }

        Ok(None)
    }

    /// Clear the CRL cache.
    pub async fn clear_cache(&self) {
        let mut cache = self.crl_cache.write().await;
        cache.clear();
        info!("CRL cache cleared");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_config_builder() {
        let config = RevocationConfig::builder()
            .enable_crl(true)
            .enable_ocsp(false)
            .crl_cache_duration(Duration::from_secs(7200))
            .fail_on_unknown(true)
            .build();

        assert!(config.enable_crl);
        assert!(!config.enable_ocsp);
        assert_eq!(config.crl_cache_duration, Duration::from_secs(7200));
        assert!(config.fail_on_unknown);
    }

    #[test]
    fn test_revocation_status() {
        assert!(RevocationStatus::Revoked.is_revoked());
        assert!(!RevocationStatus::Valid.is_revoked());
        assert!(RevocationStatus::Valid.is_valid());
        assert!(RevocationStatus::Unknown.is_unknown());
    }

    #[test]
    fn test_default_config() {
        let config = RevocationConfig::default();
        assert!(config.enable_crl);
        assert!(config.enable_ocsp);
        assert!(!config.fail_on_unknown);
    }
}
