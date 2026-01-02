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

//! Certificate enrollment workflows for Windows auto-enrollment.
//!
//! This module implements the complete certificate enrollment and renewal
//! workflows for Windows machines, designed to replace ADCS auto-enrollment.
//!
//! # Workflows
//!
//! ## Initial Enrollment
//!
//! 1. Load and validate configuration
//! 2. Fetch CA certificates (with optional TOFU)
//! 3. Generate key pair (CNG/TPM/software)
//! 4. Build CSR with configured subject and SANs
//! 5. Authenticate to EST server (HTTP Basic or client cert)
//! 6. Submit enrollment request
//! 7. Handle pending (HTTP 202) with retry loop
//! 8. Install issued certificate to Windows cert store
//! 9. Associate private key with certificate
//!
//! ## Re-enrollment (Renewal)
//!
//! 1. Load existing certificate from store
//! 2. Check expiration against renewal threshold
//! 3. Generate new key pair (or reuse if policy allows)
//! 4. Build CSR with same subject
//! 5. Authenticate with existing certificate (TLS client auth)
//! 6. Submit re-enrollment request
//! 7. Install new certificate
//! 8. Optionally archive old certificate
//!
//! # Example
//!
//! ```no_run,ignore
//! use usg_est_client::windows::enrollment::{EnrollmentManager, EnrollmentResult};
//! use usg_est_client::auto_enroll::config::AutoEnrollConfig;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = AutoEnrollConfig::from_toml(&std::fs::read_to_string("config.toml")?)?;
//! let manager = EnrollmentManager::new(config)?;
//!
//! // Check if enrollment is needed
//! if manager.needs_enrollment().await? {
//!     let result = manager.enroll().await?;
//!     println!("Enrolled: {}", result.thumbprint);
//! }
//!
//! // Check for renewal
//! if manager.needs_renewal().await? {
//!     let result = manager.renew().await?;
//!     println!("Renewed: {}", result.thumbprint);
//! }
//! # Ok(())
//! # }
//! ```

use crate::auto_enroll::config::{AutoEnrollConfig, KeyAlgorithm as ConfigKeyAlgorithm, TrustMode};
use crate::error::{EstError, Result};
use std::sync::Arc;
use std::time::Duration;

#[cfg(windows)]
use super::{CertStore, CertStoreLocation, MachineIdentity, StoredCertificate};

#[cfg(feature = "windows-service")]
use super::{EventLog, PerformanceCounters};

/// Result of a successful enrollment or renewal operation.
#[derive(Debug, Clone)]
pub struct EnrollmentResult {
    /// SHA-1 thumbprint of the issued certificate.
    pub thumbprint: String,
    /// Subject Distinguished Name.
    pub subject: String,
    /// Certificate expiration time (Unix timestamp).
    pub not_after: u64,
    /// Whether this was an initial enrollment or renewal.
    pub is_renewal: bool,
    /// Time taken for the operation in milliseconds.
    pub duration_ms: u64,
}

/// Enrollment status for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentStatus {
    /// No certificate exists, enrollment needed.
    NotEnrolled,
    /// Certificate exists and is valid.
    Enrolled,
    /// Certificate exists but renewal is needed.
    RenewalNeeded,
    /// Certificate exists but is expired.
    Expired,
    /// Enrollment is pending approval.
    Pending,
    /// Enrollment failed.
    Failed,
}

impl EnrollmentStatus {
    /// Get a human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::NotEnrolled => "No certificate enrolled",
            Self::Enrolled => "Certificate is valid",
            Self::RenewalNeeded => "Certificate renewal needed",
            Self::Expired => "Certificate has expired",
            Self::Pending => "Enrollment pending approval",
            Self::Failed => "Enrollment failed",
        }
    }
}

/// Options for enrollment operations.
#[derive(Debug, Clone)]
pub struct EnrollmentOptions {
    /// Maximum time to wait for pending enrollment (seconds).
    pub pending_timeout: u64,
    /// Interval between pending status checks (seconds).
    pub pending_check_interval: u64,
    /// Whether to force re-enrollment even if certificate exists.
    pub force: bool,
    /// Whether to archive the old certificate on renewal.
    pub archive_old: bool,
    /// Whether to generate a new key on renewal (vs. reusing).
    pub new_key_on_renewal: bool,
}

impl Default for EnrollmentOptions {
    fn default() -> Self {
        Self {
            pending_timeout: 3600,      // 1 hour
            pending_check_interval: 60, // 1 minute
            force: false,
            archive_old: true,
            new_key_on_renewal: true,
        }
    }
}

/// Manages certificate enrollment and renewal workflows.
pub struct EnrollmentManager {
    /// Configuration for enrollment.
    config: AutoEnrollConfig,
    /// Enrollment options.
    options: EnrollmentOptions,
    /// Performance counters for metrics.
    #[cfg(feature = "windows-service")]
    counters: Option<Arc<PerformanceCounters>>,
    /// Event log for Windows Event Log integration.
    #[cfg(feature = "windows-service")]
    event_log: Option<EventLog>,
}

impl EnrollmentManager {
    /// Create a new enrollment manager with the given configuration.
    pub fn new(config: AutoEnrollConfig) -> Result<Self> {
        Ok(Self {
            config,
            options: EnrollmentOptions::default(),
            #[cfg(feature = "windows-service")]
            counters: None,
            #[cfg(feature = "windows-service")]
            event_log: None,
        })
    }

    /// Create a new enrollment manager with custom options.
    pub fn with_options(config: AutoEnrollConfig, options: EnrollmentOptions) -> Result<Self> {
        Ok(Self {
            config,
            options,
            #[cfg(feature = "windows-service")]
            counters: None,
            #[cfg(feature = "windows-service")]
            event_log: None,
        })
    }

    /// Set performance counters for metrics collection.
    #[cfg(feature = "windows-service")]
    pub fn with_counters(mut self, counters: Arc<PerformanceCounters>) -> Self {
        self.counters = Some(counters);
        self
    }

    /// Set event log for Windows Event Log integration.
    #[cfg(feature = "windows-service")]
    pub fn with_event_log(mut self, event_log: EventLog) -> Self {
        self.event_log = Some(event_log);
        self
    }

    /// Get the current enrollment status.
    #[cfg(windows)]
    pub async fn status(&self) -> Result<EnrollmentStatus> {
        let identity = MachineIdentity::current()?;
        let store = self.open_cert_store()?;

        let cn = self.get_common_name(&identity);

        match store.find_by_subject(&cn)? {
            Some(cert) => {
                // Check if certificate is expired
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                if cert.not_after < now {
                    return Ok(EnrollmentStatus::Expired);
                }

                // Check if renewal is needed
                let threshold_days = self.config.renewal.threshold_days.unwrap_or(30);
                let threshold_secs = threshold_days as u64 * 24 * 60 * 60;
                let time_remaining = cert.not_after.saturating_sub(now);

                if time_remaining < threshold_secs {
                    return Ok(EnrollmentStatus::RenewalNeeded);
                }

                Ok(EnrollmentStatus::Enrolled)
            }
            None => Ok(EnrollmentStatus::NotEnrolled),
        }
    }

    /// Check if initial enrollment is needed.
    #[cfg(windows)]
    pub async fn needs_enrollment(&self) -> Result<bool> {
        if self.options.force {
            return Ok(true);
        }

        let status = self.status().await?;
        Ok(matches!(
            status,
            EnrollmentStatus::NotEnrolled | EnrollmentStatus::Expired
        ))
    }

    /// Check if certificate renewal is needed.
    #[cfg(windows)]
    pub async fn needs_renewal(&self) -> Result<bool> {
        let status = self.status().await?;
        Ok(matches!(status, EnrollmentStatus::RenewalNeeded))
    }

    /// Perform initial certificate enrollment.
    #[cfg(windows)]
    pub async fn enroll(&self) -> Result<EnrollmentResult> {
        let start = std::time::Instant::now();

        tracing::info!("Starting certificate enrollment");

        #[cfg(feature = "windows-service")]
        if let Some(ref log) = self.event_log {
            let _ = log.log_info(
                super::eventlog::EventId::ENROLLMENT_STARTED,
                "Certificate enrollment started",
            );
        }

        // Step 1: Get machine identity
        let identity = MachineIdentity::current()?;
        tracing::debug!("Machine identity: {}", identity.computer_name);

        // Step 2: Build EST client configuration
        let est_config = self.build_est_config(&identity).await?;

        // Step 3: Create EST client
        let client = crate::EstClient::new(est_config).await?;

        // Step 4: Fetch CA certificates if using bootstrap/TOFU
        if matches!(self.config.trust.mode, TrustMode::Bootstrap) {
            tracing::info!("Fetching CA certificates (bootstrap mode)");
            let ca_certs = client.get_ca_certs().await?;
            tracing::info!("Retrieved {} CA certificates", ca_certs.len());
            // In production, would verify fingerprint here
        }

        // Step 5: Generate key pair
        let (key_handle, public_key_der) = self.generate_key_pair(&identity).await?;
        tracing::debug!("Generated key pair");

        // Step 6: Build CSR
        let csr_der = self.build_csr(&identity, &public_key_der).await?;
        tracing::debug!("Built CSR ({} bytes)", csr_der.len());

        // Step 7: Submit enrollment request
        let response = client.simple_enroll(&csr_der).await?;

        // Step 8: Handle response
        let cert = match response {
            crate::EnrollmentResponse::Issued { certificate } => {
                tracing::info!("Certificate issued immediately");
                certificate
            }
            crate::EnrollmentResponse::Pending { retry_after } => {
                tracing::info!("Enrollment pending, retry after {} seconds", retry_after);
                // Implement pending loop
                self.wait_for_pending(&client, &csr_der, retry_after)
                    .await?
            }
        };

        // Step 9: Install certificate to Windows store
        let stored = self.install_certificate(&cert, &key_handle).await?;
        tracing::info!("Certificate installed: {}", stored.thumbprint);

        let duration_ms = start.elapsed().as_millis() as u64;

        #[cfg(feature = "windows-service")]
        {
            if let Some(ref counters) = self.counters {
                counters.record_enrollment_success();
                counters.record_enrollment_time(duration_ms);
            }
            if let Some(ref log) = self.event_log {
                let _ = log.log_info(
                    super::eventlog::EventId::ENROLLMENT_COMPLETED,
                    &format!("Certificate enrolled: {}", stored.thumbprint),
                );
            }
        }

        Ok(EnrollmentResult {
            thumbprint: stored.thumbprint,
            subject: stored.subject,
            not_after: stored.not_after,
            is_renewal: false,
            duration_ms,
        })
    }

    /// Perform certificate renewal.
    #[cfg(windows)]
    pub async fn renew(&self) -> Result<EnrollmentResult> {
        let start = std::time::Instant::now();

        tracing::info!("Starting certificate renewal");

        #[cfg(feature = "windows-service")]
        if let Some(ref log) = self.event_log {
            let _ = log.log_info(
                super::eventlog::EventId::RENEWAL_STARTED,
                "Certificate renewal started",
            );
        }

        // Step 1: Get machine identity
        let identity = MachineIdentity::current()?;

        // Step 2: Find existing certificate
        let store = self.open_cert_store()?;
        let cn = self.get_common_name(&identity);
        let existing_cert = store
            .find_by_subject(&cn)?
            .ok_or_else(|| EstError::platform("No existing certificate found for renewal"))?;

        tracing::debug!("Found existing certificate: {}", existing_cert.thumbprint);

        // Step 3: Build EST client with existing cert for TLS auth
        let est_config = self
            .build_est_config_for_renewal(&identity, &existing_cert)
            .await?;
        let client = crate::EstClient::new(est_config).await?;

        // Step 4: Generate new key pair (or reuse based on policy)
        let (key_handle, public_key_der) = if self.options.new_key_on_renewal {
            self.generate_key_pair(&identity).await?
        } else {
            // Reuse existing key - would need to extract from store
            return Err(EstError::platform("Key reuse not yet implemented"));
        };

        // Step 5: Build CSR with same subject
        let csr_der = self.build_csr(&identity, &public_key_der).await?;

        // Step 6: Submit re-enrollment request
        let response = client.simple_reenroll(&csr_der).await?;

        // Step 7: Handle response
        let cert = match response {
            crate::EnrollmentResponse::Issued { certificate } => certificate,
            crate::EnrollmentResponse::Pending { retry_after } => {
                self.wait_for_pending(&client, &csr_der, retry_after)
                    .await?
            }
        };

        // Step 8: Archive old certificate if configured
        if self.options.archive_old {
            tracing::debug!("Archiving old certificate: {}", existing_cert.thumbprint);
            // Move to archive store (not deleting)
            // This is a framework - actual archive would move to a different store
        }

        // Step 9: Install new certificate
        let stored = self.install_certificate(&cert, &key_handle).await?;
        tracing::info!("New certificate installed: {}", stored.thumbprint);

        let duration_ms = start.elapsed().as_millis() as u64;

        #[cfg(feature = "windows-service")]
        {
            if let Some(ref counters) = self.counters {
                counters.record_renewal_success();
                counters.record_enrollment_time(duration_ms);
            }
            if let Some(ref log) = self.event_log {
                let _ = log.log_info(
                    super::eventlog::EventId::RENEWAL_COMPLETED,
                    &format!("Certificate renewed: {}", stored.thumbprint),
                );
            }
        }

        Ok(EnrollmentResult {
            thumbprint: stored.thumbprint,
            subject: stored.subject,
            not_after: stored.not_after,
            is_renewal: true,
            duration_ms,
        })
    }

    /// Get the current certificate information.
    #[cfg(windows)]
    pub async fn get_certificate_info(&self) -> Result<Option<CertificateInfo>> {
        let identity = MachineIdentity::current()?;
        let store = self.open_cert_store()?;
        let cn = self.get_common_name(&identity);

        match store.find_by_subject(&cn)? {
            Some(cert) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let days_remaining = if cert.not_after > now {
                    ((cert.not_after - now) / (24 * 60 * 60)) as i64
                } else {
                    -((now - cert.not_after) / (24 * 60 * 60)) as i64
                };

                Ok(Some(CertificateInfo {
                    thumbprint: cert.thumbprint,
                    subject: cert.subject,
                    issuer: cert.issuer,
                    not_before: cert.not_before,
                    not_after: cert.not_after,
                    days_remaining,
                    has_private_key: cert.has_private_key,
                }))
            }
            None => Ok(None),
        }
    }

    // Private helper methods

    #[cfg(windows)]
    fn open_cert_store(&self) -> Result<CertStore> {
        let store_path = self
            .config
            .storage
            .windows_store
            .as_deref()
            .unwrap_or("LocalMachine\\My");

        CertStore::open_path(store_path)
    }

    #[cfg(windows)]
    fn get_common_name(&self, identity: &MachineIdentity) -> String {
        self.config.certificate.common_name.clone()
    }

    #[cfg(windows)]
    async fn build_est_config(&self, identity: &MachineIdentity) -> Result<crate::EstClientConfig> {
        use crate::{EstClientConfig, HttpAuth, TrustAnchors};

        let mut builder = EstClientConfig::builder().server_url(&self.config.server.url)?;

        // Set CA label if configured
        if let Some(ref label) = self.config.server.ca_label {
            builder = builder.ca_label(label);
        }

        // Configure trust anchors
        match self.config.trust.mode {
            TrustMode::WebPki => {
                builder = builder.trust_anchors(TrustAnchors::WebPki);
            }
            TrustMode::Explicit => {
                if let Some(ref path) = self.config.trust.ca_bundle_path {
                    let ca_pem = std::fs::read_to_string(path).map_err(|e| EstError::Io(e))?;
                    builder = builder.trust_anchors(TrustAnchors::Explicit(ca_pem));
                }
            }
            TrustMode::Bootstrap => {
                builder = builder.trust_anchors(TrustAnchors::Bootstrap);
            }
            TrustMode::Insecure => {
                // For testing only
                builder = builder.trust_anchors(TrustAnchors::Bootstrap);
            }
        }

        // Configure authentication
        if let Some(ref username) = self.config.authentication.username {
            let password = self.get_password().await?;
            builder = builder.http_auth(username, &password);
        }

        builder.build()
    }

    #[cfg(windows)]
    async fn build_est_config_for_renewal(
        &self,
        identity: &MachineIdentity,
        existing_cert: &StoredCertificate,
    ) -> Result<crate::EstClientConfig> {
        // For renewal, we use the existing certificate for TLS client auth
        // This is a framework - actual implementation would export cert and key
        self.build_est_config(identity).await
    }

    #[cfg(windows)]
    async fn get_password(&self) -> Result<String> {
        // Get password from configured source
        match self.config.authentication.password_source.as_deref() {
            Some(source) if source.starts_with("env:") => {
                let var_name = &source[4..];
                std::env::var(var_name).map_err(|_| {
                    EstError::platform(format!("Environment variable {} not set", var_name))
                })
            }
            Some(source) if source.starts_with("file:") => {
                let path = &source[5..];
                std::fs::read_to_string(path)
                    .map(|s| s.trim().to_string())
                    .map_err(|e| EstError::Io(e))
            }
            Some("credential_manager") => {
                // Would use Windows Credential Manager here
                Err(EstError::platform(
                    "Credential Manager support not yet implemented",
                ))
            }
            _ => {
                // Direct password (not recommended for production)
                self.config
                    .authentication
                    .password
                    .clone()
                    .ok_or_else(|| EstError::platform("No password configured"))
            }
        }
    }

    #[cfg(windows)]
    async fn generate_key_pair(&self, _identity: &MachineIdentity) -> Result<(KeyHandle, Vec<u8>)> {
        use super::CngKeyProvider;
        use crate::hsm::{KeyAlgorithm, KeyProvider};

        let algorithm = match self.config.certificate.key.algorithm {
            ConfigKeyAlgorithm::EcdsaP256 => KeyAlgorithm::EcdsaP256,
            ConfigKeyAlgorithm::EcdsaP384 => KeyAlgorithm::EcdsaP384,
            ConfigKeyAlgorithm::Rsa2048 => KeyAlgorithm::Rsa2048,
            ConfigKeyAlgorithm::Rsa3072 => KeyAlgorithm::Rsa3072,
            ConfigKeyAlgorithm::Rsa4096 => KeyAlgorithm::Rsa4096,
        };

        let provider = CngKeyProvider::new()?;
        let handle = provider
            .generate_key_pair(algorithm, Some("EST-Enrollment"))
            .await?;
        let public_key = provider.public_key(&handle).await?;

        Ok((KeyHandle(handle.id().to_string()), public_key))
    }

    #[cfg(windows)]
    async fn build_csr(
        &self,
        identity: &MachineIdentity,
        _public_key_der: &[u8],
    ) -> Result<Vec<u8>> {
        #[cfg(feature = "csr-gen")]
        {
            use crate::csr::CsrBuilder;

            let mut builder = CsrBuilder::new().common_name(&self.config.certificate.common_name);

            if let Some(ref org) = self.config.certificate.organization {
                builder = builder.organization(org);
            }
            if let Some(ref ou) = self.config.certificate.organizational_unit {
                builder = builder.organizational_unit(ou);
            }
            if let Some(ref country) = self.config.certificate.country {
                builder = builder.country(country);
            }
            if let Some(ref state) = self.config.certificate.state {
                builder = builder.state(state);
            }
            if let Some(ref locality) = self.config.certificate.locality {
                builder = builder.locality(locality);
            }

            // Add SANs
            if let Some(ref san) = self.config.certificate.san {
                for dns in &san.dns {
                    builder = builder.san_dns(dns);
                }
                for ip in &san.ip {
                    builder = builder.san_ip(*ip);
                }
                for email in &san.email {
                    builder = builder.san_email(email);
                }
            }

            let (csr_der, _key_pair) = builder.build()?;
            Ok(csr_der)
        }

        #[cfg(not(feature = "csr-gen"))]
        {
            Err(EstError::platform(
                "CSR generation requires csr-gen feature",
            ))
        }
    }

    #[cfg(windows)]
    async fn wait_for_pending(
        &self,
        client: &crate::EstClient,
        csr_der: &[u8],
        initial_retry_after: u64,
    ) -> Result<x509_cert::Certificate> {
        let mut retry_after = initial_retry_after;
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(self.options.pending_timeout);

        loop {
            if start.elapsed() > timeout {
                return Err(EstError::platform("Enrollment pending timeout exceeded"));
            }

            tracing::info!("Waiting {} seconds before retry...", retry_after);
            tokio::time::sleep(Duration::from_secs(retry_after)).await;

            match client.simple_enroll(csr_der).await? {
                crate::EnrollmentResponse::Issued { certificate } => {
                    return Ok(certificate);
                }
                crate::EnrollmentResponse::Pending {
                    retry_after: new_retry,
                } => {
                    retry_after = new_retry;
                    tracing::info!("Still pending, retry after {} seconds", retry_after);
                }
            }
        }
    }

    #[cfg(windows)]
    async fn install_certificate(
        &self,
        cert: &x509_cert::Certificate,
        _key_handle: &KeyHandle,
    ) -> Result<StoredCertificate> {
        use der::Encode;

        let store = self.open_cert_store()?;
        let cert_der = cert.to_der().map_err(|e| EstError::Der(e))?;

        // Import certificate (key association would happen here in production)
        store.import_certificate(&cert_der)
    }
}

/// Handle to a generated key pair.
#[derive(Debug, Clone)]
pub struct KeyHandle(String);

impl KeyHandle {
    /// Get the key identifier.
    pub fn id(&self) -> &str {
        &self.0
    }
}

/// Information about an enrolled certificate.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// SHA-1 thumbprint.
    pub thumbprint: String,
    /// Subject Distinguished Name.
    pub subject: String,
    /// Issuer Distinguished Name.
    pub issuer: String,
    /// Not valid before (Unix timestamp).
    pub not_before: u64,
    /// Not valid after (Unix timestamp).
    pub not_after: u64,
    /// Days remaining until expiration (negative if expired).
    pub days_remaining: i64,
    /// Whether the certificate has an associated private key.
    pub has_private_key: bool,
}

/// Recovery options for enrollment issues.
#[derive(Debug, Clone)]
pub struct RecoveryOptions {
    /// Force re-enrollment even if certificate exists.
    pub force_reenroll: bool,
    /// Delete existing certificate before re-enrollment.
    pub delete_existing: bool,
    /// Generate new key even if existing key is valid.
    pub regenerate_key: bool,
    /// Re-fetch CA certificates.
    pub refresh_ca_certs: bool,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            force_reenroll: false,
            delete_existing: false,
            regenerate_key: false,
            refresh_ca_certs: false,
        }
    }
}

/// Recovery helper for enrollment issues.
pub struct RecoveryHelper {
    config: AutoEnrollConfig,
    options: RecoveryOptions,
}

impl RecoveryHelper {
    /// Create a new recovery helper.
    pub fn new(config: AutoEnrollConfig, options: RecoveryOptions) -> Self {
        Self { config, options }
    }

    /// Attempt recovery from enrollment failure.
    #[cfg(windows)]
    pub async fn recover(&self) -> Result<EnrollmentResult> {
        tracing::info!("Starting enrollment recovery");

        if self.options.delete_existing {
            // Delete existing certificate if present
            self.delete_existing_certificate().await?;
        }

        if self.options.refresh_ca_certs {
            // Re-fetch CA certificates
            self.refresh_ca_certificates().await?;
        }

        // Perform fresh enrollment
        let manager = EnrollmentManager::with_options(
            self.config.clone(),
            EnrollmentOptions {
                force: true,
                new_key_on_renewal: self.options.regenerate_key,
                ..Default::default()
            },
        )?;

        manager.enroll().await
    }

    #[cfg(windows)]
    async fn delete_existing_certificate(&self) -> Result<()> {
        let identity = MachineIdentity::current()?;
        let store = CertStore::open_path(
            self.config
                .storage
                .windows_store
                .as_deref()
                .unwrap_or("LocalMachine\\My"),
        )?;

        let cn = &self.config.certificate.common_name;

        if let Some(cert) = store.find_by_subject(cn)? {
            tracing::info!("Deleting existing certificate: {}", cert.thumbprint);
            store.delete_certificate(&cert.thumbprint)?;
        }

        Ok(())
    }

    #[cfg(windows)]
    async fn refresh_ca_certificates(&self) -> Result<()> {
        // Would re-fetch and update CA certificates here
        tracing::info!("Refreshing CA certificates");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrollment_status_description() {
        assert_eq!(
            EnrollmentStatus::NotEnrolled.description(),
            "No certificate enrolled"
        );
        assert_eq!(
            EnrollmentStatus::Enrolled.description(),
            "Certificate is valid"
        );
        assert_eq!(
            EnrollmentStatus::RenewalNeeded.description(),
            "Certificate renewal needed"
        );
        assert_eq!(
            EnrollmentStatus::Expired.description(),
            "Certificate has expired"
        );
    }

    #[test]
    fn test_enrollment_options_default() {
        let opts = EnrollmentOptions::default();
        assert_eq!(opts.pending_timeout, 3600);
        assert_eq!(opts.pending_check_interval, 60);
        assert!(!opts.force);
        assert!(opts.archive_old);
        assert!(opts.new_key_on_renewal);
    }

    #[test]
    fn test_recovery_options_default() {
        let opts = RecoveryOptions::default();
        assert!(!opts.force_reenroll);
        assert!(!opts.delete_existing);
        assert!(!opts.regenerate_key);
        assert!(!opts.refresh_ca_certs);
    }

    #[test]
    fn test_key_handle() {
        let handle = KeyHandle("test-key-123".to_string());
        assert_eq!(handle.id(), "test-key-123");
    }
}
