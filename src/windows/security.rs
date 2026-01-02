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

//! Security utilities for Windows auto-enrollment.
//!
//! This module provides security-related functionality including:
//!
//! - **Key Protection**: Policies for private key generation and storage
//! - **Certificate Pinning**: Pin EST server certificates for added security
//! - **Audit Logging**: Security event auditing
//! - **Network Security**: TLS configuration and proxy support
//!
//! # Key Protection
//!
//! Private keys are protected by default using:
//! - Non-exportable key storage
//! - TPM-backed keys (when available)
//! - Key usage auditing
//!
//! # Example
//!
//! ```no_run,ignore
//! use usg_est_client::windows::security::{KeyProtection, CertificatePinning};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure key protection
//! let protection = KeyProtection::default()
//!     .with_non_exportable(true)
//!     .with_tpm_preferred(true);
//!
//! // Configure certificate pinning
//! let pinning = CertificatePinning::new()
//!     .add_pin("SHA256:abc123...");
//! # Ok(())
//! # }
//! ```

use crate::error::{EstError, Result};
use std::collections::HashSet;

/// Key protection policy configuration.
#[derive(Debug, Clone)]
pub struct KeyProtection {
    /// Require non-exportable keys.
    pub non_exportable: bool,
    /// Prefer TPM-backed keys when available.
    pub tpm_preferred: bool,
    /// Require TPM-backed keys (fail if TPM unavailable).
    pub tpm_required: bool,
    /// Minimum key size for RSA (bits).
    pub min_rsa_key_size: u32,
    /// Allowed key algorithms.
    pub allowed_algorithms: HashSet<KeyAlgorithmPolicy>,
    /// Enable key usage auditing.
    pub audit_key_usage: bool,
}

impl Default for KeyProtection {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert(KeyAlgorithmPolicy::EcdsaP256);
        allowed.insert(KeyAlgorithmPolicy::EcdsaP384);
        allowed.insert(KeyAlgorithmPolicy::Rsa2048);
        allowed.insert(KeyAlgorithmPolicy::Rsa3072);
        allowed.insert(KeyAlgorithmPolicy::Rsa4096);

        Self {
            non_exportable: true,
            tpm_preferred: true,
            tpm_required: false,
            min_rsa_key_size: 2048,
            allowed_algorithms: allowed,
            audit_key_usage: true,
        }
    }
}

impl KeyProtection {
    /// Create a new key protection policy with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a high-security policy (TPM required, no export).
    pub fn high_security() -> Self {
        Self {
            non_exportable: true,
            tpm_preferred: true,
            tpm_required: true,
            min_rsa_key_size: 3072,
            audit_key_usage: true,
            ..Default::default()
        }
    }

    /// Create a policy for development/testing (exportable, no TPM).
    pub fn development() -> Self {
        Self {
            non_exportable: false,
            tpm_preferred: false,
            tpm_required: false,
            min_rsa_key_size: 2048,
            audit_key_usage: false,
            ..Default::default()
        }
    }

    /// Set non-exportable requirement.
    pub fn with_non_exportable(mut self, non_exportable: bool) -> Self {
        self.non_exportable = non_exportable;
        self
    }

    /// Set TPM preference.
    pub fn with_tpm_preferred(mut self, preferred: bool) -> Self {
        self.tpm_preferred = preferred;
        self
    }

    /// Set TPM requirement.
    pub fn with_tpm_required(mut self, required: bool) -> Self {
        self.tpm_required = required;
        if required {
            self.tpm_preferred = true;
        }
        self
    }

    /// Set minimum RSA key size.
    pub fn with_min_rsa_key_size(mut self, bits: u32) -> Self {
        self.min_rsa_key_size = bits;
        self
    }

    /// Validate a key algorithm against the policy.
    pub fn validate_algorithm(&self, algorithm: KeyAlgorithmPolicy) -> Result<()> {
        if !self.allowed_algorithms.contains(&algorithm) {
            return Err(EstError::platform(format!(
                "Key algorithm {:?} not allowed by policy",
                algorithm
            )));
        }

        // Check RSA key size
        let min_size = self.min_rsa_key_size;
        match algorithm {
            KeyAlgorithmPolicy::Rsa2048 if min_size > 2048 => {
                return Err(EstError::platform(format!(
                    "RSA-2048 below minimum key size of {} bits",
                    min_size
                )));
            }
            KeyAlgorithmPolicy::Rsa3072 if min_size > 3072 => {
                return Err(EstError::platform(format!(
                    "RSA-3072 below minimum key size of {} bits",
                    min_size
                )));
            }
            _ => {}
        }

        Ok(())
    }
}

/// Key algorithm for policy validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgorithmPolicy {
    /// ECDSA with P-256 curve.
    EcdsaP256,
    /// ECDSA with P-384 curve.
    EcdsaP384,
    /// RSA 2048-bit.
    Rsa2048,
    /// RSA 3072-bit.
    Rsa3072,
    /// RSA 4096-bit.
    Rsa4096,
}

/// Certificate pinning configuration.
///
/// Certificate pinning helps prevent man-in-the-middle attacks by
/// validating that the server certificate matches a known pin.
#[derive(Debug, Clone, Default)]
pub struct CertificatePinning {
    /// SHA-256 fingerprints of pinned certificates or public keys.
    pins: HashSet<String>,
    /// Allow fallback to unpinned validation if no pins match.
    allow_fallback: bool,
    /// Include subjectPublicKeyInfo hash (SPKI) in addition to certificate hash.
    include_spki: bool,
}

impl CertificatePinning {
    /// Create a new certificate pinning configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a certificate pin.
    ///
    /// Pin format: `SHA256:hex_fingerprint` or just `hex_fingerprint`
    pub fn add_pin(mut self, pin: &str) -> Self {
        let normalized = pin
            .strip_prefix("SHA256:")
            .unwrap_or(pin)
            .to_lowercase()
            .replace(':', "")
            .replace(' ', "");
        self.pins.insert(normalized);
        self
    }

    /// Add multiple pins.
    pub fn add_pins(mut self, pins: &[&str]) -> Self {
        for pin in pins {
            self = self.add_pin(pin);
        }
        self
    }

    /// Allow fallback to standard validation if no pins match.
    pub fn with_fallback(mut self, allow: bool) -> Self {
        self.allow_fallback = allow;
        self
    }

    /// Include SPKI hash validation.
    pub fn with_spki(mut self, include: bool) -> Self {
        self.include_spki = include;
        self
    }

    /// Check if any pins are configured.
    pub fn has_pins(&self) -> bool {
        !self.pins.is_empty()
    }

    /// Get the number of pins.
    pub fn pin_count(&self) -> usize {
        self.pins.len()
    }

    /// Validate a certificate fingerprint against configured pins.
    pub fn validate_fingerprint(&self, fingerprint: &str) -> Result<()> {
        if self.pins.is_empty() {
            return Ok(()); // No pins configured, allow all
        }

        let normalized = fingerprint.to_lowercase().replace(':', "").replace(' ', "");

        if self.pins.contains(&normalized) {
            return Ok(());
        }

        if self.allow_fallback {
            tracing::warn!("Certificate fingerprint not in pin set, allowing fallback");
            return Ok(());
        }

        Err(EstError::platform(format!(
            "Certificate fingerprint {} does not match any configured pin",
            fingerprint
        )))
    }

    /// Get all configured pins.
    pub fn pins(&self) -> impl Iterator<Item = &String> {
        self.pins.iter()
    }
}

/// Security audit event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityAuditEvent {
    /// Key pair generated.
    KeyGenerated,
    /// Key pair deleted.
    KeyDeleted,
    /// Key used for signing.
    KeyUsed,
    /// Certificate enrolled.
    CertificateEnrolled,
    /// Certificate renewed.
    CertificateRenewed,
    /// Certificate deleted.
    CertificateDeleted,
    /// Certificate exported.
    CertificateExported,
    /// Authentication succeeded.
    AuthenticationSuccess,
    /// Authentication failed.
    AuthenticationFailure,
    /// Configuration changed.
    ConfigurationChanged,
    /// Policy violation detected.
    PolicyViolation,
}

impl SecurityAuditEvent {
    /// Get the event name for logging.
    pub fn name(&self) -> &'static str {
        match self {
            Self::KeyGenerated => "KEY_GENERATED",
            Self::KeyDeleted => "KEY_DELETED",
            Self::KeyUsed => "KEY_USED",
            Self::CertificateEnrolled => "CERT_ENROLLED",
            Self::CertificateRenewed => "CERT_RENEWED",
            Self::CertificateDeleted => "CERT_DELETED",
            Self::CertificateExported => "CERT_EXPORTED",
            Self::AuthenticationSuccess => "AUTH_SUCCESS",
            Self::AuthenticationFailure => "AUTH_FAILURE",
            Self::ConfigurationChanged => "CONFIG_CHANGED",
            Self::PolicyViolation => "POLICY_VIOLATION",
        }
    }

    /// Check if this is a security-sensitive event that should always be logged.
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::KeyDeleted
                | Self::CertificateDeleted
                | Self::CertificateExported
                | Self::AuthenticationFailure
                | Self::PolicyViolation
        )
    }
}

/// Security audit logger.
pub struct SecurityAudit {
    /// Whether auditing is enabled.
    enabled: bool,
    /// Log to Windows Event Log.
    use_event_log: bool,
    /// Log to file.
    log_file_path: Option<std::path::PathBuf>,
}

impl Default for SecurityAudit {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityAudit {
    /// Create a new security audit logger.
    pub fn new() -> Self {
        Self {
            enabled: true,
            use_event_log: true,
            log_file_path: None,
        }
    }

    /// Disable auditing.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            use_event_log: false,
            log_file_path: None,
        }
    }

    /// Set whether to use Windows Event Log.
    pub fn with_event_log(mut self, use_event_log: bool) -> Self {
        self.use_event_log = use_event_log;
        self
    }

    /// Set a file path for audit logs.
    pub fn with_file(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.log_file_path = Some(path.into());
        self
    }

    /// Log a security audit event.
    pub fn log(&self, event: SecurityAuditEvent, details: &str) {
        if !self.enabled {
            return;
        }

        let message = format!("[SECURITY] {} - {}", event.name(), details);

        // Always log critical events at warn level
        if event.is_critical() {
            tracing::warn!("{}", message);
        } else {
            tracing::info!("{}", message);
        }

        // Log to file if configured
        if let Some(ref path) = self.log_file_path {
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                use std::io::Write;
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let _ = writeln!(file, "{} {}", timestamp, message);
            }
        }
    }

    /// Log a key generation event.
    pub fn log_key_generated(&self, algorithm: &str, label: Option<&str>) {
        let details = match label {
            Some(l) => format!("Algorithm: {}, Label: {}", algorithm, l),
            None => format!("Algorithm: {}", algorithm),
        };
        self.log(SecurityAuditEvent::KeyGenerated, &details);
    }

    /// Log a certificate enrollment event.
    pub fn log_certificate_enrolled(&self, thumbprint: &str, subject: &str) {
        let details = format!("Thumbprint: {}, Subject: {}", thumbprint, subject);
        self.log(SecurityAuditEvent::CertificateEnrolled, &details);
    }

    /// Log an authentication failure.
    pub fn log_auth_failure(&self, reason: &str) {
        self.log(SecurityAuditEvent::AuthenticationFailure, reason);
    }

    /// Log a policy violation.
    pub fn log_policy_violation(&self, policy: &str, details: &str) {
        let message = format!("Policy: {}, Details: {}", policy, details);
        self.log(SecurityAuditEvent::PolicyViolation, &message);
    }
}

/// TLS security configuration.
#[derive(Debug, Clone)]
pub struct TlsSecurityConfig {
    /// Minimum TLS version (1.2 or 1.3).
    pub min_version: TlsVersion,
    /// Preferred TLS version.
    pub preferred_version: TlsVersion,
    /// Certificate pinning configuration.
    pub certificate_pinning: Option<CertificatePinning>,
    /// Allow self-signed certificates (for testing only).
    pub allow_self_signed: bool,
    /// Verify hostname.
    pub verify_hostname: bool,
    /// Custom cipher suites (empty = use defaults).
    pub cipher_suites: Vec<String>,
}

impl Default for TlsSecurityConfig {
    fn default() -> Self {
        Self {
            min_version: TlsVersion::Tls12,
            preferred_version: TlsVersion::Tls13,
            certificate_pinning: None,
            allow_self_signed: false,
            verify_hostname: true,
            cipher_suites: Vec::new(),
        }
    }
}

impl TlsSecurityConfig {
    /// Create a new TLS security configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a high-security configuration.
    pub fn high_security() -> Self {
        Self {
            min_version: TlsVersion::Tls13,
            preferred_version: TlsVersion::Tls13,
            certificate_pinning: None,
            allow_self_signed: false,
            verify_hostname: true,
            cipher_suites: Vec::new(),
        }
    }

    /// Create a configuration for development/testing.
    pub fn development() -> Self {
        Self {
            min_version: TlsVersion::Tls12,
            preferred_version: TlsVersion::Tls13,
            certificate_pinning: None,
            allow_self_signed: true,
            verify_hostname: false,
            cipher_suites: Vec::new(),
        }
    }

    /// Set certificate pinning.
    pub fn with_pinning(mut self, pinning: CertificatePinning) -> Self {
        self.certificate_pinning = Some(pinning);
        self
    }

    /// Set minimum TLS version.
    pub fn with_min_version(mut self, version: TlsVersion) -> Self {
        self.min_version = version;
        self
    }
}

/// TLS version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    /// TLS 1.2 (minimum required by RFC 7030).
    Tls12,
    /// TLS 1.3 (preferred).
    Tls13,
}

impl TlsVersion {
    /// Get the version string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tls12 => "TLS 1.2",
            Self::Tls13 => "TLS 1.3",
        }
    }
}

/// Network security configuration.
#[derive(Debug, Clone, Default)]
pub struct NetworkSecurityConfig {
    /// TLS security settings.
    pub tls: TlsSecurityConfig,
    /// Proxy configuration.
    pub proxy: Option<ProxyConfig>,
    /// Connection timeout in seconds.
    pub connect_timeout_secs: u64,
    /// Request timeout in seconds.
    pub request_timeout_secs: u64,
    /// Maximum retry attempts.
    pub max_retries: u32,
    /// Base retry delay in seconds.
    pub retry_delay_secs: u64,
}

impl NetworkSecurityConfig {
    /// Create a new network security configuration.
    pub fn new() -> Self {
        Self {
            tls: TlsSecurityConfig::default(),
            proxy: None,
            connect_timeout_secs: 30,
            request_timeout_secs: 60,
            max_retries: 3,
            retry_delay_secs: 5,
        }
    }

    /// Set proxy configuration.
    pub fn with_proxy(mut self, proxy: ProxyConfig) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Set timeouts.
    pub fn with_timeouts(mut self, connect: u64, request: u64) -> Self {
        self.connect_timeout_secs = connect;
        self.request_timeout_secs = request;
        self
    }

    /// Set retry configuration.
    pub fn with_retries(mut self, max_retries: u32, delay_secs: u64) -> Self {
        self.max_retries = max_retries;
        self.retry_delay_secs = delay_secs;
        self
    }
}

/// Proxy configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Proxy URL.
    pub url: String,
    /// Proxy username (if required).
    pub username: Option<String>,
    /// Proxy password (if required).
    pub password: Option<String>,
    /// Bypass proxy for these hosts.
    pub no_proxy: Vec<String>,
}

impl ProxyConfig {
    /// Create a new proxy configuration.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            username: None,
            password: None,
            no_proxy: Vec::new(),
        }
    }

    /// Set proxy authentication.
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    /// Add hosts to bypass proxy.
    pub fn with_no_proxy(mut self, hosts: &[&str]) -> Self {
        self.no_proxy = hosts.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Get from system environment.
    pub fn from_environment() -> Option<Self> {
        std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .ok()
            .map(|url| {
                let mut config = Self::new(url);
                if let Ok(no_proxy) =
                    std::env::var("NO_PROXY").or_else(|_| std::env::var("no_proxy"))
                {
                    config.no_proxy = no_proxy.split(',').map(|s| s.trim().to_string()).collect();
                }
                config
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_protection_default() {
        let policy = KeyProtection::default();
        assert!(policy.non_exportable);
        assert!(policy.tpm_preferred);
        assert!(!policy.tpm_required);
        assert_eq!(policy.min_rsa_key_size, 2048);
    }

    #[test]
    fn test_key_protection_high_security() {
        let policy = KeyProtection::high_security();
        assert!(policy.non_exportable);
        assert!(policy.tpm_required);
        assert_eq!(policy.min_rsa_key_size, 3072);
    }

    #[test]
    fn test_key_protection_validate_algorithm() {
        let policy = KeyProtection::default();
        assert!(
            policy
                .validate_algorithm(KeyAlgorithmPolicy::EcdsaP256)
                .is_ok()
        );
        assert!(
            policy
                .validate_algorithm(KeyAlgorithmPolicy::Rsa2048)
                .is_ok()
        );

        let strict = KeyProtection::default().with_min_rsa_key_size(3072);
        assert!(
            strict
                .validate_algorithm(KeyAlgorithmPolicy::Rsa2048)
                .is_err()
        );
        assert!(
            strict
                .validate_algorithm(KeyAlgorithmPolicy::Rsa4096)
                .is_ok()
        );
    }

    #[test]
    fn test_certificate_pinning() {
        let pinning = CertificatePinning::new()
            .add_pin("SHA256:abcdef123456")
            .add_pin("ABCDEF123456");

        assert!(pinning.has_pins());
        assert_eq!(pinning.pin_count(), 2);

        assert!(pinning.validate_fingerprint("abcdef123456").is_ok());
        assert!(pinning.validate_fingerprint("ABCDEF123456").is_ok());
        assert!(pinning.validate_fingerprint("invalid").is_err());
    }

    #[test]
    fn test_certificate_pinning_fallback() {
        let pinning = CertificatePinning::new()
            .add_pin("abcdef")
            .with_fallback(true);

        assert!(pinning.validate_fingerprint("different").is_ok());
    }

    #[test]
    fn test_security_audit_event() {
        assert_eq!(SecurityAuditEvent::KeyGenerated.name(), "KEY_GENERATED");
        assert!(SecurityAuditEvent::PolicyViolation.is_critical());
        assert!(!SecurityAuditEvent::KeyGenerated.is_critical());
    }

    #[test]
    fn test_tls_version_ordering() {
        assert!(TlsVersion::Tls12 < TlsVersion::Tls13);
    }

    #[test]
    fn test_tls_security_config() {
        let config = TlsSecurityConfig::high_security();
        assert_eq!(config.min_version, TlsVersion::Tls13);
        assert!(!config.allow_self_signed);

        let dev = TlsSecurityConfig::development();
        assert!(dev.allow_self_signed);
    }

    #[test]
    fn test_proxy_config() {
        let proxy = ProxyConfig::new("http://proxy.example.com:8080")
            .with_auth("user", "pass")
            .with_no_proxy(&["localhost", "127.0.0.1"]);

        assert_eq!(proxy.url, "http://proxy.example.com:8080");
        assert_eq!(proxy.username, Some("user".to_string()));
        assert_eq!(proxy.no_proxy.len(), 2);
    }

    #[test]
    fn test_network_security_config() {
        let config = NetworkSecurityConfig::new()
            .with_timeouts(10, 30)
            .with_retries(5, 10);

        assert_eq!(config.connect_timeout_secs, 10);
        assert_eq!(config.request_timeout_secs, 30);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.retry_delay_secs, 10);
    }
}
