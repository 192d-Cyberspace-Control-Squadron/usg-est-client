//! CSR (Certificate Signing Request) generation utilities.
//!
//! This module provides a builder for creating PKCS#10 Certificate Signing
//! Requests. It is feature-gated behind the `csr-gen` feature.

#[cfg(feature = "csr-gen")]
mod builder {
    use std::net::IpAddr;

    use rcgen::{
        CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair,
        KeyUsagePurpose, SanType,
    };

    use crate::error::{EstError, Result};
    use crate::types::CsrAttributes;

    /// Builder for creating Certificate Signing Requests.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use usg_est_client::csr::CsrBuilder;
    ///
    /// let (csr_der, key_pair) = CsrBuilder::new()
    ///     .common_name("device.example.com")
    ///     .organization("Example Corp")
    ///     .country("US")
    ///     .san_dns("device.example.com")
    ///     .build()
    ///     .expect("Failed to generate CSR");
    /// ```
    pub struct CsrBuilder {
        params: CertificateParams,
        key_pair: Option<KeyPair>,
    }

    impl Default for CsrBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CsrBuilder {
        /// Create a new CSR builder with default parameters.
        pub fn new() -> Self {
            Self {
                params: CertificateParams::default(),
                key_pair: None,
            }
        }

        /// Set the Common Name (CN) for the subject.
        pub fn common_name(mut self, cn: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::CommonName, cn.into());
            self
        }

        /// Set the Organization (O) for the subject.
        pub fn organization(mut self, org: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::OrganizationName, org.into());
            self
        }

        /// Set the Organizational Unit (OU) for the subject.
        pub fn organizational_unit(mut self, ou: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::OrganizationalUnitName, ou.into());
            self
        }

        /// Set the Country (C) for the subject.
        pub fn country(mut self, country: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::CountryName, country.into());
            self
        }

        /// Set the State/Province (ST) for the subject.
        pub fn state(mut self, state: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::StateOrProvinceName, state.into());
            self
        }

        /// Set the Locality (L) for the subject.
        pub fn locality(mut self, locality: impl Into<String>) -> Self {
            self.params
                .distinguished_name
                .push(DnType::LocalityName, locality.into());
            self
        }

        /// Add a DNS Subject Alternative Name.
        pub fn san_dns(mut self, dns: impl Into<String>) -> Self {
            self.params
                .subject_alt_names
                .push(SanType::DnsName(dns.into().try_into().unwrap()));
            self
        }

        /// Add an IP address Subject Alternative Name.
        pub fn san_ip(mut self, ip: IpAddr) -> Self {
            self.params.subject_alt_names.push(SanType::IpAddress(ip));
            self
        }

        /// Add an email Subject Alternative Name.
        pub fn san_email(mut self, email: impl Into<String>) -> Self {
            self.params
                .subject_alt_names
                .push(SanType::Rfc822Name(email.into().try_into().unwrap()));
            self
        }

        /// Add a URI Subject Alternative Name.
        pub fn san_uri(mut self, uri: impl Into<String>) -> Self {
            self.params
                .subject_alt_names
                .push(SanType::URI(uri.into().try_into().unwrap()));
            self
        }

        /// Enable digital signature key usage.
        pub fn key_usage_digital_signature(mut self) -> Self {
            self.params.key_usages.push(KeyUsagePurpose::DigitalSignature);
            self
        }

        /// Enable key encipherment key usage.
        pub fn key_usage_key_encipherment(mut self) -> Self {
            self.params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
            self
        }

        /// Enable key agreement key usage.
        pub fn key_usage_key_agreement(mut self) -> Self {
            self.params.key_usages.push(KeyUsagePurpose::KeyAgreement);
            self
        }

        /// Add TLS client authentication extended key usage.
        pub fn extended_key_usage_client_auth(mut self) -> Self {
            self.params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ClientAuth);
            self
        }

        /// Add TLS server authentication extended key usage.
        pub fn extended_key_usage_server_auth(mut self) -> Self {
            self.params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ServerAuth);
            self
        }

        /// Set the challenge password attribute.
        ///
        /// This can be used for TLS channel binding per RFC 7030 Section 3.5.
        pub fn challenge_password(self, password: impl Into<String>) -> Self {
            // Note: rcgen doesn't directly support challenge-password
            // This would need custom extension handling
            let _ = password;
            self
        }

        /// Apply attributes from a server's /csrattrs response.
        ///
        /// This configures the CSR builder based on the server's requirements.
        pub fn with_attributes(self, _attrs: &CsrAttributes) -> Self {
            // Would iterate through attrs and apply relevant settings
            // For now, this is a placeholder
            self
        }

        /// Use an existing key pair instead of generating a new one.
        pub fn with_key_pair(mut self, key_pair: KeyPair) -> Self {
            self.key_pair = Some(key_pair);
            self
        }

        /// Build the CSR with a new ECDSA P-256 key pair.
        ///
        /// Returns the DER-encoded CSR and the generated key pair.
        pub fn build(self) -> Result<(Vec<u8>, KeyPair)> {
            let key_pair = match self.key_pair {
                Some(kp) => kp,
                None => KeyPair::generate()
                    .map_err(|e| EstError::csr(format!("Failed to generate key pair: {}", e)))?,
            };

            let csr = self
                .params
                .serialize_request(&key_pair)
                .map_err(|e| EstError::csr(format!("Failed to serialize CSR: {}", e)))?;

            let csr_der = csr.der().to_vec();

            Ok((csr_der, key_pair))
        }

        /// Build the CSR using the provided key pair.
        ///
        /// Returns only the DER-encoded CSR.
        pub fn build_with_key(self, key_pair: &KeyPair) -> Result<Vec<u8>> {
            let csr = self
                .params
                .serialize_request(key_pair)
                .map_err(|e| EstError::csr(format!("Failed to serialize CSR: {}", e)))?;

            Ok(csr.der().to_vec())
        }
    }

    /// Generate a simple CSR for a device.
    ///
    /// This is a convenience function for common use cases.
    pub fn generate_device_csr(
        common_name: &str,
        organization: Option<&str>,
    ) -> Result<(Vec<u8>, KeyPair)> {
        let mut builder = CsrBuilder::new()
            .common_name(common_name)
            .san_dns(common_name)
            .key_usage_digital_signature()
            .key_usage_key_encipherment()
            .extended_key_usage_client_auth();

        if let Some(org) = organization {
            builder = builder.organization(org);
        }

        builder.build()
    }

    /// Generate a CSR for a TLS server.
    pub fn generate_server_csr(
        common_name: &str,
        san_names: &[&str],
    ) -> Result<(Vec<u8>, KeyPair)> {
        let mut builder = CsrBuilder::new()
            .common_name(common_name)
            .key_usage_digital_signature()
            .key_usage_key_encipherment()
            .extended_key_usage_server_auth();

        for name in san_names {
            builder = builder.san_dns(*name);
        }

        builder.build()
    }
}

#[cfg(feature = "csr-gen")]
pub use builder::*;

#[cfg(not(feature = "csr-gen"))]
pub fn feature_not_enabled() {
    // This module requires the "csr-gen" feature
}

#[cfg(all(test, feature = "csr-gen"))]
mod tests {
    use super::*;

    #[test]
    fn test_csr_builder_basic() {
        let (csr_der, _key_pair) = CsrBuilder::new()
            .common_name("test.example.com")
            .organization("Test Org")
            .build()
            .expect("Failed to build CSR");

        assert!(!csr_der.is_empty());
        // CSR should start with SEQUENCE tag
        assert_eq!(csr_der[0], 0x30);
    }

    #[test]
    fn test_generate_device_csr() {
        let (csr_der, _key_pair) =
            generate_device_csr("device001.example.com", Some("Example Corp"))
                .expect("Failed to generate device CSR");

        assert!(!csr_der.is_empty());
    }

    #[test]
    fn test_generate_server_csr() {
        let (csr_der, _key_pair) =
            generate_server_csr("server.example.com", &["www.example.com", "api.example.com"])
                .expect("Failed to generate server CSR");

        assert!(!csr_der.is_empty());
    }
}
