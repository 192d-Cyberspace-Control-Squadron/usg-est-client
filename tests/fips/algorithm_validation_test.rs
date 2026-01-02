// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! FIPS 140-2 Algorithm Validation Tests
//!
//! These tests validate the algorithm enforcement and validation functionality.

#![cfg(feature = "fips")]

use usg_est_client::fips::algorithms::*;

#[test]
fn test_symmetric_algorithm_validation() {
    let validator = AlgorithmValidator::new();

    // All AES variants should be FIPS-approved
    assert!(validator
        .validate_symmetric_full(SymmetricAlgorithm::Aes128Cbc)
        .is_ok());
    assert!(validator
        .validate_symmetric_full(SymmetricAlgorithm::Aes192Cbc)
        .is_ok());
    assert!(validator
        .validate_symmetric_full(SymmetricAlgorithm::Aes256Cbc)
        .is_ok());
    assert!(validator
        .validate_symmetric_full(SymmetricAlgorithm::Aes128Gcm)
        .is_ok());
    assert!(validator
        .validate_symmetric_full(SymmetricAlgorithm::Aes192Gcm)
        .is_ok());
    assert!(validator
        .validate_symmetric_full(SymmetricAlgorithm::Aes256Gcm)
        .is_ok());
}

#[test]
fn test_asymmetric_algorithm_validation() {
    let validator = AlgorithmValidator::new();

    // RSA 2048+ should be approved
    assert!(validator
        .validate_asymmetric_full(AsymmetricAlgorithm::Rsa2048)
        .is_ok());
    assert!(validator
        .validate_asymmetric_full(AsymmetricAlgorithm::Rsa3072)
        .is_ok());
    assert!(validator
        .validate_asymmetric_full(AsymmetricAlgorithm::Rsa4096)
        .is_ok());

    // ECDSA P-256+ should be approved
    assert!(validator
        .validate_asymmetric_full(AsymmetricAlgorithm::EcdsaP256)
        .is_ok());
    assert!(validator
        .validate_asymmetric_full(AsymmetricAlgorithm::EcdsaP384)
        .is_ok());
    assert!(validator
        .validate_asymmetric_full(AsymmetricAlgorithm::EcdsaP521)
        .is_ok());
}

#[test]
fn test_rsa_key_size_validation() {
    let policy = AlgorithmPolicy::default();

    // Valid RSA key sizes (>= 2048)
    assert!(policy.validate_rsa_key_size(2048).is_ok());
    assert!(policy.validate_rsa_key_size(3072).is_ok());
    assert!(policy.validate_rsa_key_size(4096).is_ok());

    // Invalid RSA key sizes (< 2048)
    assert!(policy.validate_rsa_key_size(512).is_err());
    assert!(policy.validate_rsa_key_size(1024).is_err());
    assert!(policy.validate_rsa_key_size(2047).is_err());
}

#[test]
fn test_ecc_key_size_validation() {
    let policy = AlgorithmPolicy::default();

    // Valid ECC key sizes (>= 256)
    assert!(policy.validate_ecc_key_size(256).is_ok());
    assert!(policy.validate_ecc_key_size(384).is_ok());
    assert!(policy.validate_ecc_key_size(521).is_ok());

    // Invalid ECC key sizes (< 256)
    assert!(policy.validate_ecc_key_size(160).is_err());
    assert!(policy.validate_ecc_key_size(192).is_err());
    assert!(policy.validate_ecc_key_size(224).is_err());
    assert!(policy.validate_ecc_key_size(255).is_err());
}

#[test]
fn test_tls_version_validation() {
    let policy = AlgorithmPolicy::default();

    // TLS 1.2 and 1.3 should be approved
    assert!(policy.validate_tls_version(TlsVersion::Tls12).is_ok());
    assert!(policy.validate_tls_version(TlsVersion::Tls13).is_ok());
}

#[test]
fn test_tls_version_ordering() {
    assert!(TlsVersion::Tls12 < TlsVersion::Tls13);
    assert!(TlsVersion::Tls13 > TlsVersion::Tls12);
}

#[test]
fn test_blocked_algorithm_names() {
    let policy = AlgorithmPolicy::default();

    // Blocked algorithms should fail
    assert!(policy.check_algorithm_name("3DES").is_err());
    assert!(policy.check_algorithm_name("3des").is_err());
    assert!(policy.check_algorithm_name("DES").is_err());
    assert!(policy.check_algorithm_name("MD5").is_err());
    assert!(policy.check_algorithm_name("md5").is_err());
    assert!(policy.check_algorithm_name("SHA1").is_err());
    assert!(policy.check_algorithm_name("SHA-1").is_err());
    assert!(policy.check_algorithm_name("RC4").is_err());
    assert!(policy.check_algorithm_name("RC2").is_err());
    assert!(policy.check_algorithm_name("RSA1024").is_err());
    assert!(policy.check_algorithm_name("RSA512").is_err());

    // Approved algorithms should pass
    assert!(policy.check_algorithm_name("AES-128-CBC").is_ok());
    assert!(policy.check_algorithm_name("AES-256-GCM").is_ok());
    assert!(policy.check_algorithm_name("SHA-256").is_ok());
    assert!(policy.check_algorithm_name("SHA-384").is_ok());
    assert!(policy.check_algorithm_name("SHA-512").is_ok());
    assert!(policy.check_algorithm_name("RSA-2048").is_ok());
    assert!(policy.check_algorithm_name("ECDSA-P256").is_ok());
}

#[test]
fn test_sha1_legacy_mode() {
    let mut policy = AlgorithmPolicy::default();

    // SHA-1 should be blocked by default
    assert!(policy.check_algorithm_name("SHA1").is_err());
    assert!(policy.check_algorithm_name("SHA-1").is_err());

    // Enable legacy mode
    policy.allow_sha1_legacy = true;

    // SHA-1 should now be allowed
    assert!(policy.check_algorithm_name("SHA1").is_ok());
    assert!(policy.check_algorithm_name("SHA-1").is_ok());

    // Other blocked algorithms should still fail
    assert!(policy.check_algorithm_name("MD5").is_err());
    assert!(policy.check_algorithm_name("DES").is_err());
    assert!(policy.check_algorithm_name("3DES").is_err());
}

#[test]
fn test_signature_algorithm_oid_validation() {
    let validator = AlgorithmValidator::new();

    // FIPS-approved signature algorithm OIDs
    assert!(validator
        .validate_signature_algorithm_oid("1.2.840.113549.1.1.11")
        .is_ok()); // sha256WithRSAEncryption
    assert!(validator
        .validate_signature_algorithm_oid("1.2.840.113549.1.1.12")
        .is_ok()); // sha384WithRSAEncryption
    assert!(validator
        .validate_signature_algorithm_oid("1.2.840.113549.1.1.13")
        .is_ok()); // sha512WithRSAEncryption
    assert!(validator
        .validate_signature_algorithm_oid("1.2.840.10045.4.3.2")
        .is_ok()); // ecdsa-with-SHA256
    assert!(validator
        .validate_signature_algorithm_oid("1.2.840.10045.4.3.3")
        .is_ok()); // ecdsa-with-SHA384
    assert!(validator
        .validate_signature_algorithm_oid("1.2.840.10045.4.3.4")
        .is_ok()); // ecdsa-with-SHA512

    // Blocked signature algorithm OIDs
    assert!(validator
        .validate_signature_algorithm_oid("1.2.840.113549.1.1.4")
        .is_err()); // md5WithRSAEncryption
    assert!(validator
        .validate_signature_algorithm_oid("1.2.840.113549.1.1.5")
        .is_err()); // sha1WithRSAEncryption
    assert!(validator
        .validate_signature_algorithm_oid("1.2.840.10045.4.1")
        .is_err()); // ecdsa-with-SHA1

    // Unknown OID should be rejected
    assert!(validator
        .validate_signature_algorithm_oid("1.2.3.4.5.6")
        .is_err());
}

#[test]
fn test_algorithm_key_sizes() {
    assert_eq!(AsymmetricAlgorithm::Rsa2048.key_size(), 2048);
    assert_eq!(AsymmetricAlgorithm::Rsa3072.key_size(), 3072);
    assert_eq!(AsymmetricAlgorithm::Rsa4096.key_size(), 4096);
    assert_eq!(AsymmetricAlgorithm::EcdsaP256.key_size(), 256);
    assert_eq!(AsymmetricAlgorithm::EcdsaP384.key_size(), 384);
    assert_eq!(AsymmetricAlgorithm::EcdsaP521.key_size(), 521);
}

#[test]
fn test_algorithm_type_detection() {
    // RSA algorithms
    assert!(AsymmetricAlgorithm::Rsa2048.is_rsa());
    assert!(!AsymmetricAlgorithm::Rsa2048.is_ecdsa());
    assert!(AsymmetricAlgorithm::Rsa3072.is_rsa());
    assert!(!AsymmetricAlgorithm::Rsa3072.is_ecdsa());
    assert!(AsymmetricAlgorithm::Rsa4096.is_rsa());
    assert!(!AsymmetricAlgorithm::Rsa4096.is_ecdsa());

    // ECDSA algorithms
    assert!(!AsymmetricAlgorithm::EcdsaP256.is_rsa());
    assert!(AsymmetricAlgorithm::EcdsaP256.is_ecdsa());
    assert!(!AsymmetricAlgorithm::EcdsaP384.is_rsa());
    assert!(AsymmetricAlgorithm::EcdsaP384.is_ecdsa());
    assert!(!AsymmetricAlgorithm::EcdsaP521.is_rsa());
    assert!(AsymmetricAlgorithm::EcdsaP521.is_ecdsa());
}

#[test]
fn test_algorithm_display_formatting() {
    // Symmetric algorithms
    assert_eq!(format!("{}", SymmetricAlgorithm::Aes128Cbc), "AES-128-CBC");
    assert_eq!(format!("{}", SymmetricAlgorithm::Aes256Gcm), "AES-256-GCM");

    // Asymmetric algorithms
    assert_eq!(format!("{}", AsymmetricAlgorithm::Rsa2048), "RSA-2048");
    assert_eq!(format!("{}", AsymmetricAlgorithm::EcdsaP256), "ECDSA-P256");
    assert_eq!(format!("{}", AsymmetricAlgorithm::EcdsaP521), "ECDSA-P521");

    // Hash algorithms
    assert_eq!(format!("{}", HashAlgorithm::Sha256), "SHA-256");
    assert_eq!(format!("{}", HashAlgorithm::Sha512), "SHA-512");

    // TLS versions
    assert_eq!(format!("{}", TlsVersion::Tls12), "TLS 1.2");
    assert_eq!(format!("{}", TlsVersion::Tls13), "TLS 1.3");
}

#[test]
fn test_custom_algorithm_policy() {
    // Create a custom policy with higher minimums
    let policy = AlgorithmPolicy {
        block_non_fips: true,
        min_rsa_bits: 3072,
        min_ecc_bits: 384,
        min_tls_version: TlsVersion::Tls13,
        allow_sha1_legacy: false,
    };

    // RSA 2048 should now fail
    assert!(policy.validate_rsa_key_size(2048).is_err());
    // RSA 3072 should pass
    assert!(policy.validate_rsa_key_size(3072).is_ok());

    // ECC 256 should now fail
    assert!(policy.validate_ecc_key_size(256).is_err());
    // ECC 384 should pass
    assert!(policy.validate_ecc_key_size(384).is_ok());

    // TLS 1.2 should now fail
    assert!(policy.validate_tls_version(TlsVersion::Tls12).is_err());
    // TLS 1.3 should pass
    assert!(policy.validate_tls_version(TlsVersion::Tls13).is_ok());
}

#[test]
fn test_algorithm_validator_with_custom_policy() {
    let policy = AlgorithmPolicy {
        block_non_fips: true,
        min_rsa_bits: 4096,
        min_ecc_bits: 521,
        min_tls_version: TlsVersion::Tls13,
        allow_sha1_legacy: false,
    };

    let validator = AlgorithmValidator::with_policy(policy);

    // RSA 2048 and 3072 should fail with this policy
    assert!(validator
        .validate_asymmetric_full(AsymmetricAlgorithm::Rsa2048)
        .is_err());
    assert!(validator
        .validate_asymmetric_full(AsymmetricAlgorithm::Rsa3072)
        .is_err());
    // RSA 4096 should pass
    assert!(validator
        .validate_asymmetric_full(AsymmetricAlgorithm::Rsa4096)
        .is_ok());

    // ECC P-256 and P-384 should fail
    assert!(validator
        .validate_asymmetric_full(AsymmetricAlgorithm::EcdsaP256)
        .is_err());
    assert!(validator
        .validate_asymmetric_full(AsymmetricAlgorithm::EcdsaP384)
        .is_err());
    // ECC P-521 should pass
    assert!(validator
        .validate_asymmetric_full(AsymmetricAlgorithm::EcdsaP521)
        .is_ok());
}

#[test]
fn test_non_fips_mode_allows_all() {
    let mut policy = AlgorithmPolicy::default();
    policy.block_non_fips = false;

    // All algorithms should be allowed when blocking is disabled
    assert!(policy.check_algorithm_name("3DES").is_ok());
    assert!(policy.check_algorithm_name("MD5").is_ok());
    assert!(policy.check_algorithm_name("SHA1").is_ok());
    assert!(policy.validate_rsa_key_size(1024).is_ok());
    assert!(policy.validate_ecc_key_size(192).is_ok());
}
