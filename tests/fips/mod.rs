// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 U.S. Federal Government (in countries where recognized)

//! FIPS 140-2 Compliance Test Suite
//!
//! This test suite validates FIPS 140-2 compliance features including:
//! - FIPS configuration and validation
//! - Algorithm enforcement
//! - OpenSSL FIPS module integration
//! - FIPS mode detection and activation
//!
//! ## Running FIPS Tests
//!
//! To run the FIPS tests, enable the `fips` feature:
//!
//! ```bash
//! cargo test --features fips --test fips_config_test
//! cargo test --features fips --test algorithm_validation_test
//! ```
//!
//! ## FIPS Module Requirements
//!
//! Some tests are marked with `#[ignore]` because they require:
//! - OpenSSL 3.0+ with FIPS module installed
//! - FIPS module configured (fipsmodule.cnf)
//! - System-wide OpenSSL configuration enabling FIPS
//!
//! To run these tests:
//!
//! ```bash
//! cargo test --features fips -- --ignored
//! ```
//!
//! ## Test Coverage
//!
//! - **Configuration Tests**: FipsConfig builder, validation, defaults
//! - **Algorithm Tests**: Symmetric, asymmetric, hash algorithms
//! - **Key Size Tests**: RSA and ECC minimum key sizes
//! - **TLS Version Tests**: TLS 1.2/1.3 requirements
//! - **OID Validation Tests**: Signature algorithm OIDs
//! - **Policy Tests**: Custom policies, blocking, legacy mode

#![cfg(feature = "fips")]

mod algorithm_validation_test;
mod fips_config_test;
