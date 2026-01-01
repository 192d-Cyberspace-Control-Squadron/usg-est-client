//! Integration tests for usg-est-client
//!
//! These tests use wiremock to create mock EST servers and test
//! all operations, authentication methods, and error handling.

mod integration;

#[path = "integration/operations/mod.rs"]
mod operations;

#[path = "integration/auth/mod.rs"]
mod auth;

// More test modules will be added:
// mod tls;
// mod errors;
