//! Integration tests for usg-est-client
//!
//! These tests use wiremock to create mock EST servers and test
//! all operations, authentication methods, and error handling.

mod integration;

#[path = "integration/operations/mod.rs"]
mod operations;

// More test modules will be added:
// mod auth;
// mod tls;
// mod errors;
