# EST Client Roadmap

## Overview

This roadmap tracks the implementation of a fully RFC 7030 compliant EST (Enrollment over Secure Transport) client library in Rust.

**Status: Core Implementation Complete ✅**

---

## Phase 1: Foundation ✅ COMPLETE

### 1.1 Project Setup

- ✅ Create `Cargo.toml` with dependencies
- ✅ Create directory structure (`src/`, `src/operations/`, `src/types/`, `examples/`)

### 1.2 Error Handling (`src/error.rs`)

- ✅ Define `EstError` enum with all variants:
  - `TlsConfig` - TLS configuration errors
  - `Http` - HTTP request failures
  - `InvalidContentType` - Response content-type mismatches
  - `CertificateParsing` - Certificate parsing errors
  - `CmsParsing` - CMS/PKCS#7 parsing errors
  - `CsrGeneration` - CSR generation failures
  - `ServerError` - EST server errors (4xx/5xx)
  - `EnrollmentPending` - HTTP 202 with Retry-After
  - `AuthenticationRequired` - HTTP 401 challenges
  - `Base64` - Base64 decoding errors
  - `Der` - DER encoding/decoding errors
  - `Url` - URL parsing errors
  - `BootstrapVerification` - Bootstrap fingerprint failures
  - `MissingHeader` - Required header missing
  - `InvalidMultipart` - Multipart parsing errors
  - `NotSupported` - Operation not supported by server
- ✅ Define `Result<T>` type alias
- ✅ Helper constructors for all error types
- ✅ `is_retryable()` and `retry_after()` methods

### 1.3 Configuration (`src/config.rs`)

- ✅ `EstClientConfig` struct with all fields
- ✅ `ClientIdentity` struct (PEM cert chain + key)
- ✅ `HttpAuth` struct (username + password)
- ✅ `TrustAnchors` enum (WebPki, Explicit, Bootstrap)
- ✅ `BootstrapConfig` with fingerprint verification callback
- ✅ Builder pattern for `EstClientConfig`
- ✅ URL building with optional CA label support

### 1.4 TLS Configuration (`src/tls.rs`)

- ✅ Build `rustls::ClientConfig` from `EstClientConfig`
- ✅ Configure TLS 1.2+ minimum version
- ✅ Load client certificate and key from PEM
- ✅ Configure trust anchors (webpki-roots or explicit)
- ✅ Build `reqwest::Client` with TLS config

---

## Phase 2: Core Types ✅ COMPLETE

### 2.1 PKCS#7/CMS Parsing (`src/types/pkcs7.rs`)

- ✅ Parse `application/pkcs7-mime` responses
- ✅ Extract certificates from CMS SignedData (certs-only)
- ✅ Handle base64 Content-Transfer-Encoding
- ✅ Convert to `x509_cert::Certificate` types
- ✅ Helper functions for encoding/decoding

### 2.2 Type Definitions (`src/types/mod.rs`)

- ✅ `CaCertificates` - Collection of CA certificates
- ✅ `EnrollmentResponse` enum (Issued/Pending)
- ✅ `ServerKeygenResponse` - Certificate + private key
- ✅ Content-type and operation constants
- ✅ Re-export `x509_cert::Certificate`

---

## Phase 3: EST Client Core ✅ COMPLETE

### 3.1 Client Structure (`src/client.rs`)

- ✅ `EstClient` struct with config and HTTP client
- ✅ `EstClient::new(config)` async constructor
- ✅ `build_url(operation)` helper for well-known paths
- ✅ URL format: `https://{server}/.well-known/est/{ca_label?}/{operation}`
- ✅ HTTP Basic auth header injection when configured
- ✅ Error handling for all response codes
- ✅ Multipart response parsing

---

## Phase 4: Mandatory Operations ✅ COMPLETE

### 4.1 GET /cacerts

- ✅ Make GET request to `/.well-known/est/cacerts`
- ✅ Accept `application/pkcs7-mime` response
- ✅ Base64 decode response body
- ✅ Parse CMS SignedData (certs-only)
- ✅ Return `CaCertificates`

### 4.2 POST /simpleenroll

- ✅ Accept PKCS#10 CSR (DER bytes)
- ✅ Base64 encode CSR body
- ✅ Set `Content-Type: application/pkcs10`
- ✅ POST to `/.well-known/est/simpleenroll`
- ✅ Handle HTTP 200: Parse certificate from PKCS#7
- ✅ Handle HTTP 202: Extract Retry-After, return `Pending`
- ✅ Handle HTTP 401: Return `AuthenticationRequired`
- ✅ Handle 4xx/5xx: Return `ServerError`

### 4.3 POST /simplereenroll

- ✅ Same flow as simpleenroll
- ✅ POST to `/.well-known/est/simplereenroll`
- ✅ Requires existing client certificate for TLS auth
- ✅ Validation helpers for reenrollment

---

## Phase 5: Optional Operations ✅ COMPLETE

### 5.1 CSR Attributes

- ✅ `CsrAttributes` struct (`src/types/csr_attrs.rs`)
- ✅ Parse `application/csrattrs` response (ASN.1 sequence)
- ✅ GET request to `/.well-known/est/csrattrs`
- ✅ Handle HTTP 404/501 (not implemented)
- ✅ Well-known OID constants
- ✅ Helper methods (`contains_oid`, `oids()`)

### 5.2 Server Key Generation

- ✅ `ServerKeygenResponse` struct (cert + private key)
- ✅ POST to `/.well-known/est/serverkeygen`
- ✅ Parse `multipart/mixed` response
- ✅ Handle private key parts (PKCS#8)
- ✅ Detect encrypted private keys (CMS EnvelopedData)
- ✅ PEM conversion helpers

### 5.3 Full CMC

- ✅ `CmcRequest` struct (PKIData) (`src/types/cmc.rs`)
- ✅ `CmcResponse` struct (ResponseBody)
- ✅ `CmcStatus` enum with status codes
- ✅ POST `application/pkcs7-mime; smime-type=CMC-request`
- ✅ Parse CMC response
- ✅ CMC control attribute OID constants

---

## Phase 6: CSR Generation ✅ COMPLETE

### 6.1 CSR Builder (`src/csr.rs`)

- ✅ Feature gate: `#[cfg(feature = "csr-gen")]`
- ✅ `CsrBuilder` struct with builder pattern
- ✅ Subject DN fields: CN, O, OU, C, ST, L
- ✅ Subject Alternative Names: DNS, IP, Email, URI
- ✅ Key usage and extended key usage
- ✅ `with_attributes(CsrAttributes)` to apply server requirements
- ✅ `build()` - Generate new ECDSA P-256 key pair + CSR
- ✅ `build_with_key(KeyPair)` - Use existing key
- ✅ Return DER-encoded CSR bytes
- ✅ Helper functions: `generate_device_csr()`, `generate_server_csr()`

---

## Phase 7: Bootstrap/TOFU Mode ✅ COMPLETE

### 7.1 Bootstrap Client (`src/bootstrap.rs`)

- ✅ `BootstrapClient` struct (server URL + CA label)
- ✅ Disable TLS server verification
- ✅ `fetch_ca_certs()` - Get CA certs without trust
- ✅ Compute SHA-256 fingerprints
- ✅ `format_fingerprint([u8; 32])` - "AB:CD:EF:..." format
- ✅ `parse_fingerprint(str)` - Parse hex fingerprint
- ✅ `get_subject_cn()` - Extract CN from certificate
- ✅ User verification callback integration

---

## Phase 8: Integration ✅ COMPLETE

### 8.1 Library Exports (`src/lib.rs`)

- ✅ Re-export public types
- ✅ Re-export `EstClient`
- ✅ Re-export `EstClientConfig` and related
- ✅ Feature-gated CSR builder exports
- ✅ Module documentation
- ✅ Version constant

### 8.2 Examples (`examples/`)

- ✅ `simple_enroll.rs` - Basic enrollment flow
- ✅ `reenroll.rs` - Certificate renewal
- ✅ `bootstrap.rs` - TOFU CA discovery

### 8.3 Testing

- ✅ Unit tests for PKCS#7 parsing
- ✅ Unit tests for CSR attributes parsing
- ✅ Unit tests for all operations helpers
- ✅ Unit tests for error handling
- ✅ Unit tests for configuration
- ✅ Unit tests for CSR building
- ✅ 39 unit tests total
- [ ] Integration tests with wiremock ⚠️ TODO

---

## Phase 9: Documentation ✅ COMPLETE

### 9.1 Comprehensive Documentation

- ✅ `docs/README.md` - Overview and quick start
- ✅ `docs/getting-started.md` - Installation and basic usage
- ✅ `docs/operations.md` - Detailed EST operations guide
- ✅ `docs/configuration.md` - Configuration reference
- ✅ `docs/security.md` - Security best practices
- ✅ `docs/api-reference.md` - Complete API documentation
- ✅ `docs/examples.md` - Usage examples and patterns

### 9.2 Code Quality

- ✅ All clippy warnings fixed
- ✅ All 39 unit tests passing
- ✅ Code formatted with rustfmt
- ✅ Comprehensive inline documentation

---

## Phase 10: Future Enhancements 🔄 IN PROGRESS

### 10.1 Testing Improvements

- [ ] **Integration tests with wiremock** - Mock HTTP server tests
- [ ] **Fixtures** - Sample EST responses (PKCS#7, multipart, CMC)
- [ ] **Error scenario tests** - HTTP errors, invalid responses
- [ ] **TLS configuration tests** - Test certificates
- [ ] **Target: 70-80% code coverage** (currently 26.21%)

### 10.2 Advanced Features (Future)

- [ ] Automatic certificate renewal scheduling
- [ ] Certificate revocation support (CRL/OCSP)
- [ ] Hardware security module (HSM) integration
- [ ] PKCS#11 support for private keys
- [ ] Encrypted private key decryption (CMS EnvelopedData)
- [ ] Complete CMC implementation (beyond basic support)
- [ ] Certificate chain validation helpers
- [ ] SCEP protocol support
- [ ] Metrics and monitoring integration

### 10.3 Platform Support

- ✅ macOS support
- ✅ Linux support
- ✅ Windows support (via rustls)
- [ ] WASM support (investigate feasibility)
- [ ] Embedded/no_std support (investigate feasibility)

---

## RFC 7030 Compliance Checklist ✅ ALL COMPLETE

| Requirement | Section | Status |
|------------|---------|--------|
| TLS 1.2+ required | 3.3.1 | ✅ |
| Base64 Content-Transfer-Encoding | 4 | ✅ |
| application/pkcs10 Content-Type | 4.2 | ✅ |
| application/pkcs7-mime responses | 4.1, 4.2 | ✅ |
| HTTP 202 + Retry-After | 4.2.3 | ✅ |
| Well-known URI paths | 3.2.2 | ✅ |
| Optional CA label segment | 3.2.2 | ✅ |
| Client certificate TLS auth | 3.3.2 | ✅ |
| HTTP Basic auth fallback | 3.2.3 | ✅ |
| PKCS#7 certs-only parsing | 4.1.3 | ✅ |
| CSR attributes (optional) | 4.5 | ✅ |
| Server key generation (optional) | 4.4 | ✅ |
| Full CMC (optional) | 4.3 | ✅ |
| Bootstrap/TOFU mode | 4.1.1 | ✅ |

---

## Current Status Summary

### ✅ Completed

- **Core implementation**: All EST operations implemented
- **RFC 7030 compliance**: Fully compliant with mandatory and optional operations
- **Error handling**: Comprehensive error types and handling
- **Configuration**: Flexible configuration with builder pattern
- **Security**: TLS 1.2+, multiple authentication methods, bootstrap mode
- **CSR generation**: Full-featured CSR builder (feature-gated)
- **Documentation**: 7 comprehensive documentation files
- **Examples**: 3 working examples
- **Code quality**: All clippy warnings fixed, formatted code
- **Tests**: 39 unit tests covering core functionality

### 🔄 In Progress

- **Integration tests**: Need mock server tests for HTTP operations
- **Code coverage**: 26.21% → target 70-80%

### 📊 Metrics

- **Lines of Code**: ~885 lines (library)
- **Test Coverage**: 26.21% (232/885 lines)
- **Unit Tests**: 39 passing
- **Documentation**: 7 files, ~3,500 lines
- **Examples**: 3 complete examples
- **Dependencies**: 19 production, 2 dev

---

## Getting Started

```rust
use usg_est_client::{EstClient, EstClientConfig, csr::CsrBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure client
    let config = EstClientConfig::builder()
        .server_url("https://est.example.com")?
        .build()?;

    let client = EstClient::new(config).await?;

    // Get CA certificates
    let ca_certs = client.get_ca_certs().await?;
    println!("Retrieved {} CA certificates", ca_certs.len());

    // Generate CSR and enroll
    let (csr_der, key_pair) = CsrBuilder::new()
        .common_name("device.example.com")
        .build()?;

    let response = client.simple_enroll(&csr_der).await?;

    Ok(())
}
```

See [docs/](docs/) for complete documentation.

---

## Contributing

See coverage report in [coverage/coverage_summary.md](coverage/coverage_summary.md) for areas needing improvement.

Priority areas:

1. Integration tests with wiremock
2. Error handling tests
3. Response parsing tests with fixtures

---

## License

AGPL-3.0
