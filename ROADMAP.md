# EST Client Roadmap

## Overview

This roadmap outlines the implementation plan for a fully RFC 7030 compliant EST (Enrollment over Secure Transport) client library in Rust.

---

## Phase 1: Foundation

### 1.1 Project Setup
- [x] Create `Cargo.toml` with dependencies
- [ ] Create directory structure (`src/`, `src/operations/`, `src/types/`, `examples/`)

### 1.2 Error Handling (`src/error.rs`)
- [ ] Define `EstError` enum with variants:
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
- [ ] Define `Result<T>` type alias

### 1.3 Configuration (`src/config.rs`)
- [ ] `EstClientConfig` struct:
  - `server_url: Url` - EST server base URL
  - `ca_label: Option<String>` - Optional CA label for multi-CA
  - `client_identity: Option<ClientIdentity>` - TLS client auth
  - `http_auth: Option<HttpAuth>` - HTTP Basic auth fallback
  - `trust_anchors: TrustAnchors` - Trust configuration
  - `timeout: Duration` - Request timeout
  - `channel_binding: bool` - TLS channel binding
- [ ] `ClientIdentity` struct (PEM cert chain + key)
- [ ] `HttpAuth` struct (username + password)
- [ ] `TrustAnchors` enum:
  - `WebPki` - Mozilla root store
  - `Explicit(Vec<Vec<u8>>)` - Custom CA certs
  - `Bootstrap(BootstrapConfig)` - TOFU mode
- [ ] `BootstrapConfig` with fingerprint verification callback
- [ ] Builder pattern for `EstClientConfig`

### 1.4 TLS Configuration (`src/tls.rs`)
- [ ] Build `rustls::ClientConfig` from `EstClientConfig`
- [ ] Configure TLS 1.2+ minimum version
- [ ] Load client certificate and key from PEM
- [ ] Configure trust anchors (webpki-roots or explicit)
- [ ] Build `reqwest::Client` with TLS config

---

## Phase 2: Core Types

### 2.1 PKCS#7/CMS Parsing (`src/types/pkcs7.rs`)
- [ ] Parse `application/pkcs7-mime` responses
- [ ] Extract certificates from CMS SignedData (certs-only)
- [ ] Handle base64 Content-Transfer-Encoding
- [ ] Convert to `x509_cert::Certificate` types

### 2.2 Type Definitions (`src/types/mod.rs`)
- [ ] `CaCertificates` - Vector of CA certificates
- [ ] `EnrollmentResponse` enum:
  - `Issued(Certificate)` - Immediate issuance
  - `Pending { retry_after: u64 }` - Manual approval required
- [ ] Re-export `x509_cert::Certificate`

---

## Phase 3: EST Client Core

### 3.1 Client Structure (`src/client.rs`)
- [ ] `EstClient` struct with config and HTTP client
- [ ] `EstClient::new(config)` async constructor
- [ ] `build_url(operation)` helper for well-known paths
- [ ] URL format: `https://{server}/.well-known/est/{ca_label?}/{operation}`
- [ ] HTTP Basic auth header injection when configured

---

## Phase 4: Mandatory Operations (RFC 7030 §4.1-4.2)

### 4.1 GET /cacerts (`src/operations/cacerts.rs`)
- [ ] Make GET request to `/.well-known/est/cacerts`
- [ ] Accept `application/pkcs7-mime` response
- [ ] Base64 decode response body
- [ ] Parse CMS SignedData (certs-only)
- [ ] Return `CaCertificates`

### 4.2 POST /simpleenroll (`src/operations/enroll.rs`)
- [ ] Accept PKCS#10 CSR (DER bytes)
- [ ] Base64 encode CSR body
- [ ] Set `Content-Type: application/pkcs10`
- [ ] POST to `/.well-known/est/simpleenroll`
- [ ] Handle HTTP 200: Parse certificate from PKCS#7
- [ ] Handle HTTP 202: Extract Retry-After, return `Pending`
- [ ] Handle HTTP 401: Return `AuthenticationRequired`
- [ ] Handle 4xx/5xx: Return `ServerError`

### 4.3 POST /simplereenroll (`src/operations/reenroll.rs`)
- [ ] Same flow as simpleenroll
- [ ] POST to `/.well-known/est/simplereenroll`
- [ ] Requires existing client certificate for TLS auth

---

## Phase 5: Optional Operations (RFC 7030 §4.3-4.5)

### 5.1 CSR Attributes (`src/types/csr_attrs.rs`, `src/operations/csrattrs.rs`)
- [ ] `CsrAttributes` struct
- [ ] Parse `application/csrattrs` response (ASN.1 sequence)
- [ ] GET request to `/.well-known/est/csrattrs`
- [ ] Handle HTTP 404/501 (not implemented)

### 5.2 Server Key Generation (`src/operations/serverkeygen.rs`)
- [ ] `ServerKeygenResponse` struct (cert + private key)
- [ ] POST to `/.well-known/est/serverkeygen`
- [ ] Parse `multipart/mixed` response:
  - Part 1: `application/pkcs8` (private key, possibly encrypted)
  - Part 2: Certificate
- [ ] Handle encrypted private keys (CMS EnvelopedData)

### 5.3 Full CMC (`src/types/cmc.rs`, `src/operations/fullcmc.rs`)
- [ ] `CmcRequest` struct (PKIData)
- [ ] `CmcResponse` struct (ResponseBody)
- [ ] POST `application/pkcs7-mime; smime-type=CMC-request`
- [ ] Parse CMC response

---

## Phase 6: CSR Generation (Feature-Gated)

### 6.1 CSR Builder (`src/csr.rs`)
- [ ] Feature gate: `#[cfg(feature = "csr-gen")]`
- [ ] `CsrBuilder` struct with builder pattern
- [ ] Subject DN fields: CN, O, OU, C, ST, L
- [ ] Subject Alternative Names: DNS, IP, Email, URI
- [ ] Key usage and extended key usage
- [ ] `with_attributes(CsrAttributes)` to apply server requirements
- [ ] `build()` - Generate new key pair + CSR
- [ ] `build_with_key(KeyPair)` - Use existing key
- [ ] Return DER-encoded CSR bytes

---

## Phase 7: Bootstrap/TOFU Mode

### 7.1 Bootstrap Client (`src/bootstrap.rs`)
- [ ] `BootstrapClient` struct (server URL + CA label)
- [ ] Disable TLS server verification
- [ ] `fetch_ca_certs_unverified()` - Get CA certs without trust
- [ ] Compute SHA-256 fingerprints
- [ ] `format_fingerprint([u8; 32])` - "AB:CD:EF:..." format
- [ ] User verification callback integration

---

## Phase 8: Integration

### 8.1 Library Exports (`src/lib.rs`)
- [ ] Re-export public types
- [ ] Re-export `EstClient`
- [ ] Re-export `EstClientConfig` and related
- [ ] Feature-gated CSR builder exports
- [ ] Module documentation

### 8.2 Examples (`examples/`)
- [ ] `simple_enroll.rs` - Basic enrollment flow
- [ ] `reenroll.rs` - Certificate renewal
- [ ] `bootstrap.rs` - TOFU CA discovery

### 8.3 Testing
- [ ] Unit tests for PKCS#7 parsing
- [ ] Unit tests for CSR attributes parsing
- [ ] Integration tests with wiremock

---

## RFC 7030 Compliance Checklist

| Requirement | Section | Status |
|------------|---------|--------|
| TLS 1.2+ required | 3.3.1 | [ ] |
| Base64 Content-Transfer-Encoding | 4 | [ ] |
| application/pkcs10 Content-Type | 4.2 | [ ] |
| application/pkcs7-mime responses | 4.1, 4.2 | [ ] |
| HTTP 202 + Retry-After | 4.2.3 | [ ] |
| Well-known URI paths | 3.2.2 | [ ] |
| Optional CA label segment | 3.2.2 | [ ] |
| Client certificate TLS auth | 3.3.2 | [ ] |
| HTTP Basic auth fallback | 3.2.3 | [ ] |
| PKCS#7 certs-only parsing | 4.1.3 | [ ] |
| CSR attributes (optional) | 4.5 | [ ] |
| Server key generation (optional) | 4.4 | [ ] |
| Full CMC (optional) | 4.3 | [ ] |
| Bootstrap/TOFU mode | 4.1.1 | [ ] |

---

## Dependencies Summary

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `reqwest` | HTTP client |
| `rustls` | TLS implementation |
| `rustls-pemfile` | PEM parsing |
| `webpki-roots` | Mozilla root CA store |
| `x509-cert` | X.509 certificate parsing |
| `der` | DER encoding/decoding |
| `cms` | CMS/PKCS#7 parsing |
| `pkcs8` | Private key handling |
| `spki` | Subject Public Key Info |
| `const-oid` | OID constants |
| `sha2` | SHA-256 for fingerprints |
| `rcgen` | CSR generation (optional) |
| `base64` | Base64 encoding |
| `thiserror` | Error handling |
| `url` | URL parsing |
| `tracing` | Logging |

---

## API Summary

```rust
// Create client
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")
    .client_identity(cert_pem, key_pem)
    .build()?;
let client = EstClient::new(config).await?;

// Get CA certificates
let ca_certs = client.get_ca_certs().await?;

// Enroll for certificate
let csr = CsrBuilder::new()
    .common_name("device.example.com")
    .build()?;
let response = client.simple_enroll(&csr).await?;
match response {
    EnrollmentResponse::Issued(cert) => { /* use cert */ }
    EnrollmentResponse::Pending { retry_after } => { /* wait and retry */ }
}

// Renew certificate
let response = client.simple_reenroll(&csr).await?;

// Query CSR attributes
let attrs = client.get_csr_attributes().await?;

// Server key generation
let keygen = client.server_keygen(&csr).await?;
```
