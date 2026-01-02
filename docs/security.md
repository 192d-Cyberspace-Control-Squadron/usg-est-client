# Security Considerations

This document outlines security considerations when using the EST client library.

## Overview

EST (Enrollment over Secure Transport) is designed to provide secure certificate enrollment. However, proper configuration and usage are essential to maintain security.

---

## TLS Requirements

### Minimum TLS Version

RFC 7030 requires TLS 1.2 or higher:

✅ **Supported:**
- TLS 1.2
- TLS 1.3

❌ **Not Supported:**
- TLS 1.0
- TLS 1.1
- SSL (all versions)

The library enforces this automatically through rustls.

### Certificate Validation

**Always validate the EST server's certificate in production:**

✅ **Secure:**
```rust
// Use WebPKI roots
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .build()?;

// Or explicit trust anchors
let ca_cert = std::fs::read("ca.pem")?;
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .trust_explicit(vec![ca_cert])
    .build()?;
```

❌ **Insecure:**
```rust
// NEVER use in production!
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .trust_any_insecure()
    .build()?;
```

### Hostname Verification

The library automatically verifies that the server's certificate matches the hostname in the URL. This prevents man-in-the-middle attacks.

---

## Authentication

### TLS Client Certificate Authentication

**Preferred method** for EST re-enrollment:

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .client_identity(ClientIdentity::new(cert_pem, key_pem))
    .build()?;
```

**Security considerations:**
- Protects private key in transit (only certificate is sent)
- Provides mutual authentication
- Required for re-enrollment operations

**Private Key Protection:**
```rust
// ✅ Load from secure storage with proper permissions
let key_pem = std::fs::read("/etc/pki/private/key.pem")?;

// ❌ Don't hardcode private keys
const KEY: &str = "-----BEGIN PRIVATE KEY-----...";  // BAD!
```

### HTTP Basic Authentication

**Use with caution:**

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .http_auth(HttpAuth {
        username: "user".to_string(),
        password: "password".to_string(),
    })
    .build()?;
```

**Security considerations:**
- Credentials are base64-encoded (not encrypted)
- Only secure when used over TLS
- Avoid hardcoding credentials
- Use environment variables or secure credential stores

**Better approach:**
```rust
use std::env;

let username = env::var("EST_USERNAME")?;
let password = env::var("EST_PASSWORD")?;

let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .http_auth(HttpAuth { username, password })
    .build()?;
```

---

## Bootstrap Mode Security

Bootstrap mode (TOFU - Trust On First Use) requires special care:

### The Bootstrap Problem

Initial enrollment has a chicken-and-egg problem:
- Need certificate to authenticate
- Need to authenticate to get certificate

### Secure Bootstrap Process

**1. Fetch CA certificates (unverified):**
```rust
let bootstrap = BootstrapClient::new("https://est.example.com")?;
let (ca_certs, fingerprints) = bootstrap.fetch_ca_certs().await?;
```

**2. Verify fingerprints out-of-band:**
```rust
// Display fingerprints
for (i, fp) in fingerprints.iter().enumerate() {
    println!("CA {} fingerprint: {}",
        i + 1,
        BootstrapClient::format_fingerprint(fp)
    );
}

// User MUST verify these through alternate channel:
// - Phone call to administrator
// - Pre-configured fingerprint from manufacturer
// - Secure provisioning system
// - Physical label on device/documentation
```

**3. Only proceed after verification:**
```rust
// After out-of-band verification
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .trust_explicit(ca_certs.to_pem_vec()?)
    .build()?;
```

### Bootstrap Threats

**Man-in-the-Middle Attack:**
- Attacker intercepts bootstrap request
- Returns their own CA certificate
- Can issue fraudulent certificates

**Mitigation:**
- Always verify fingerprints out-of-band
- Use multiple verification methods when possible
- Consider pre-provisioning CA certificates

**Bootstrap Authentication:**
```rust
// Even during bootstrap, use authentication if available
let bootstrap_config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .trust_any_insecure()  // Only during bootstrap
    .http_auth(HttpAuth {
        username: device_id,
        password: device_secret,
    })
    .build()?;
```

---

## Private Key Management

### Client-Generated Keys (Recommended)

Generate keys locally and never transmit private keys:

```rust
let (csr_der, key_pair) = CsrBuilder::new()
    .common_name("device.example.com")
    .build()?;

// Private key never leaves the device
let private_key_pem = key_pair.serialize_pem();
```

**Benefits:**
- Private key never transmitted over network
- Better security posture
- Compliance with security policies

### Server-Generated Keys

Use with caution:

```rust
let response = client.server_keygen(&csr_der).await?;
// Private key transmitted from server to client!
```

**Security considerations:**
- Private key is transmitted over TLS
- Depends on TLS security
- May not meet compliance requirements
- Only use when necessary (e.g., HSM scenarios)

**If you must use server keygen:**
```rust
// Check if key is encrypted
if response.key_encrypted {
    // Better, but still requires decryption key management
    let decrypted = decrypt_private_key(
        &response.private_key,
        &decryption_key
    )?;
}

// Store immediately with proper protection
secure_store_private_key(&response.private_key)?;
```

### Key Storage

**File Permissions:**
```bash
# Linux/Unix
chmod 600 /path/to/private-key.pem
chown appuser:appgroup /path/to/private-key.pem

# Verify
ls -l /path/to/private-key.pem
# Should show: -rw------- 1 appuser appgroup
```

**Secure Storage Options:**
- Hardware Security Modules (HSM)
- Trusted Platform Modules (TPM)
- System keychains (macOS Keychain, Windows DPAPI)
- Encrypted filesystems
- Secret management systems (HashiCorp Vault, etc.)

**Avoid:**
- World-readable permissions
- Storing in version control
- Including in container images
- Hardcoding in source code

### PKCS#11 HSM Integration

The library provides PKCS#11 support for hardware-backed key storage through the `pkcs11` feature:

```rust
use usg_est_client::hsm::pkcs11::Pkcs11KeyProvider;
use usg_est_client::hsm::{KeyProvider, KeyAlgorithm};

// Initialize PKCS#11 provider
let provider = Pkcs11KeyProvider::new(
    "/usr/lib/softhsm/libsofthsm2.so",  // PKCS#11 library path
    None,                                // Use first available slot
    "1234",                              // PIN
)?;

// Generate key in HSM
let key_handle = provider
    .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("device-key"))
    .await?;

// Private key never leaves the HSM
```

#### PKCS#11 Security Benefits

✅ **Hardware Security Boundary:**
- Private keys generated and stored within HSM
- Keys marked as non-extractable (CKA_EXTRACTABLE=false)
- Private key operations performed inside secure boundary
- Protection against memory dumps and debugging attacks

✅ **Persistent Storage:**
- Keys persist across application restarts
- Token-based storage (CKA_TOKEN=true)
- Keys survive process termination

✅ **Standards-Based:**
- Industry-standard PKCS#11 (Cryptoki) interface
- Works with multiple HSM vendors
- Portable across different hardware

#### PKCS#11 Security Considerations

**PIN/Password Protection:**

```rust
// ❌ Don't hardcode PINs
let provider = Pkcs11KeyProvider::new(lib, None, "1234")?;  // BAD!

// ✅ Use environment variables or secure credential stores
use std::env;
let pin = env::var("HSM_PIN")?;
let provider = Pkcs11KeyProvider::new(lib, None, &pin)?;
```

**Token Security:**
- Physical security for hardware tokens required
- Protect against unauthorized physical access
- Consider tamper-evident seals for data center HSMs
- Remote attestation for cloud HSMs

**Session Management:**
- Sessions automatically logged out on provider drop
- Avoid long-lived sessions where possible
- Monitor for session hijacking attempts

**Slot Selection:**

```rust
// Verify you're using the correct slot
let provider = Pkcs11KeyProvider::new(
    lib_path,
    Some(0),  // Specify exact slot ID
    &pin,
)?;

let info = provider.provider_info();
println!("Using token: {}", info.name);
```

#### Supported PKCS#11 Implementations

**Tested With:**
- **SoftHSM 2.x**: Software HSM for development/testing
- **YubiHSM 2**: Hardware HSM for production
- **AWS CloudHSM**: Cloud-based HSM service

**Library Paths:**

| Implementation | Typical Library Path |
|---------------|---------------------|
| SoftHSM (Linux) | `/usr/lib/softhsm/libsofthsm2.so` |
| SoftHSM (macOS) | `/usr/local/lib/softhsm/libsofthsm2.so` |
| YubiHSM | `/usr/lib/yubihsm_pkcs11.so` |
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` |

#### PKCS#11 Best Practices

✅ **Key Generation:**

```rust
// Generate keys directly in HSM (never import)
let handle = provider
    .generate_key_pair(
        KeyAlgorithm::EcdsaP256,
        Some("device-key-2025"),  // Descriptive label
    )
    .await?;
```

✅ **Key Lifecycle:**

```rust
// Find existing keys
if let Some(handle) = provider.find_key("device-key").await? {
    // Reuse existing key
} else {
    // Generate new key
    provider.generate_key_pair(algorithm, Some("device-key")).await?
}

// Delete keys when no longer needed
provider.delete_key(&handle).await?;
```

✅ **Monitoring:**
- Log all HSM operations
- Monitor for excessive failed PIN attempts
- Alert on unexpected key generation/deletion
- Track session creation/destruction

❌ **Avoid:**
- Importing externally-generated keys when possible
- Using default PINs (e.g., "0000", "1234")
- Storing PINs in source code or config files
- Allowing unlimited PIN retry attempts

#### PKCS#11 Limitations

Current implementation limitations:

- CSR generation requires manual PKCS#10 construction with HSM keys
- Signing operations return raw signatures (caller must format for CSR)
- No support for key wrapping/unwrapping
- No support for encryption/decryption operations
- Limited to signing and key generation

For production HSM-based CSR generation, you'll need to:

1. Get public key from HSM: `provider.public_key(&handle)`
2. Build PKCS#10 CertificationRequestInfo structure manually
3. Hash the request info
4. Sign hash using: `provider.sign(&handle, &hash)`
5. Encode complete CSR in DER format

#### PKCS#11 Testing

**SoftHSM Setup for Testing:**

```bash
# Install SoftHSM
# Ubuntu/Debian:
sudo apt-get install softhsm2

# macOS:
brew install softhsm

# Initialize token
softhsm2-util --init-token --slot 0 --label "TestToken" --so-pin 0000 --pin 1234

# Verify
softhsm2-util --show-slots
```

**Test Key Generation:**

```rust
#[tokio::test]
async fn test_hsm_key_generation() {
    let provider = Pkcs11KeyProvider::new(
        "/usr/lib/softhsm/libsofthsm2.so",
        Some(0),
        "1234",
    ).unwrap();

    let handle = provider
        .generate_key_pair(KeyAlgorithm::EcdsaP256, Some("test-key"))
        .await
        .unwrap();

    // Verify key is non-extractable
    assert!(!handle.metadata().extractable);
}
```

#### PKCS#11 Security Checklist

Before deploying PKCS#11 HSM integration:

- [ ] HSM library path validated and secured
- [ ] PIN stored securely (not hardcoded)
- [ ] Correct slot/token selected
- [ ] Keys marked as non-extractable (CKA_EXTRACTABLE=false)
- [ ] Keys marked as sensitive (CKA_SENSITIVE=true)
- [ ] Key labels follow naming convention
- [ ] Session logout on provider drop verified
- [ ] Physical security for hardware HSM ensured
- [ ] Monitoring and logging configured
- [ ] PIN retry limits enforced
- [ ] Regular token firmware updates applied
- [ ] Backup/recovery procedures documented

#### References

- [PKCS#11 v2.40 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
- [OASIS PKCS#11 Technical Committee](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11)
- [SoftHSM Documentation](https://www.opendnssec.org/softhsm/)

---

## Certificate Validation

### Validate Issued Certificates

Always verify certificates received from the server:

```rust
match client.simple_enroll(&csr_der).await? {
    EnrollmentResponse::Issued { certificate } => {
        // Verify certificate properties

        // 1. Check expiration
        let not_after = certificate.tbs_certificate.validity.not_after;
        // Verify not_after is reasonable

        // 2. Check subject matches CSR
        let subject = &certificate.tbs_certificate.subject;
        // Verify subject matches what you requested

        // 3. Verify signature chain
        // Use x509-cert or openssl to validate chain

        // Only then save and use the certificate
        save_certificate(&certificate)?;
    }
    _ => {}
}
```

### Certificate Renewal Timing

Renew certificates before expiration:

```rust
use time::OffsetDateTime;

fn should_renew(cert: &Certificate) -> bool {
    let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // Renew if less than 30 days remaining
    let days_remaining = (not_after - now) / 86400;
    days_remaining < 30
}
```

---

## Input Validation

### URL Validation

The library validates URLs, but be aware:

```rust
// ✅ HTTPS is enforced for security
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .build()?;

// ⚠️ HTTP is allowed but insecure
let config = EstClientConfig::builder()
    .server_url("http://est.example.com")?  // No TLS!
    .build()?;
```

**Always use HTTPS in production.**

### CSR Validation

Validate CSR contents before submission:

```rust
use pkcs10::CertificationRequest;
use der::Decode;

// Parse and validate CSR
let csr = CertificationRequest::from_der(&csr_der)?;

// Check subject
let subject = &csr.info.subject;
// Verify it contains expected fields

// Check public key
let public_key = &csr.info.public_key;
// Verify key type and size meet requirements
```

---

## Error Handling

### Don't Expose Sensitive Information

```rust
// ❌ Bad: Exposes internal details
match client.simple_enroll(&csr_der).await {
    Err(e) => {
        println!("Error: {:?}", e);  // May expose sensitive info
    }
    _ => {}
}

// ✅ Good: Generic error message
match client.simple_enroll(&csr_der).await {
    Err(e) => {
        eprintln!("Enrollment failed");
        log::error!("Enrollment error: {}", e);  // Log to secure location
    }
    _ => {}
}
```

### Timing Attacks

Be aware of timing differences:

```rust
// Constant-time comparison for sensitive values
use subtle::ConstantTimeEq;

fn verify_fingerprint(received: &[u8], expected: &[u8]) -> bool {
    received.ct_eq(expected).into()
}
```

---

## Logging and Monitoring

### Secure Logging

```rust
use tracing::{info, warn, error};

// ✅ Log non-sensitive information
info!("Starting enrollment for device {}", device_id);

// ❌ Don't log sensitive data
// error!("Auth failed with password: {}", password);  // BAD!

// ✅ Log sanitized information
warn!("Authentication failed for user: {}", username);
```

### What to Log

**Safe to log:**
- Operation types (enroll, reenroll, etc.)
- Success/failure status
- Device identifiers
- Timestamps
- Error types (not details)

**Never log:**
- Private keys
- Passwords
- Authentication tokens
- Full error details (may contain sensitive data)

### Monitoring

Monitor for security events:
- Repeated authentication failures
- Unusual enrollment patterns
- Certificate validation failures
- TLS errors

---

## Compliance Considerations

### FIPS 140-2

For FIPS compliance, additional configuration may be needed:
- Use FIPS-validated cryptographic modules
- Consider using OpenSSL FIPS module instead of rustls
- Verify all algorithms meet FIPS requirements

### Common Criteria

For Common Criteria evaluation:
- Document all cryptographic operations
- Ensure audit logging meets requirements
- Implement proper key management
- Follow vendor-specific guidelines

---

## Certificate Revocation

Certificate revocation is essential for invalidating certificates before their natural expiration date. This library provides framework support for both CRL (Certificate Revocation Lists) and OCSP (Online Certificate Status Protocol).

### Revocation Overview

The `revocation` feature provides a unified API for checking certificate revocation status:

```rust
use usg_est_client::revocation::{RevocationChecker, RevocationConfig};

// Create revocation checker
let config = RevocationConfig::builder()
    .enable_crl(true)
    .enable_ocsp(true)
    .crl_cache_duration(Duration::from_secs(3600))
    .build();

let checker = RevocationChecker::new(config);

// Check certificate status
let result = checker.check_revocation(&cert, &issuer).await?;

if result.is_revoked() {
    // Certificate has been revoked
}
```

### CRL (Certificate Revocation Lists)

#### How CRL Works

1. CA publishes a signed list of revoked certificates
2. Client downloads CRL from distribution points
3. Client checks if certificate serial number is in the list
4. CRL is cached locally for efficiency

#### CRL Distribution Points

CRLs are referenced in certificates via the CRL Distribution Points extension (OID 2.5.29.31):

```rust
// The library automatically extracts CRL URLs from certificates
let crl_urls = checker.extract_crl_urls(&cert)?;
```

#### CRL Caching

CRLs are cached to minimize network traffic:

```rust
let config = RevocationConfig::builder()
    .crl_cache_duration(Duration::from_secs(3600))  // 1 hour
    .crl_cache_max_entries(100)                     // Max cache size
    .build();
```

**Cache Strategy:**

- CRLs are cached by URL
- Cache entries expire based on `crl_cache_duration`
- Cache is also checked against CRL's `nextUpdate` field
- Manual cache clear: `checker.clear_cache().await`

#### CRL Security Considerations

✅ **Best Practices:**

- Always verify CRL signature against issuing CA
- Check CRL's `thisUpdate` and `nextUpdate` fields
- Use HTTPS for CRL distribution points when possible
- Implement cache refresh before `nextUpdate` time
- Monitor for unusually large CRL sizes (potential DoS)

❌ **Security Risks:**

- Unverified CRL signatures can be forged
- Stale CRLs may not reflect recent revocations
- Large CRLs can cause memory/bandwidth exhaustion
- HTTP CRL distribution points can be tampered with

#### CRL Limitations

- **Scale**: CRLs grow as more certificates are revoked
- **Freshness**: Only as current as last download
- **Bandwidth**: Full CRL download required (Delta CRLs help but add complexity)
- **Privacy**: Client may leak certificate serial numbers to CRL server

### OCSP (Online Certificate Status Protocol)

#### How OCSP Works

1. Client extracts OCSP responder URL from certificate
2. Client sends real-time status request to OCSP responder
3. Responder returns signed status (good/revoked/unknown)
4. Client validates response signature

#### OCSP Responder URLs

OCSP endpoints are referenced in certificates via the Authority Information Access extension (OID 1.3.6.1.5.5.7.1.1):

```rust
// The library automatically extracts OCSP URLs from certificates
let ocsp_url = checker.extract_ocsp_url(&cert)?;
```

#### OCSP Configuration

```rust
let config = RevocationConfig::builder()
    .enable_ocsp(true)
    .ocsp_timeout(Duration::from_secs(10))  // Request timeout
    .build();
```

#### OCSP Security Considerations

✅ **Best Practices:**

- Always verify OCSP response signature
- Use nonces to prevent replay attacks
- Implement reasonable timeouts (5-10 seconds)
- Use HTTPS for OCSP responders
- Validate response timestamps
- Check response's `thisUpdate` and `nextUpdate`

❌ **Security Risks:**
- Unverified OCSP responses can be forged
- Replay attacks without nonces
- Privacy: OCSP request reveals which certificate you're checking
- Availability: Real-time dependency on OCSP responder

#### OCSP Stapling

OCSP Stapling (TLS Certificate Status Request extension) improves privacy and performance:

- Server caches OCSP response
- Server includes ("staples") response in TLS handshake
- Client doesn't need to contact OCSP responder
- Reduces latency and improves privacy

**Note:** OCSP Stapling is handled at the TLS layer and is transparent to the EST client.

### Revocation Strategy

#### Hard-Fail vs Soft-Fail

**Hard-Fail (Strict):**

```rust
let config = RevocationConfig::builder()
    .fail_on_unknown(true)  // Reject if status cannot be determined
    .build();
```

- Pros: Maximum security
- Cons: May block valid certificates if revocation service is unavailable

**Soft-Fail (Permissive):**

```rust
let config = RevocationConfig::builder()
    .fail_on_unknown(false)  // Allow if status cannot be determined
    .build();
```

- Pros: Better availability
- Cons: Revoked certificates may be accepted if revocation service is down

#### Recommended Strategy

For most production systems:

```rust
let config = RevocationConfig::builder()
    .enable_crl(true)        // Enable CRL checking
    .enable_ocsp(true)       // Enable OCSP checking
    .fail_on_unknown(false)  // Soft-fail for availability
    .crl_cache_duration(Duration::from_secs(3600))
    .ocsp_timeout(Duration::from_secs(10))
    .build();
```

**Checking Order:**

1. Try OCSP first (faster, more current)
2. Fall back to CRL if OCSP fails
3. Return Unknown if both fail (soft-fail mode)

#### High-Security Environments

For environments requiring maximum security:

```rust
let config = RevocationConfig::builder()
    .enable_crl(true)
    .enable_ocsp(true)
    .fail_on_unknown(true)   // Hard-fail: reject unknown status
    .ocsp_timeout(Duration::from_secs(5))
    .build();
```

Monitor revocation check failures and have fallback procedures for legitimate outages.

### Implementation Status

The current implementation provides a **framework** for revocation checking:

✅ **Implemented:**

- Configuration API (`RevocationConfig`)
- Cache infrastructure for CRLs
- Timeout handling for OCSP
- Hard-fail/soft-fail policy
- Unified checking API
- Extension OID lookups (CRL Distribution Points, AIA)

⚠️ **Framework Only (Requires Completion for Production):**

- CRL download and HTTP fetching
- CRL parsing (DER/PEM formats)
- CRL signature verification
- Certificate serial number lookup in CRL
- OCSP request formatting (DER encoding)
- OCSP response parsing
- OCSP signature verification
- OCSP nonce handling

#### Production Readiness

To complete the revocation implementation for production use:

1. **Add CRL Parsing Dependency:**

   ```toml
   x509-parser = "0.15"  # or equivalent
   ```

2. **Implement CRL Operations:**
   - Download CRL via HTTP/HTTPS (using `reqwest`)
   - Parse CRL structure (DER/PEM)
   - Verify CRL signature using issuer's public key
   - Search CRL for certificate serial number
   - Check revocation reason and time

3. **Implement OCSP Operations:**
   - Build OCSP request (DER encoding)
   - Send HTTP POST to OCSP responder
   - Parse OCSP response (DER decoding)
   - Verify response signature
   - Include and verify nonces
   - Check response freshness

4. **Additional Security:**
   - Implement certificate serial number extraction
   - Add issuer name/key hash matching
   - Implement response caching for OCSP
   - Add support for OCSP Must-Staple extension

### Monitoring and Alerting

Track these metrics for revocation checking:

```rust
// Example metrics to track
metrics.increment("revocation_checks_total");
metrics.increment(format!("revocation_status_{}", status));  // good/revoked/unknown
metrics.increment("revocation_crl_cache_hits");
metrics.increment("revocation_crl_cache_misses");
metrics.increment("revocation_ocsp_timeouts");
metrics.gauge("revocation_check_duration_ms", duration.as_millis() as f64);
```

**Recommended Alerts:**

- Revocation check failure rate > 5%
- OCSP timeout rate > 10%
- CRL cache miss rate > 80% (may indicate cache issues)
- Revoked certificate detected (critical alert)

### Testing Revocation

#### Test with Revoked Certificates

```rust
#[tokio::test]
async fn test_revoked_certificate_detected() {
    let checker = RevocationChecker::new(RevocationConfig::default());

    // Use a known-revoked test certificate
    let cert = load_test_cert("revoked.pem");
    let issuer = load_test_cert("ca.pem");

    let result = checker.check_revocation(&cert, &issuer).await.unwrap();
    assert!(result.is_revoked());
}
```

#### Mock OCSP Responder

For testing, use a local OCSP responder or wiremock:

```rust
use wiremock::{MockServer, Mock, ResponseTemplate};

#[tokio::test]
async fn test_ocsp_revoked_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_bytes(create_ocsp_revoked_response()))
        .mount(&mock_server)
        .await;

    // Test with mock OCSP responder
}
```

### Security Checklist for Revocation

Before enabling revocation checking in production:

- [ ] CRL signature verification implemented
- [ ] OCSP response signature verification implemented
- [ ] OCSP nonce support enabled
- [ ] Timeouts configured appropriately
- [ ] Hard-fail vs soft-fail policy decided
- [ ] Monitoring and alerting configured
- [ ] CRL cache size limits enforced
- [ ] HTTPS used for CRL/OCSP when possible
- [ ] Fallback strategy documented
- [ ] Regular testing with revoked certificates

### RFC References

- [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) - X.509 PKI Certificate and CRL Profile (Section 5: CRLs)
- [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960) - Online Certificate Status Protocol (OCSP)
- [RFC 6961](https://datatracker.ietf.org/doc/html/rfc6961) - TLS Multiple Certificate Status Request Extension (OCSP Stapling)

---

## Security Checklist

Before deploying to production:

- [ ] TLS 1.2+ enforced
- [ ] Server certificate validation enabled
- [ ] No use of `trust_any_insecure()`
- [ ] Appropriate authentication method configured
- [ ] Private keys stored securely with proper permissions
- [ ] Credentials not hardcoded
- [ ] Bootstrap fingerprints verified out-of-band
- [ ] Certificate validation implemented
- [ ] Proper error handling (no sensitive info exposure)
- [ ] Secure logging configured
- [ ] Security monitoring in place
- [ ] Renewal automation configured
- [ ] Incident response plan documented

---

## Reporting Security Issues

If you discover a security vulnerability in this library:

1. **Do not** open a public GitHub issue
2. Email security details to the maintainers
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

---

## Additional Resources

- [RFC 7030 - EST Protocol](https://datatracker.ietf.org/doc/html/rfc7030)
- [RFC 8446 - TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [OWASP Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [NIST Guidelines on Certificate Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
