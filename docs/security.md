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
