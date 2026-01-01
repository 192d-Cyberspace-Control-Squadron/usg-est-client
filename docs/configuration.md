# Configuration Guide

This guide covers all configuration options for the EST client.

## EstClientConfig

The `EstClientConfig` struct configures the EST client. Use the builder pattern to construct it:

```rust
use usg_est_client::EstClientConfig;

let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .build()?;
```

## Configuration Options

### Server URL (Required)

Specify the EST server URL:

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .build()?;
```

**Notes:**
- Must be a valid HTTPS URL
- Port can be specified: `https://est.example.com:8443`
- Path components are ignored (EST uses well-known URIs)

### CA Label (Optional)

For multi-CA EST servers, specify which CA to use:

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .ca_label("engineering")
    .build()?;
```

This changes the EST endpoints from:
```
/.well-known/est/cacerts
```
to:
```
/.well-known/est/engineering/cacerts
```

### Request Timeout

Set the timeout for HTTP requests (default: 30 seconds):

```rust
use std::time::Duration;

let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .timeout(Duration::from_secs(60))
    .build()?;
```

---

## Authentication

EST servers typically require authentication. The library supports two methods:

### TLS Client Certificate Authentication

Use an existing certificate to authenticate:

```rust
use usg_est_client::ClientIdentity;

let cert_pem = std::fs::read("client-cert.pem")?;
let key_pem = std::fs::read("client-key.pem")?;

let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .client_identity(ClientIdentity::new(cert_pem, key_pem))
    .build()?;
```

**ClientIdentity Format:**
- Certificate: PEM-encoded X.509 certificate (may include chain)
- Private key: PEM-encoded private key (PKCS#8 or traditional format)

**Multiple Certificates (Chain):**
```rust
// Certificate file can contain multiple PEM certificates
let cert_pem = r#"
-----BEGIN CERTIFICATE-----
... client certificate ...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
... intermediate CA ...
-----END CERTIFICATE-----
"#;
```

### HTTP Basic Authentication

Use username and password (fallback when TLS client certificates aren't available):

```rust
use usg_est_client::HttpAuth;

let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .http_auth(HttpAuth {
        username: "device001".to_string(),
        password: "secret".to_string(),
    })
    .build()?;
```

**Security Note:** HTTP Basic auth credentials are base64-encoded (not encrypted). Only use over TLS.

### Combined Authentication

Both methods can be combined (some servers may require both):

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .client_identity(ClientIdentity::new(cert_pem, key_pem))
    .http_auth(HttpAuth {
        username: "user".to_string(),
        password: "pass".to_string(),
    })
    .build()?;
```

---

## Trust Anchors

Configure how the client validates the EST server's TLS certificate.

### WebPKI Roots (Default)

Use Mozilla's root certificate store (via `webpki-roots`):

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .build()?;
```

This is suitable for:
- Public EST servers with publicly-trusted certificates
- Testing with public CAs
- Production when the EST server uses a well-known CA

### Explicit Trust Anchors

Provide specific CA certificates to trust:

```rust
let ca_cert_pem = std::fs::read("est-server-ca.pem")?;

let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .trust_explicit(vec![ca_cert_pem])
    .build()?;
```

**Multiple CA Certificates:**
```rust
let ca1 = std::fs::read("ca1.pem")?;
let ca2 = std::fs::read("ca2.pem")?;

let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .trust_explicit(vec![ca1, ca2])
    .build()?;
```

This is suitable for:
- Private/internal CAs
- Self-signed EST server certificates
- Explicit trust requirements

### Trust Any (Insecure - Testing Only)

Disable certificate verification (INSECURE - for testing only):

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .trust_any_insecure()  // ⚠️ DANGEROUS - testing only!
    .build()?;
```

**WARNING:** This disables all TLS certificate validation. Never use in production!

### Bootstrap Mode

For initial enrollment without pre-established trust, use bootstrap mode:

```rust
use usg_est_client::bootstrap::BootstrapClient;

// Phase 1: Bootstrap - fetch CA certs without verification
let bootstrap = BootstrapClient::new("https://est.example.com")?;
let (ca_certs, fingerprints) = bootstrap.fetch_ca_certs().await?;

// Display fingerprints for out-of-band verification
for (i, fp) in fingerprints.iter().enumerate() {
    println!("CA {} fingerprint: {}",
        i + 1,
        BootstrapClient::format_fingerprint(fp)
    );
}

// Verify fingerprints through alternate channel (phone, email, etc.)
// ...

// Phase 2: Convert to regular client with explicit trust
let ca_pems = ca_certs.to_pem_vec()?;

let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .trust_explicit(ca_pems)
    .build()?;

let client = EstClient::new(config).await?;
```

---

## TLS Configuration

### Minimum TLS Version

The library requires TLS 1.2 or higher (per RFC 7030):

```rust
// TLS 1.2 and 1.3 are automatically supported
// TLS 1.0 and 1.1 are not supported
```

### Cipher Suites

The library uses rustls with secure defaults. Cipher suites are automatically selected based on:
- TLS version negotiated
- Server preferences
- Security best practices

---

## Advanced Configuration

### Custom Verification Callbacks

For bootstrap mode with custom verification:

```rust
use usg_est_client::{EstClientConfig, TrustAnchors, BootstrapConfig};

let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .trust_anchors(TrustAnchors::Bootstrap(BootstrapConfig {
        verify_fingerprint: Box::new(|fingerprint| {
            // Custom verification logic
            let expected = hex::decode("ABCD...").unwrap();
            fingerprint == expected.as_slice()
        }),
    }))
    .build()?;
```

### Channel Binding

Enable TLS channel binding for challenge-password (per RFC 7030 Section 3.5):

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .channel_binding(true)
    .build()?;
```

When enabled, the `tls-unique` channel binding value is included in the CSR challenge-password attribute.

---

## Environment-Specific Configurations

### Development/Testing

```rust
let config = EstClientConfig::builder()
    .server_url("https://localhost:8443")?
    .trust_any_insecure()  // For self-signed certs
    .http_auth(HttpAuth {
        username: "test".to_string(),
        password: "test".to_string(),
    })
    .timeout(Duration::from_secs(10))
    .build()?;
```

### Production with Internal CA

```rust
let ca_cert = include_bytes!("../certs/internal-ca.pem");

let config = EstClientConfig::builder()
    .server_url("https://est.internal.company.com")?
    .trust_explicit(vec![ca_cert.to_vec()])
    .timeout(Duration::from_secs(30))
    .build()?;
```

### Production with Client Certificate

```rust
let cert_pem = std::fs::read("/etc/pki/client-cert.pem")?;
let key_pem = std::fs::read("/etc/pki/client-key.pem")?;

let config = EstClientConfig::builder()
    .server_url("https://est.company.com")?
    .client_identity(ClientIdentity::new(cert_pem, key_pem))
    .timeout(Duration::from_secs(45))
    .build()?;
```

### IoT Device Bootstrap

```rust
use usg_est_client::bootstrap::BootstrapClient;

// Phase 1: Bootstrap with fingerprint verification
let bootstrap = BootstrapClient::new("https://est.iot.company.com")?;
let (ca_certs, fps) = bootstrap.fetch_ca_certs().await?;

// Verify against manufacturer-provided fingerprint
let expected_fp = include_bytes!("../fingerprint.bin");
assert_eq!(&fps[0], expected_fp);

// Phase 2: Regular enrollment
let config = EstClientConfig::builder()
    .server_url("https://est.iot.company.com")?
    .trust_explicit(ca_certs.to_pem_vec()?)
    .http_auth(HttpAuth {
        username: device_id,
        password: device_secret,
    })
    .build()?;
```

---

## Configuration Validation

The builder validates configuration:

```rust
// Invalid URL
let result = EstClientConfig::builder()
    .server_url("not-a-url");
assert!(result.is_err());

// Non-HTTPS URL
let result = EstClientConfig::builder()
    .server_url("http://est.example.com");
// Still accepts but should use HTTPS in production

// Missing server URL
let result = EstClientConfig::builder()
    .build();
assert!(result.is_err());
```

---

## Configuration Examples

### Minimal Configuration

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .build()?;
```

### Complete Configuration

```rust
use usg_est_client::{EstClientConfig, ClientIdentity, HttpAuth};
use std::time::Duration;

let cert_pem = std::fs::read("client.pem")?;
let key_pem = std::fs::read("key.pem")?;
let ca_pem = std::fs::read("ca.pem")?;

let config = EstClientConfig::builder()
    .server_url("https://est.example.com:8443")?
    .ca_label("production")
    .client_identity(ClientIdentity::new(cert_pem, key_pem))
    .http_auth(HttpAuth {
        username: "device001".to_string(),
        password: "secret".to_string(),
    })
    .trust_explicit(vec![ca_pem])
    .timeout(Duration::from_secs(60))
    .channel_binding(true)
    .build()?;

let client = EstClient::new(config).await?;
```

---

## Next Steps

- Review [Security Considerations](security.md)
- Explore [EST Operations](operations.md)
- See [Examples](examples.md) for complete workflows
