# EST Operations

This guide provides detailed information about all EST operations supported by the library.

## Overview

EST (Enrollment over Secure Transport) defines several operations for certificate management. This library implements all mandatory and optional operations from RFC 7030.

## Operation Categories

### Mandatory Operations

These operations MUST be supported by all EST servers:

- **Distribution of CA Certificates** (`/cacerts`)
- **Simple Enrollment** (`/simpleenroll`)
- **Simple Re-enrollment** (`/simplereenroll`)

### Optional Operations

These operations MAY be supported by EST servers:

- **CSR Attributes** (`/csrattrs`)
- **Server-Side Key Generation** (`/serverkeygen`)
- **Full CMC** (`/fullcmc`)

---

## CA Certificates (`/cacerts`)

Retrieve the current CA certificates from the EST server.

### Usage

```rust
let ca_certs = client.get_ca_certs().await?;

println!("Retrieved {} CA certificate(s)", ca_certs.len());

for cert in ca_certs.iter() {
    println!("Issuer: {:?}", cert.tbs_certificate.issuer);
    println!("Subject: {:?}", cert.tbs_certificate.subject);
}
```

### Response

Returns a `CaCertificates` struct containing a collection of X.509 certificates.

```rust
pub struct CaCertificates {
    certificates: Vec<x509_cert::Certificate>,
}

impl CaCertificates {
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn iter(&self) -> impl Iterator<Item = &Certificate>;
}
```

### RFC Reference

- RFC 7030 Section 4.1: Distribution of CA Certificates
- Content-Type: `application/pkcs7-mime`
- Format: PKCS#7 certs-only structure

### Use Cases

- Initial trust establishment
- CA certificate rollover
- Verifying certificate chains

---

## Simple Enrollment (`/simpleenroll`)

Request a new certificate from the EST server.

### Usage

```rust
use usg_est_client::{csr::CsrBuilder, EnrollmentResponse};

// Generate CSR
let (csr_der, key_pair) = CsrBuilder::new()
    .common_name("device.example.com")
    .organization("Example Corp")
    .build()?;

// Submit enrollment request
match client.simple_enroll(&csr_der).await? {
    EnrollmentResponse::Issued { certificate } => {
        println!("Certificate issued!");
        // Save certificate and key_pair
    }
    EnrollmentResponse::Pending { retry_after } => {
        println!("Pending approval. Retry after {} seconds", retry_after);
        // Implement retry logic
    }
}
```

### Request

- **Method**: POST
- **Content-Type**: `application/pkcs10`
- **Body**: Base64-encoded PKCS#10 CSR
- **Authentication**: Optional (HTTP Basic or TLS client certificate)

### Response

The response can be one of two types:

#### Immediate Issuance (HTTP 200)

Certificate is issued immediately:

```rust
EnrollmentResponse::Issued {
    certificate: x509_cert::Certificate,
}
```

#### Pending Approval (HTTP 202)

Enrollment requires manual approval:

```rust
EnrollmentResponse::Pending {
    retry_after: u64, // Seconds to wait before retrying
}
```

### Handling Pending Enrollments

```rust
use tokio::time::{sleep, Duration};

loop {
    match client.simple_enroll(&csr_der).await? {
        EnrollmentResponse::Issued { certificate } => {
            println!("Certificate issued!");
            break;
        }
        EnrollmentResponse::Pending { retry_after } => {
            println!("Still pending... retrying in {} seconds", retry_after);
            sleep(Duration::from_secs(retry_after)).await;
        }
    }
}
```

### RFC Reference

- RFC 7030 Section 4.2.1: Simple Enrollment

---

## Simple Re-enrollment (`/simplereenroll`)

Renew or rekey an existing certificate.

### Usage

```rust
use usg_est_client::{ClientIdentity, EstClientConfig};

// Load existing certificate and key
let cert_pem = std::fs::read("current-cert.pem")?;
let key_pem = std::fs::read("current-key.pem")?;

// Configure with client certificate authentication
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .client_identity(ClientIdentity::new(cert_pem, key_pem))
    .build()?;

let client = EstClient::new(config).await?;

// Generate new CSR (can use new key for rekeying)
let (csr_der, new_key) = CsrBuilder::new()
    .common_name("device.example.com")
    .build()?;

// Re-enroll
match client.simple_reenroll(&csr_der).await? {
    EnrollmentResponse::Issued { certificate } => {
        println!("Certificate renewed!");
        // Update stored certificate and key
    }
    EnrollmentResponse::Pending { retry_after } => {
        println!("Re-enrollment pending approval");
    }
}
```

### Requirements

- **MUST** use TLS client certificate authentication (the certificate being renewed)
- Subject field and SubjectAltName extension should match the current certificate

### Renewal vs. Rekeying

**Renewal**: Generate CSR with the same key pair
```rust
// Use existing key
let csr_der = CsrBuilder::new()
    .common_name("device.example.com")
    .with_key_pair(existing_key_pair)
    .build_with_key(&existing_key_pair)?;
```

**Rekeying**: Generate CSR with a new key pair
```rust
// Generate new key
let (csr_der, new_key_pair) = CsrBuilder::new()
    .common_name("device.example.com")
    .build()?;
```

### RFC Reference

- RFC 7030 Section 4.2.2: Simple Re-enrollment

---

## CSR Attributes (`/csrattrs`)

Query the server for CSR attribute requirements.

### Usage

```rust
match client.get_csr_attributes().await {
    Ok(attrs) => {
        if attrs.is_empty() {
            println!("No specific requirements");
        } else {
            println!("Server requires {} attributes:", attrs.len());
            for attr in &attrs.attributes {
                println!("  - OID: {}", attr.oid);
            }
        }
    }
    Err(EstError::NotSupported { operation }) => {
        println!("CSR attributes not supported by server");
    }
    Err(e) => return Err(e.into()),
}
```

### Response

```rust
pub struct CsrAttributes {
    pub attributes: Vec<CsrAttribute>,
}

pub struct CsrAttribute {
    pub oid: ObjectIdentifier,
    pub values: Vec<Vec<u8>>,
}
```

### Common Attributes

The library provides OID constants for common attributes:

```rust
use usg_est_client::types::csr_attrs::oids;

// Check for specific attributes
if attrs.contains_oid(&oids::CHALLENGE_PASSWORD) {
    println!("Challenge password required");
}

if attrs.contains_oid(&oids::EXTENSION_REQUEST) {
    println!("Extension request required");
}

// Available OID constants:
// - CHALLENGE_PASSWORD
// - EXTENSION_REQUEST
// - SUBJECT_ALT_NAME
// - KEY_USAGE
// - EXTENDED_KEY_USAGE
// - BASIC_CONSTRAINTS
```

### Applying Attributes to CSR

```rust
// Get attributes from server
let attrs = client.get_csr_attributes().await?;

// Build CSR with attributes
let (csr_der, key_pair) = CsrBuilder::new()
    .common_name("device.example.com")
    .with_attributes(&attrs) // Apply server requirements
    .build()?;
```

### RFC Reference

- RFC 7030 Section 4.5: CSR Attributes

---

## Server-Side Key Generation (`/serverkeygen`)

Request the server to generate a key pair and issue a certificate.

### Usage

```rust
use usg_est_client::ServerKeygenResponse;

// Create a CSR with subject information
// (The public key is just a placeholder)
let (csr_der, _) = CsrBuilder::new()
    .common_name("device.example.com")
    .organization("Example Corp")
    .build()?;

// Request server key generation
let response = client.server_keygen(&csr_der).await?;

println!("Certificate issued!");
println!("Private key encrypted: {}", response.key_encrypted);

// Save the server-generated private key securely
std::fs::write("server-generated-key.der", &response.private_key)?;

// Save the certificate
use der::Encode;
std::fs::write("certificate.der", response.certificate.to_der()?)?;
```

### Response

```rust
pub struct ServerKeygenResponse {
    pub certificate: Certificate,
    pub private_key: Vec<u8>,      // DER-encoded PKCS#8
    pub key_encrypted: bool,
}
```

### Encrypted Private Keys

If `key_encrypted` is true, the private key is wrapped in CMS EnvelopedData:

```rust
use usg_est_client::operations::serverkeygen;

if response.key_encrypted {
    // Check if encrypted
    assert!(serverkeygen::is_key_encrypted(&response.private_key));

    // Decrypt (requires additional implementation)
    // let decrypted_key = serverkeygen::decrypt_private_key(
    //     &response.private_key,
    //     &decryption_key
    // )?;
}
```

### Converting to PEM

```rust
use usg_est_client::operations::serverkeygen::{parse_pkcs8_key, PrivateKeyInfo};

let key_info = parse_pkcs8_key(&response.private_key)?;
let pem = key_info.to_pem();

std::fs::write("private-key.pem", pem)?;
```

### Security Considerations

- Server-generated private keys are transmitted over the network
- Ensure TLS is properly configured with strong cipher suites
- Consider using client-generated keys when possible for better security
- Store private keys securely (encrypted at rest, proper permissions)

### RFC Reference

- RFC 7030 Section 4.4: Server-Side Key Generation

---

## Full CMC (`/fullcmc`)

Support for complex PKI operations using Certificate Management over CMS.

### Usage

```rust
use usg_est_client::{CmcRequest, CmcResponse};

// Create CMC request (requires CMC message construction)
let cmc_request = CmcRequest::new(cmc_data);

// Submit CMC request
let cmc_response = client.full_cmc(&cmc_request).await?;

if cmc_response.is_success() {
    println!("CMC operation successful");
} else {
    println!("CMC operation status: {:?}", cmc_response.status);
}
```

### CMC Status Codes

```rust
use usg_est_client::CmcStatus;

match cmc_response.status {
    CmcStatus::Success => println!("Operation successful"),
    CmcStatus::Failed => println!("Operation failed"),
    CmcStatus::Pending => println!("Operation pending"),
    CmcStatus::NoSupport => println!("Operation not supported"),
    CmcStatus::ConfirmRequired => println!("Confirmation required"),
    CmcStatus::PopRequired => println!("Proof of possession required"),
    CmcStatus::Partial => println!("Partial success"),
}
```

### CMC Operations

Full CMC supports advanced operations:

- Certificate revocation requests
- Certificate modification
- Identity proof mechanisms
- Proof of possession

### RFC Reference

- RFC 7030 Section 4.3: Full CMC
- RFC 5272: Certificate Management over CMS (CMC)

---

## Error Handling

All operations can return errors. Common error patterns:

```rust
use usg_est_client::EstError;

match client.simple_enroll(&csr_der).await {
    Ok(response) => {
        // Handle success
    }
    Err(EstError::AuthenticationRequired { challenge }) => {
        println!("Auth required: {}", challenge);
    }
    Err(EstError::ServerError { status, message }) => {
        println!("Server error {}: {}", status, message);
    }
    Err(EstError::NotSupported { operation }) => {
        println!("Operation {} not supported", operation);
    }
    Err(EstError::TlsConfig(msg)) => {
        println!("TLS configuration error: {}", msg);
    }
    Err(e) => {
        println!("Error: {}", e);
    }
}
```

## Multi-CA Deployments

EST servers can support multiple CAs using labels:

```rust
let config = EstClientConfig::builder()
    .server_url("https://est.example.com")?
    .ca_label("engineering-ca")  // Use specific CA
    .build()?;

// This will use URLs like:
// https://est.example.com/.well-known/est/engineering-ca/cacerts
// https://est.example.com/.well-known/est/engineering-ca/simpleenroll
```

## Next Steps

- Review [Configuration](configuration.md) for advanced options
- Read [Security Considerations](security.md)
- Explore [Examples](examples.md) for complete workflows
