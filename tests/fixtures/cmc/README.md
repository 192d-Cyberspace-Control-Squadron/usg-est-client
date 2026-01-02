# CMC Test Fixtures

This directory contains minimal but valid CMC (Certificate Management over CMS) test fixtures encoded in base64.

## Files

### basic-request.b64

Minimal valid PKIData structure (base64-encoded DER):
- `controlSequence`: empty SEQUENCE
- `reqSequence`: empty SEQUENCE
- `cmsSequence`: empty SEQUENCE
- `otherMsgSequence`: empty SEQUENCE

DER structure (hex): `30 0C 30 00 30 00 30 00 30 00`

### basic-response.b64

Minimal valid PKIResponse structure (base64-encoded DER):
- `controlSequence`: empty SEQUENCE
- `cmsSequence`: empty SEQUENCE
- `otherMsgSequence`: empty SEQUENCE

DER structure (hex): `30 09 30 00 30 00 30 00`

## Usage

These fixtures can be used in integration tests for basic CMC parsing validation:

```rust
use std::fs;
use base64::prelude::*;
use usg_est_client::types::cmc_full::{PkiData, PkiResponse};

// Load and decode PKIData fixture
let b64 = fs::read_to_string("tests/fixtures/cmc/basic-request.b64")?;
let der = BASE64_STANDARD.decode(b64.trim())?;
let pki_data = PkiData::from_der(&der)?;

// Load and decode PKIResponse fixture
let b64 = fs::read_to_string("tests/fixtures/cmc/basic-response.b64")?;
let der = BASE64_STANDARD.decode(b64.trim())?;
let pki_response = PkiResponse::from_der(&der)?;
```

## Notes

- These are **minimal** structures with empty sequences
- They pass basic DER parsing validation
- For full testing, use the PkiDataBuilder to create more complete requests
- See RFC 5272 for full PKIData/PKIResponse structure definitions
