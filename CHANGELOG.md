# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Core EST Operations (Phase 1-9)

- RFC 7030 compliant EST client implementation
- All mandatory EST operations: `/cacerts`, `/simpleenroll`, `/simplereenroll`
- Optional EST operations: `/csrattrs`, `/serverkeygen`, `/fullcmc`
- TLS client certificate authentication
- HTTP Basic authentication fallback
- Bootstrap/TOFU mode for initial CA discovery
- Comprehensive error handling and retry logic
- CSR generation helpers (feature-gated with `csr-gen`)

#### Advanced Features (Phase 10.2)

- **Automatic Certificate Renewal** (`renewal` feature)
  - `RenewalScheduler` for background certificate expiration monitoring
  - Configurable renewal thresholds and check intervals
  - Exponential backoff retry logic for failed renewals
  - Event callback system for extensibility
  - See [src/renewal.rs](src/renewal.rs)

- **Certificate Chain Validation** (`validation` feature)
  - RFC 5280 certificate path validation
  - Chain building from end-entity to root CA
  - Trust anchor verification
  - Basic constraints and validity period checking
  - See [src/validation.rs](src/validation.rs)

- **Metrics and Monitoring** (`metrics` feature)
  - Thread-safe metrics collection for EST operations
  - Operation counters (total, success, failed)
  - Duration histograms (min, max, average)
  - TLS handshake metrics
  - Success rate calculations
  - Ready for Prometheus/OpenTelemetry integration
  - See [src/metrics.rs](src/metrics.rs)

- **Certificate Revocation Checking** (`revocation` feature)
  - RevocationChecker with CRL and OCSP support frameworks
  - CRL caching with configurable refresh duration
  - Revocation status checking API
  - Distribution point and OCSP responder URL extraction
  - See [src/revocation.rs](src/revocation.rs)

- **Encrypted Private Key Decryption** (`enveloped` feature)
  - CMS EnvelopedData parsing framework
  - Multi-algorithm support (AES-128/192/256, 3DES-CBC)
  - DecryptionKey validation
  - Support for server-side key generation with encryption
  - See [src/enveloped.rs](src/enveloped.rs)

#### Integration Testing (Phase 10.1)

- Integration tests with wiremock for all EST operations
- Mock EST server test fixtures
- Authentication testing (TLS client cert, HTTP Basic)
- Error handling and retry logic tests
- Code coverage: 55.82% (from initial 26.21%)

### Changed

- License changed from AGPL-3.0 to Apache-2.0
- ROADMAP reorganized: moved SCEP protocol support to "Possible Future Enhancements"
- All new modules are feature-gated for minimal default footprint

### Fixed

- Floating point precision in metrics tests
- Unused import warnings in validation and metrics modules
- Test data length validation in enveloped module

### Security

- All advanced feature modules include Apache 2.0 license headers
- CMS EnvelopedData decryption framework (implementation pending)
- Certificate revocation checking framework (CRL/OCSP parsing pending)

## [0.1.0] - Initial Development

### Project Setup

- Initial project structure
- Core EST client implementation
- Bootstrap mode support
- Basic documentation

---

## Compliance Status

### RFC 7030 (EST Protocol)

- ✅ All mandatory operations implemented
- ✅ All optional operations implemented
- ✅ TLS 1.2+ requirement met
- ✅ Client certificate authentication
- ✅ HTTP Basic authentication
- ✅ Bootstrap/TOFU mode

### Test Coverage

- 56 unit tests (all passing)
- Integration tests for all operations
- 55.82% code coverage

### Feature Flags

- `csr-gen` (default) - CSR generation with rcgen
- `renewal` - Automatic certificate renewal
- `validation` - RFC 5280 certificate chain validation
- `metrics` - EST operation metrics collection
- `revocation` - CRL and OCSP revocation checking
- `enveloped` - CMS EnvelopedData decryption

---

[Unreleased]: https://github.com/johnwillman/usg-est-client/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/johnwillman/usg-est-client/releases/tag/v0.1.0
