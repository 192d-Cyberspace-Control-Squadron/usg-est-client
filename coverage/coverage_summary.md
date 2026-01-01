# Test Coverage Summary

**Overall Coverage: 26.21%** (232/885 lines covered)

## Coverage by Module

| Module | Coverage | Lines Covered | Total Lines | Priority |
|--------|----------|---------------|-------------|----------|
| src/client.rs | 0.00% | 0/162 | 162 | 🔴 HIGH |
| src/types/mod.rs | 0.00% | 0/14 | 14 | 🔴 HIGH |
| src/operations/reenroll.rs | 0.00% | 0/15 | 15 | 🔴 HIGH |
| src/operations/cacerts.rs | 10.71% | 3/28 | 28 | 🟡 MEDIUM |
| src/tls.rs | 13.33% | 12/90 | 90 | 🟡 MEDIUM |
| src/types/csr_attrs.rs | 17.57% | 13/74 | 74 | 🟡 MEDIUM |
| src/types/pkcs7.rs | 21.88% | 14/64 | 64 | 🟡 MEDIUM |
| src/operations/fullcmc.rs | 28.57% | 8/28 | 28 | 🟢 LOW |
| src/config.rs | 33.68% | 32/95 | 95 | 🟢 LOW |
| src/types/cmc.rs | 34.21% | 13/38 | 38 | 🟢 LOW |
| src/bootstrap.rs | 40.26% | 31/77 | 77 | 🟢 LOW |
| src/operations/serverkeygen.rs | 42.86% | 9/21 | 21 | 🟢 LOW |
| src/error.rs | 48.48% | 16/33 | 33 | 🟢 LOW |
| src/csr.rs | 53.10% | 60/113 | 113 | 🟢 LOW |
| src/operations/csrattrs.rs | 63.16% | 12/19 | 19 | ✅ GOOD |
| src/operations/enroll.rs | 64.29% | 9/14 | 14 | ✅ GOOD |

## Why Coverage is Lower Than Expected

The low coverage (26.21%) is primarily due to:

1. **No Integration Tests**: The project has 39 unit tests but no integration tests that actually call the main `EstClient` methods
2. **Client Module Untested**: `src/client.rs` (162 lines) has 0% coverage - this is the main public API
3. **Async Code**: Many functions are async and require mock HTTP servers to test properly
4. **Network Operations**: Real EST operations require a live server or complex mocking

## What IS Tested (Unit Tests)

Currently tested with good coverage:
- ✅ CSR building and validation (53%)
- ✅ Error handling and display (48%)
- ✅ Configuration builder patterns (34%)
- ✅ Bootstrap fingerprint operations (40%)
- ✅ Type conversions and parsing helpers (34-64%)

## What NEEDS Testing (Integration Tests)

Areas with 0% coverage that need integration tests:
- 🔴 `EstClient` HTTP operations (all async methods)
- 🔴 TLS configuration and connection setup
- 🔴 PKCS#7/CMS parsing from real responses
- 🔴 Multipart response parsing (server keygen)
- 🔴 Error handling for HTTP errors
- 🔴 Retry logic for pending enrollments

## Recommendations

### Immediate Actions
1. **Add Mock Server Tests**: Use `wiremock` (already in dev-dependencies) to test EstClient methods
2. **Test Error Paths**: Add tests for HTTP errors, authentication failures, invalid responses
3. **Test Response Parsing**: Add fixtures for PKCS#7, multipart, and CMC responses

### Coverage Goals
- **Target**: 70-80% for library code
- **Minimum**: 60% for public API (EstClient methods)
- **Current**: 26.21% overall

### Test Files to Add
1. `tests/client_integration.rs` - EstClient with mock server
2. `tests/fixtures/` - Sample EST responses (PKCS#7, multipart, etc.)
3. `tests/error_handling.rs` - Error scenarios
4. `tests/retry_logic.rs` - Pending enrollment retry

## Note

The current 39 unit tests are valuable for testing:
- Pure functions (CSR building, fingerprint computation)
- Type conversions
- Configuration validation
- Error type construction

However, the main value proposition of this library (EST operations) requires integration tests with mocked HTTP responses.
