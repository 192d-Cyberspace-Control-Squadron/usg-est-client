# Code Coverage Summary

**Last Updated**: 2026-01-01
**Coverage Tool**: cargo-tarpaulin

## Overall Coverage

**55.82%** coverage (494/885 lines covered)

## Coverage by Module

| Module | Covered/Total | Percentage |
|--------|---------------|------------|
| src/bootstrap.rs | 54/77 | 70.13% |
| src/client.rs | 109/162 | 67.28% |
| src/error.rs | 27/33 | 81.82% |
| src/types/pkcs7.rs | 40/64 | 62.50% |
| src/csr.rs | 65/113 | 57.52% |
| src/config.rs | 52/95 | 54.74% |
| src/types/csr_attrs.rs | 39/74 | 52.70% |
| src/tls.rs | 45/90 | 50.00% |
| src/types/cmc.rs | 19/38 | 50.00% |
| src/types/mod.rs | 3/14 | 21.43% |
| src/operations/csrattrs.rs | 12/19 | 63.16% |
| src/operations/enroll.rs | 9/14 | 64.29% |
| src/operations/serverkeygen.rs | 9/21 | 42.86% |
| src/operations/fullcmc.rs | 8/28 | 28.57% |
| src/operations/reenroll.rs | 0/15 | 0.00% |
| src/operations/cacerts.rs | 3/28 | 10.71% |

## Test Suite Breakdown

### Unit Tests (39 tests)
- bootstrap: 3 tests
- config: 0 tests
- csr: 6 tests
- operations: 11 tests
- types: 17 tests
- tls: 2 tests

### Integration Tests (80 tests)
- Infrastructure: 2 tests
- Operations: 25 tests
  - cacerts: 5 tests
  - enrollment: 9 tests
  - re-enrollment: 3 tests
  - CSR attributes: 4 tests
  - server key generation: 2 tests
  - full CMC: 2 tests
- Authentication: 11 tests
  - TLS client certificates: 6 tests
  - HTTP Basic auth: 5 tests
- TLS Configuration: 21 tests
  - Config tests: 11 tests
  - Bootstrap/TOFU: 10 tests
- Error Handling: 21 tests
  - Network errors: 8 tests
  - Protocol errors: 9 tests
  - Retry logic: 4 tests

**Total Tests**: 119 tests (all passing)

## Coverage Progress

### Phase 10.1 Impact
- **Before**: 26.21% (232/885 lines)
- **After**: 55.82% (494/885 lines)
- **Improvement**: +29.61 percentage points (+113% increase)

## Areas Needing Coverage

### High Priority (Core Operations <50%)
1. **src/operations/reenroll.rs** (0%) - No coverage yet
2. **src/operations/cacerts.rs** (10.71%) - Critical operation
3. **src/operations/fullcmc.rs** (28.57%) - CMC support
4. **src/operations/serverkeygen.rs** (42.86%) - Server key generation

### Medium Priority (Infrastructure <50%)
1. **src/types/mod.rs** (21.43%) - Type definitions
2. **src/tls.rs** (50.00%) - TLS handling

### Notes
- Operations modules have lower coverage because they primarily contain
  integration code that's tested through end-to-end scenarios
- Some operations (reenroll, fullcmc, serverkeygen) are tested via
  integration tests but those paths aren't fully exercised yet
- Bootstrap and error handling modules have excellent coverage (>70%)

## Next Steps for Coverage Improvement

1. Add integration tests that exercise re-enrollment flows
2. Create tests for full CMC operations
3. Improve server key generation test coverage
4. Add more cacerts operation edge cases
5. Target: 70-80% overall coverage

## Running Coverage Locally

```bash
# Generate HTML coverage report
cargo tarpaulin --out Html --output-dir coverage --skip-clean --timeout 300 --exclude-files 'tests/*'

# View report
open coverage/tarpaulin-report.html
```

## CI/CD Integration

Coverage reports are generated automatically on:
- Push to main branch
- Pull request creation
- Manual workflow dispatch

Reports are uploaded to the Actions artifacts and can be viewed in the GitHub Actions summary.
