# pyPANA Test Suite

This directory contains the current test files for pyPANA v2.3.0 implementation.

## Active Test Files (13 tests)

### Core Compatibility Tests
- `test_compatibility.py` - Main v2.3.0 compatibility verification test
- `test_protocol_flow.py` - PANA protocol message format tests (v2.3.0 compliant)
- `test_simple_auth.py` - Simple authentication flow test
- `test_e2e.py` - End-to-end testing with v2.3.0 fixes

### OpenPANA Interoperability
- `test_openpana_fixed.py` - Tests for OpenPANA compatibility with v2.3.0 fixes
- `test_pypana_paa_openpana.py` - pyPANA PAA server for OpenPANA PaC testing
- `test_pypana_complete.py` - Complete pyPANA ↔ pyPANA testing

### Cryptographic Tests
- `test_auth_avp.py` - AUTH AVP calculation and verification tests
- `test_crypto_algorithms.py` - Cryptographic algorithm tests
- `test_avp_format.py` - AVP format validation tests

### RFC Compliance Tests
- `test_rfc6786_compliance.py` - RFC 6786 AVP encryption compliance tests
- `test_rfc_compliant_reauth.py` - RFC compliant re-authentication tests

### Integration Test
- `test_pana.py` - Basic PANA protocol tests

## Test Scripts
- `run_final_test.sh` - Final test execution script
- `run_openpana_test.sh` - OpenPANA interoperability test script
- `run_pypana_paa_test.sh` - pyPANA PAA test script
- `test_final_interop.sh` - Final interoperability test script
- `test_pana_radius.sh` - PANA-RADIUS integration test script
- `test_simple.sh` - Simple test execution script
- `test_interop.sh` - Interoperability test script

## Running Tests

### Quick Verification (v2.3.0)
From the project root:
```bash
# Run main compatibility verification
python3 tests/test_compatibility.py

# Run protocol flow tests
python3 tests/test_protocol_flow.py

# Run simple authentication test
python3 tests/test_simple_auth.py
```

### OpenPANA Interoperability Testing
```bash
# Start pyPANA PAA for OpenPANA testing
python3 tests/test_pypana_paa_openpana.py --bind 127.0.0.1 --port 5555

# In another terminal, run OpenPANA PaC
openpac -i 127.0.0.1 -p 5555 -t eap-tls
```

### Run All Active Tests
```bash
cd tests
for test in test_*.py; do
    echo "Running $test..."
    python3 "$test"
done
```

## Removed Tests

The following test files were removed as they tested experimental or test-specific implementations:

- `test_pana_eap_integration.py` - Tested experimental pana_eap_integration.py module
- `test_eap_tls_integration.py` - Tested experimental EAP-TLS implementation
- `test_eap_fragmentation.py` - Tested unused eap_fragmentation.py module
- `test_cert_validation.py` - Tested test-specific eap_tls_secure.py handler

These tests were for modules that are not part of the main implementation. The actual pyPANA implementation uses `eap_tls_factory.py` with either `eap_tls_pyopenssl.py` or `eap_tls.py`.

## Test Requirements

- Python 3.7+
- All pyPANA dependencies installed
- For OpenPANA tests: OpenPANA tools installed (optional)
- Certificates in certs/ directory for EAP-TLS tests

## Notes

- All tests use relative imports to access the main pyPANA modules
- Tests are designed to work with v2.3.0 RFC 5191 compliant implementation
- OpenPANA interoperability tests require OpenPANA installation
- The current test suite focuses on core functionality and compatibility