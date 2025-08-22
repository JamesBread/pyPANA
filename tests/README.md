# pyPANA Test Suite Documentation

This directory contains all test files for the pyPANA v2.3.0 implementation.

## Quick Start

### Running Core Tests

```bash
# From project root - run main compatibility test
python3 tests/test_compatibility.py

# Run protocol flow tests
python3 tests/test_protocol_flow.py

# Run simple authentication test
python3 tests/test_simple_auth.py
```

## Test Categories

### 1. Core Compatibility Tests (4 tests)
Essential tests for v2.3.0 RFC 5191 compliance and basic functionality.

- **test_compatibility.py** - Main v2.3.0 compatibility verification
- **test_protocol_flow.py** - PANA protocol message format tests
- **test_simple_auth.py** - Simple authentication flow test
- **test_e2e.py** - End-to-end testing with v2.3.0 fixes

### 2. OpenPANA Interoperability (3 tests)
Tests for compatibility with OpenPANA implementation.

- **test_openpana_fixed.py** - OpenPANA compatibility with v2.3.0 fixes
- **test_pypana_paa_openpana.py** - pyPANA PAA server for OpenPANA PaC testing
- **test_pypana_complete.py** - Complete pyPANA ↔ pyPANA testing

### 3. Cryptographic Tests (3 tests)
Verification of cryptographic operations and AVP handling.

- **test_auth_avp.py** - AUTH AVP calculation and verification
- **test_crypto_algorithms.py** - Cryptographic algorithm tests
- **test_avp_format.py** - AVP format validation tests

### 4. RFC Compliance Tests (2 tests)
Tests ensuring compliance with relevant RFCs.

- **test_rfc6786_compliance.py** - RFC 6786 AVP encryption compliance
- **test_rfc_compliant_reauth.py** - RFC compliant re-authentication

### 5. Integration Test (1 test)
Tests for various integration scenarios.

- **test_pana.py** - Basic PANA protocol tests

## Test Scripts

Shell scripts for automated testing:

- **run_final_test.sh** - Final test execution script
- **run_openpana_test.sh** - OpenPANA interoperability test
- **run_pypana_paa_test.sh** - pyPANA PAA test script
- **test_final_interop.sh** - Final interoperability test
- **test_pana_radius.sh** - PANA-RADIUS integration test
- **test_simple.sh** - Simple test execution
- **test_interop.sh** - Interoperability test

## Running Tests

### Run All Active Tests
```bash
cd tests
for test in test_*.py; do
    echo "Running $test..."
    python3 "$test"
done
```

### OpenPANA Interoperability Testing
```bash
# Terminal 1: Start pyPANA PAA
python3 tests/test_pypana_paa_openpana.py --bind 127.0.0.1 --port 5555

# Terminal 2: Run OpenPANA PaC
openpac -i 127.0.0.1 -p 5555 -t eap-tls
```

### Individual Test Examples

```bash
# Test v2.3.0 compatibility
python3 tests/test_compatibility.py

# Test protocol message formats
python3 tests/test_protocol_flow.py

# Test AUTH AVP calculation
python3 tests/test_auth_avp.py

# Test RFC 6786 compliance
python3 tests/test_rfc6786_compliance.py
```

## Test Status

All 13 active tests are verified to work with pyPANA v2.3.0:
- ✅ Core compatibility tests pass
- ✅ OpenPANA interoperability at protocol level
- ✅ Cryptographic operations verified
- ✅ RFC compliance validated
- ✅ Integration tests functional

## Removed Tests

The following test files were removed as they only tested experimental or test-specific implementations:
- `test_eap_tls_integration.py` - Tested experimental EAP-TLS implementation
- `test_eap_fragmentation.py` - Tested unused fragmentation module
- `test_cert_validation.py` - Tested test-specific secure handler

The main implementation uses `eap_tls_factory.py` with `eap_tls_pyopenssl.py` or `eap_tls.py`.

## Requirements

- Python 3.7+
- pyPANA dependencies installed
- OpenPANA tools (optional, for interop testing)
- X.509 certificates in `certs/` directory

## Notes

- All tests import from parent directory modules
- Tests are designed for v2.3.0 RFC 5191 compliant implementation
- OpenPANA interop tests require OpenPANA installation
- Focus is on core functionality and compatibility