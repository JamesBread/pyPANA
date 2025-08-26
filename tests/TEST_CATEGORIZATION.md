# Test File Categorization (v2.3.1)

## 🟢 ACTIVE TESTS (15 Working Tests)

These tests are current, functional, and relevant to pyPANA v2.3.1:

### Core Compatibility (5 tests)
- `test_compatibility.py` - Basic pyPANA ↔ pyPANA compatibility ✅
- `test_compatibility_fixed.py` - Enhanced compatibility with threading (NEW) ✅
- `test_protocol_flow.py` - Protocol message format tests (PCI flags=0x0000) ✅
- `test_simple_auth.py` - Simple authentication flow ✅
- `test_e2e.py` - End-to-end testing ✅

### OpenPANA Interoperability (3 tests)
- `test_openpana_fixed.py` - OpenPANA compatibility with fixes ✅
- `test_pypana_paa_openpana.py` - pyPANA PAA for OpenPANA PaC ✅
- `test_pypana_complete.py` - Complete pyPANA testing ✅

### Cryptographic Tests (3 tests)
- `test_auth_avp.py` - AUTH AVP calculation ✅
- `test_crypto_algorithms.py` - Algorithm verification ✅
- `test_avp_format.py` - AVP format validation ✅

### RFC Compliance (3 tests)
- `test_rfc_compliance_fixes.py` - RFC 5191 compliance validation (NEW) ✅
- `test_rfc6786_compliance.py` - RFC 6786 AVP encryption compliance ✅
- `test_rfc_compliant_reauth.py` - RFC compliant re-authentication ✅

### Integration Test (1 test)
- `test_pana.py` - Basic PANA protocol ✅

## 🔴 REMOVED TESTS

### Recently Removed (Test-only implementations)
- `test_pana_eap_integration.py` - Tested experimental pana_eap_integration.py module
- `test_eap_tls_integration.py` - Tested experimental EAP-TLS implementation
- `test_eap_fragmentation.py` - Tested unused fragmentation module  
- `test_cert_validation.py` - Tested test-specific secure handler

### Previously Moved to outdated/ directory:

### Debug/Development Tests
- `test_auth_debug.py` - AUTH AVP debugging
- `test_debug_paa.py` - PAA debugging
- `test_direct.py` - Direct connection tests

### Older Compatibility Attempts
- `test_final_openpana.py` - Earlier OpenPANA attempt
- `test_openpana_compatible.py` - Older compatibility test
- `test_openpana_compatibility.py` - Duplicate compatibility
- `test_openpana_interop.py` - Earlier interop attempt
- `test_pypana_to_openpaa.py` - Redundant with current tests
- `test_minimal_interop.py` - Minimal interop attempt
- `test_interop_simple.py` - Simple interop test

### Phase-based Tests (Replaced)
- `test_phase1_validation.py` - Phase 1 approach
- `test_phase2_encapsulation.py` - Phase 2 approach
- `test_phase3_enterprise.py` - Phase 3 approach

### Header/Format Tests (Fixed in v2.3.0)
- `test_header_fix.py` - Header format fix
- `test_fixed_header.py` - Fixed header test

### Other Outdated Tests
- `test_basic.py` - Basic tests (replaced)
- `test_structure.py` - Structure validation
- `test_revised_comprehensive.py` - Old comprehensive test
- `test_tls_keyexport.py` - TLS key export
- `test_tls_session_cache.py` - TLS session cache

## Test Organization Summary

- **Active**: 13 tests in `tests/` directory
- **Removed**: 4 test-only implementation tests
- **Outdated**: Tests in `tests/outdated/` directory (if preserved)
- **Scripts**: 7 shell scripts for automation
- **Documentation**: TEST_README.md, README.md, TEST_CATEGORIZATION.md

All active tests are verified to work with pyPANA v2.3.0 and provide comprehensive coverage of:
- RFC 5191 protocol compliance
- OpenPANA interoperability at protocol level
- Cryptographic operations
- EAP-TLS integration
- Basic PANA functionality