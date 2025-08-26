# pyPANA Test Suite Documentation

**Last Updated**: 2025-08-26  
**Version**: 2.3.1

## Overview

This document provides comprehensive documentation for all test files in the pyPANA test suite. Tests are organized by category and include descriptions, usage instructions, and expected outcomes.

## Test File Index

### Core Protocol Tests

#### 1. test_protocol_flow.py
**Purpose**: Validates PANA protocol message formats and flow according to RFC 5191  
**Key Tests**:
- PCI format validation (16 bytes, flags=0x0000, no AVPs)
- Initial PAR format (R|S flags, 20-byte nonce)
- Initial PAN format (S flag, 20-byte nonce)
- AUTH AVP calculation (SHA1-160, 20 bytes)

**Usage**:
```bash
python3 tests/test_protocol_flow.py
```

**Expected Output**:
```
✅ PCI format correct (16 bytes, no AVPs)
✅ PAR format correct (S-bit set, 20-byte nonce)
✅ PAN format correct (S-bit set, 20-byte nonce)
✅ AUTH AVP correct (20 bytes, SHA1-160)
```

#### 2. test_simple_auth.py
**Purpose**: Tests basic PANA authentication flow without full EAP-TLS  
**Key Features**:
- Simplified PAA and PaC implementation
- Basic message exchange validation
- Nonce exchange verification

**Usage**:
```bash
python3 tests/test_simple_auth.py
```

#### 3. test_compatibility.py
**Purpose**: Tests pyPANA ↔ pyPANA compatibility with v2.3.0 fixes  
**Key Features**:
- Spawns PAA and PaC processes
- Verifies authentication completion
- Checks algorithm selection (SHA1 preference)

**Note**: Original version with 5-second timeout

#### 4. test_compatibility_fixed.py
**Purpose**: Enhanced compatibility test with better output capture  
**Improvements**:
- Uses threading for better process management
- Real-time output capture with queues
- 8-second timeout for slower systems
- Shows state transitions on failure

**Usage**:
```bash
python3 tests/test_compatibility_fixed.py
```

**Expected Output**:
```
PaC authentication: ✅ SUCCESS
PAA authentication: ✅ SUCCESS
✅ Using SHA1 PRF (value 2)
✅ Using SHA1_160 integrity (value 7)
```

### Cryptographic Tests

#### 5. test_crypto_algorithms.py
**Purpose**: Comprehensive testing of cryptographic algorithms  
**Coverage**:
- PRF algorithms (SHA1, SHA256)
- Integrity algorithms (SHA1-160, SHA256-128)
- Key derivation functions
- HMAC computations
- AES-128-CTR encryption

**Key Tests**:
- RFC 5191 key derivation
- AUTH AVP computation
- Nonce generation
- Algorithm negotiation

#### 6. test_auth_avp.py
**Purpose**: AUTH AVP calculation and verification  
**Tests**:
- SHA1-160 (20 bytes) for OpenPANA compatibility
- SHA256-128 (16 bytes) truncation
- Key derivation from MSK
- Message integrity verification

### AVP and Message Format Tests

#### 7. test_avp_format.py
**Purpose**: AVP format validation according to RFC 5191  
**Tests**:
- AVP header structure (16 bits each: code, flags, length, reserved)
- AVP padding requirements (4-byte alignment)
- Reserved field validation (must be 0)

### RFC Compliance Tests

#### 8. test_rfc_compliance_fixes.py
**Purpose**: Validates all RFC 5191 compliance fixes in v2.3.0  
**Coverage**:
- PCI message format (16 bytes, no AVPs)
- Nonce timing (after S-bit messages)
- I_PAR/I_PAN storage
- Key derivation process
- Sequence number handling

#### 9. test_rfc6786_compliance.py
**Purpose**: RFC 6786 AVP encryption compliance testing  
**Features**:
- Encryption algorithm negotiation
- Encryption-Encap AVP handling
- Key derivation (PANA_PAC_ENCR_KEY, PANA_PAA_ENCR_KEY)
- AES-128-CTR nonce construction
- Encryption policy enforcement

#### 10. test_rfc_compliant_reauth.py
**Purpose**: RFC 5191 compliant re-authentication flow  
**Tests**:
- PNR/PNA message exchange
- A-bit (re-authentication flag) handling
- Session lifetime extension
- Key refresh procedures

### Integration and Interoperability Tests

#### 11. test_openpana_fixed.py
**Purpose**: OpenPANA compatibility testing with v2.3.0 fixes  
**Features**:
- Tests against OpenPANA message formats
- SHA1 algorithm compatibility
- 20-byte nonce handling
- AUTH AVP verification

#### 12. test_pypana_complete.py
**Purpose**: Complete pyPANA ↔ pyPANA authentication test  
**Coverage**:
- Full EAP-TLS handshake
- Key derivation
- State machine transitions
- Session establishment

#### 13. test_pypana_paa_openpana.py
**Purpose**: PAA server for testing with OpenPANA PaC clients  
**Features**:
- OpenPANA-compatible PAA implementation
- SHA1 algorithm preference
- Proper message formatting for OpenPANA

#### 14. test_e2e.py
**Purpose**: End-to-end testing with complete authentication flow  
**Tests**:
- Full protocol sequence
- Error handling
- Timeout scenarios
- Retransmission logic

### Full Test Suite

#### 15. test_pana.py
**Purpose**: Comprehensive PANA protocol test suite  
**Note**: Requires PyOpenSSL for full functionality  
**Coverage**:
- Message creation and parsing
- State machine transitions
- Session management
- Cryptographic operations

## Running Tests

### Run All Core Tests
```bash
# From project root
python3 run_tests.py
```

### Run Specific Test Categories

```bash
# Protocol flow tests
python3 tests/test_protocol_flow.py
python3 tests/test_simple_auth.py

# Compatibility tests
python3 tests/test_compatibility_fixed.py
python3 tests/test_pypana_complete.py

# Cryptographic tests
python3 tests/test_crypto_algorithms.py
python3 tests/test_auth_avp.py

# RFC compliance tests
python3 tests/test_rfc_compliance_fixes.py
python3 tests/test_rfc6786_compliance.py
```

### Run with Debug Output
```bash
# Most tests support --debug flag
python3 tests/test_compatibility.py --debug
```

## Test Requirements

### Dependencies
- Python 3.6+
- cryptography library
- Optional: PyOpenSSL (for test_pana.py)

### Network Requirements
- Tests use localhost (127.0.0.1)
- Ports: 5555-5559 (configurable)
- No root privileges required for test ports

## Expected Test Results

### v2.3.1 Status
✅ **All Core Tests**: PASSING  
✅ **Protocol Flow**: PASSING  
✅ **Compatibility**: PASSING  
✅ **Cryptographic**: PASSING  
✅ **RFC Compliance**: PASSING  

### Known Issues
- Wireshark JSON export shows flags as 0x00 (display bug, actual packets correct)
- PyOpenSSL required for full EAP-TLS MSK export

## Test Development Guidelines

### Adding New Tests
1. Follow existing test structure
2. Include docstrings with purpose and coverage
3. Add to appropriate category in this document
4. Update TEST_CATEGORIZATION.md if needed

### Test Naming Convention
- `test_<feature>_<aspect>.py`
- Use descriptive names
- Include RFC numbers where applicable

## Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Kill existing PANA processes
pkill -f "python.*pana"
```

#### Import Errors
```bash
# Ensure you're in project root
export PYTHONPATH=$PYTHONPATH:.
```

#### PyOpenSSL Not Available
```bash
# Install PyOpenSSL (optional, for enhanced MSK export)
pip install pyopenssl
```

## Test Coverage Summary

| Category | Tests | Status | Coverage |
|----------|-------|--------|----------|
| Protocol Flow | 4 | ✅ | Message formats, sequences |
| Compatibility | 4 | ✅ | pyPANA ↔ pyPANA, OpenPANA |
| Cryptographic | 3 | ✅ | Algorithms, AVPs, keys |
| RFC Compliance | 3 | ✅ | RFC 5191, RFC 6786 |
| Integration | 1 | ✅ | End-to-end flows |

## Version History

### v2.3.1 (2025-08-26)
- Added test_compatibility_fixed.py with improved process handling
- Updated test_protocol_flow.py for PCI flags=0x0000
- Fixed EAP-TLS state machine tests

### v2.3.0 (2025-08-21)
- Major test suite overhaul for RFC 5191 compliance
- Added comprehensive cryptographic tests
- Fixed OpenPANA compatibility tests

## References

- RFC 5191: Protocol for Carrying Authentication for Network Access (PANA)
- RFC 6786: Encrypting the PANA AVPs
- RFC 5216: The EAP-TLS Authentication Protocol