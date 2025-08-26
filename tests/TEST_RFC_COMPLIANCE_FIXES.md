# test_rfc_compliance_fixes.py Documentation

## Overview
Comprehensive test suite for RFC 5191 and RFC 6786 compliance fixes in pyPANA v2.3.0+, focusing on critical security features and protocol correctness.

## Purpose
This test file validates three critical RFC compliance areas:
1. **AUTH AVP Enforcement** - Ensures message integrity after key establishment
2. **Encryption Policy Validation** - Verifies RFC 6786 AVP encryption rules
3. **Anti-Replay Wrap-around** - Tests 32-bit sequence number overflow handling

## Test Categories

### 1. AUTH AVP Enforcement Tests

#### Background
RFC 5191 Section 5.6 mandates AUTH AVP on all messages after PANA_AUTH_KEY establishment.

#### Test Cases

**Test 1: Missing AUTH AVP Rejection**
```python
# Message without AUTH AVP after key establishment
msg = PANAMessage()
msg.msg_type = PANA_AUTH
# ... no AUTH AVP added
# Should be rejected by handle_auth_msg
```

**Test 2: PCI Exception**
```python
# PCI messages are exempt from AUTH AVP requirement
pci_msg = PANAMessage()
pci_msg.msg_type = PANA_CLIENT_INITIATION
# Should be allowed without AUTH AVP
```

**Test 3: Valid AUTH AVP**
```python
# Message with proper AUTH AVP
auth_value = crypto_ctx.compute_auth(msg_data)
msg.add_avp(AVP(AVP_AUTH, 0, auth_value))
# Should be accepted
```

### 2. Encryption Policy Validation Tests

#### Background
RFC 6786 Section 6.1 defines encryption requirements for AVPs:
- **'N' (Never)**: MUST NOT encrypt (e.g., AUTH, NONCE, KEY_ID)
- **'X' (Optional)**: MAY encrypt (e.g., EAP_PAYLOAD, SESSION_LIFETIME)
- **'Y' (Mandatory)**: MUST encrypt (currently none defined)

#### Test Cases

**Test 1: Never-Encrypt Violation**
```python
# Attempting to encrypt AUTH AVP (marked 'N')
encrypted_avp_codes = [AVP_AUTH]
valid, errors = policy.validate_encryption_policy(avps, encrypted_avp_codes)
# Should fail validation
```

**Test 2: Mandatory-Encrypt Violation**
```python
# Simulating mandatory encryption requirement
policy.mandatory_encrypt_avps = {AVP_EAP_PAYLOAD}
encrypted_avp_codes = []  # Nothing encrypted
# Should fail validation
```

**Test 3: Correct Encryption**
```python
# Only optional AVPs encrypted, never-encrypt AVPs in plaintext
encrypted_avp_codes = [AVP_EAP_PAYLOAD]  # 'X' AVP
# Should pass validation
```

### 3. Anti-Replay Wrap-around Tests

#### Background
Sequence numbers are 32-bit unsigned integers that wrap from 0xFFFFFFFF to 0.

#### Test Cases

**Test 1: Normal Progression**
```python
antireplay.check_and_update(100)  # Accept
antireplay.check_and_update(101)  # Accept
antireplay.check_and_update(100)  # Reject (duplicate)
```

**Test 2: Wrap-around Handling**
```python
max_seq = 0xFFFFFFFF
antireplay.check_and_update(max_seq)      # Accept
antireplay.check_and_update(0)            # Accept (wrapped)
antireplay.check_and_update(1)            # Accept
antireplay.check_and_update(max_seq - 100) # Reject (old)
```

**Test 3: Window Management at Boundary**
```python
# Window straddling wrap boundary
antireplay.check_and_update(0xFFFFFFF0)  # Near max
antireplay.check_and_update(0xFFFFFFFF)  # Max
antireplay.check_and_update(0)           # Wrapped
antireplay.check_and_update(10)          # After wrap
```

**Test 4: Large Sequence Jumps**
```python
antireplay.check_and_update(1000)   # Initial
antireplay.check_and_update(2000)   # Large jump (window reset)
antireplay.check_and_update(1500)   # Reject (from old window)
```

## Usage

### Running All Tests
```bash
python3 tests/test_rfc_compliance_fixes.py
```

### Running Individual Test Functions
```python
from test_rfc_compliance_fixes import test_auth_avp_enforcement
test_auth_avp_enforcement()
```

## Expected Output

### Successful Run
```
======================================================================
RFC COMPLIANCE FIX TESTS
======================================================================

=== Testing AUTH AVP Enforcement ===
✓ Test 1: Message without AUTH AVP after key establishment - should be rejected
✓ Test 2: PCI message without AUTH AVP - should be allowed
✓ Test 3: Message with AUTH AVP after key establishment - should be accepted

AUTH AVP enforcement tests passed!

=== Testing Encryption Policy Validation ===
✓ Test 1: Never-encrypt AVP encrypted - correctly rejected
✓ Test 2: Mandatory-encrypt AVP not encrypted - correctly rejected
✓ Test 3: Correct encryption policy - accepted

Encryption policy validation tests passed!

=== Testing Anti-Replay Wrap-around Handling ===
✓ Test 1: Normal sequence progression works
✓ Test 2: Wrap-around from 2^32-1 to 0 handled correctly
✓ Test 3: Window management at wrap boundary works correctly
✓ Test 4: Large sequence jumps trigger window reset

Anti-replay wrap-around tests passed!

======================================================================
ALL RFC COMPLIANCE TESTS PASSED! ✅
======================================================================
```

### Failed Test Output
```
❌ Test failed: <error description>
<stack trace>
```

## Key RFC Requirements Tested

### RFC 5191 Requirements
- Section 5.6: AUTH AVP mandatory after key establishment
- Section 5.2: Sequence number handling
- Section 6.3: PCI message format (no AVPs, flags=0)

### RFC 6786 Requirements
- Section 6.1: AVP encryption policy table
- Section 4: Encryption-Encap AVP handling
- Section 3.1: Key derivation for encryption

## Implementation Files Tested
- `pana_messages.py` - Message and AVP handling
- `pana_crypto.py` - AUTH AVP computation
- `pana_antireplay.py` - Anti-replay mechanism
- `pana_encryption_policy.py` - Encryption policy enforcement

## Common Issues

### AssertionError in Tests
Tests use assertions to validate behavior. Failed assertions indicate RFC non-compliance.

### Import Errors
Ensure the test is run from the project root or tests directory with proper PYTHONPATH.

## Test Coverage
- **Security**: AUTH AVP enforcement, anti-replay protection
- **Compliance**: RFC 5191 and RFC 6786 requirements
- **Edge Cases**: 32-bit wrap-around, window boundaries
- **Error Handling**: Policy violations, invalid configurations

## Related Tests
- `test_rfc6786_compliance.py` - Full RFC 6786 encryption tests
- `test_protocol_flow.py` - Message format compliance
- `test_auth_avp.py` - AUTH AVP calculation details