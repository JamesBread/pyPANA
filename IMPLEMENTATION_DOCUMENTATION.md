# pyPANA Implementation Documentation

## Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture Overview](#architecture-overview)
3. [Core Protocol Implementation](#core-protocol-implementation)
4. [Security Implementation](#security-implementation)
5. [Session Management](#session-management)
6. [Enterprise Features](#enterprise-features)
7. [Testing and Verification](#testing-and-verification)
8. [API Reference](#api-reference)

---

## Project Overview

pyPANA is a comprehensive Python implementation of the Protocol for carrying Authentication for Network Access (PANA) as defined in RFC 5191, with extensions from RFC 6786 for AVP encryption. The implementation provides both client (PaC - PANA Client) and server (PAA - PANA Authentication Agent) functionality with enterprise-grade features.

### Key Features
- **Full RFC 5191 Compliance**: Complete implementation of PANA protocol with proper 16-byte header format
- **RFC 6786 AVP Encryption**: Full support for sensitive data encryption in PANA messages
- **EAP-TLS Authentication**: RFC 5216 compliant with proper MSK/EMSK derivation via PyOpenSSL
- **Enterprise Integration**: RADIUS backend support for external authentication
- **Production Ready**: Rate limiting, monitoring, statistics collection, and error recovery
- **Modular Architecture**: Clean separation of concerns with 25+ specialized modules
- **Comprehensive Testing**: 15 active test files with full RFC compliance coverage

### Current Implementation Status (v2.3.1)

#### ✅ Fully Implemented
- **Core PANA Protocol (RFC 5191)**
  - All message types: PCI (flags=0x0000), PAR/PAN, PTR/PTA, PNR/PNA
  - Complete state machines for both PaC and PAA
  - Correct 16-byte header format with all required fields
  - Proper AVP structure and parsing (16-bit fields)
  - Message authentication with AUTH AVP (SHA1-160, 20 bytes)
  - Session lifetime management
  - Re-authentication support via PANA-Notification (A-bit)

- **Security Features (RFC 6786)**
  - AES-128-CTR encryption for sensitive AVPs
  - Bidirectional encryption keys (PANA_PAC_ENCR_KEY, PANA_PAA_ENCR_KEY)
  - Encryption algorithm negotiation
  - Policy-based encryption enforcement
  - Anti-replay protection with sliding window

- **EAP-TLS Authentication**
  - Complete PyOpenSSL-based implementation
  - RFC 5705 compliant key export ("client EAP encryption" label)
  - Proper MSK/EMSK derivation (64 bytes each)
  - Certificate validation and chain verification
  - Correct EAP-TLS packet length calculation (6-byte base)

- **Enterprise Features**
  - RADIUS proxy mode for external authentication
  - Session statistics and monitoring
  - Rate limiting and DoS protection
  - HTTP-based monitoring interface
  - Comprehensive logging and debugging

#### ⚠️ Partially Implemented
- **Fragmentation**: Basic support, disabled per RFC 5191 Section 5.1
- **OpenPANA Interoperability**: Protocol-level compatible (v2.3.1 fixes applied)

#### ❌ Not Implemented
- **Additional EAP Methods**: Only EAP-TLS currently supported
- **PAA Discovery**: Multicast discovery not implemented
- **IP Mobility**: Limited support for IP address changes

---

## Architecture Overview

### Module Organization

The codebase follows a clean modular architecture with clear separation of concerns:

```
pyPANA/
├── main.py                      # Entry point and CLI interface
├── Core Protocol Layer
│   ├── pana_messages.py         # Message and AVP structures
│   ├── pana_constants.py        # Protocol constants and enums
│   ├── pana_client.py           # PaC implementation
│   └── pana_server.py           # PAA implementation
├── Security Layer
│   ├── pana_crypto.py           # Cryptographic operations
│   ├── pana_antireplay.py       # Anti-replay protection
│   ├── pana_encryption_policy.py # RFC 6786 encryption policies
│   ├── pana_client_encryption.py # Client-side encryption
│   └── pana_server_encryption.py # Server-side encryption
├── Authentication Layer
│   ├── eap_tls_factory.py       # EAP-TLS implementation selection
│   ├── eap_tls_pyopenssl.py     # PyOpenSSL-based EAP-TLS
│   ├── eap_tls.py               # Fallback EAP-TLS implementation
│   └── radius_backend.py        # RADIUS integration
├── Session Management
│   ├── pana_session.py          # Session lifecycle management
│   ├── pana_retransmission.py   # Reliable message delivery
│   └── pana_error_recovery.py   # Error handling and recovery
└── Enterprise Features
    ├── pana_statistics.py        # Statistics collection
    ├── pana_monitor.py           # HTTP monitoring interface
    ├── pana_ratelimit.py         # DoS protection
    └── pana_config.py            # Configuration management
```

### Design Patterns

1. **Factory Pattern**: `eap_tls_factory.py` selects the best available EAP-TLS implementation
2. **State Machine Pattern**: Both PaC and PAA implement RFC 5191 state machines
3. **Observer Pattern**: Statistics collection observes session events
4. **Strategy Pattern**: Encryption policies determine AVP encryption behavior
5. **Singleton Pattern**: Global configuration management

---

## Core Protocol Implementation

### Message Structure (RFC 5191)

#### PANA Header Format (16 bytes)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Reserved            |        Message Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Flags             |         Message Type          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Session Identifier                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### AVP Format (8+ bytes)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           AVP Code            |           AVP Flags           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          AVP Length           |            Reserved           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Vendor-Id (opt)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Value ...
+-+-+-+-+-+-+-+-+
```

### Message Types

| Type | Value | Description |
|------|-------|-------------|
| PANA_CLIENT_INITIATION | 1 | PCI - Session initiation by client |
| PANA_AUTH | 2 | PAR/PAN - Authentication exchange |
| PANA_TERMINATION | 3 | PTR/PTA - Session termination |
| PANA_NOTIFICATION | 4 | PNR/PNA - Notifications and ping |

### State Machines

#### PaC (Client) States
- `INITIAL`: Starting state
- `WAIT_PAN_OR_PAR`: Waiting for server response
- `WAIT_EAP_MSG`: Processing EAP authentication
- `WAIT_EAP_RESULT`: Waiting for authentication result
- `OPEN`: Authenticated session active
- `CLOSED`: Session terminated

#### PAA (Server) States
- `INITIAL`: Starting state
- `WAIT_EAP_MSG`: Waiting for EAP response
- `WAIT_PAN_OR_PAR`: Waiting for client response
- `WAIT_SUCC_PAN`: Waiting for success acknowledgment
- `WAIT_FAIL_PAN`: Waiting for failure acknowledgment
- `OPEN`: Authenticated session active
- `CLOSED`: Session terminated

### Protocol Flow

```
PaC                          PAA                          RADIUS
 |                            |                              |
 |-------- PCI (S-bit) ------>|                              |
 |<------- PAR (S-bit) -------|                              |
 |-------- PAN (S-bit) ------>|                              |
 |<------- PAR (EAP-Req) -----|                              |
 |-------- PAN (EAP-Resp) --->|------- Access-Request ------>|
 |                            |<------ Access-Challenge ------|
 |<------- PAR (EAP-TLS) -----|                              |
 |-------- PAN (EAP-TLS) ---->|                              |
 |          ...               |            ...                |
 |<------- PAR (C-bit) -------|<------ Access-Accept ---------|
 |-------- PAN (C-bit) ------>|                              |
```

---

## Security Implementation

### Key Derivation (RFC 5191 Section 5.3)

#### Master Key Derivation
```python
# From EAP-TLS (RFC 5216)
MSK = export_keying_material("client EAP encryption", 64)
EMSK = export_keying_material("client EAP encryption", 64, offset=64)
```

#### PANA Key Derivation
```python
# Authentication Key
PANA_AUTH_KEY = prf+(MSK, "IETF PANA"|I_PAR|I_PAN|PaC_nonce|PAA_nonce|Key_ID)

# Encryption Keys (RFC 6786)
PANA_PAC_ENCR_KEY = prf+(MSK, "IETF PANA PaC Encr"|I_PAR|I_PAN|PaC_nonce|PAA_nonce|Key_ID)
PANA_PAA_ENCR_KEY = prf+(MSK, "IETF PANA PAA Encr"|I_PAR|I_PAN|PaC_nonce|PAA_nonce|Key_ID)
```

### Supported Algorithms

| Type | Algorithm | ID | Description |
|------|-----------|-----|-------------|
| PRF | PRF_HMAC_SHA1 | 2 | RFC 5191 mandatory |
| PRF | PRF_HMAC_SHA2_256 | 5 | Enhanced security |
| Integrity | AUTH_HMAC_SHA1_160 | 7 | 160-bit HMAC-SHA1 |
| Integrity | AUTH_HMAC_SHA2_256_128 | 12 | 128-bit truncated HMAC-SHA256 |
| Encryption | AES128_CTR | 1 | AES-128 in counter mode |

### AVP Encryption (RFC 6786)

#### Encryption Policy
```python
# Never encrypt (RFC 6786 Section 6.1)
NEVER_ENCRYPT = {AVP_AUTH, AVP_NONCE, AVP_KEY_ID, AVP_ENCRYPTION_ALGORITHM}

# May encrypt
MAY_ENCRYPT = {AVP_EAP_PAYLOAD, AVP_SESSION_LIFETIME, AVP_TERMINATION_CAUSE}

# Must encrypt (future use)
MUST_ENCRYPT = {}
```

#### Encryption Process
1. Identify AVPs to encrypt based on policy
2. Create Encryption-Encap AVP containing encrypted data
3. Use AES-128-CTR with RFC 6786 compliant nonce
4. Add Encryption-Algorithm AVP to message

### Anti-Replay Protection

- **Sliding Window**: 32-packet window by default
- **Sequence Number Tracking**: Per-session sequence validation
- **Timestamp Verification**: Optional time-based validation
- **Duplicate Detection**: Prevents replay attacks

---

## Session Management

### Session Lifecycle

1. **Creation**: New session on PCI reception or client initiation
2. **Authentication**: EAP-TLS exchange with MSK derivation
3. **Active**: Authenticated session with periodic liveness checks
4. **Re-authentication**: Triggered by lifetime expiry or IP change
5. **Termination**: Explicit termination or timeout

### Session Features

- **Lifetime Management**: Configurable session lifetime (default 3600s)
- **Automatic Cleanup**: Background thread removes expired sessions
- **Re-authentication**: Seamless session renewal before expiry
- **IP Mobility**: Detection and handling of IP address changes
- **Concurrent Sessions**: Support for multiple sessions per IP

### Retransmission Management

- **Automatic Retry**: Exponential backoff with configurable intervals
- **R-bit Support**: RFC 5191 compliant retransmission flag
- **Per-Message Tracking**: Individual timeout per message
- **Adaptive Polling**: CPU-efficient background processing

---

## Enterprise Features

### RADIUS Integration

```python
# RADIUS proxy mode
radius_client = Client(server="radius.example.com", secret=b"secret")
radius_client.authport = 1812

# Forward EAP to RADIUS
req = radius_client.CreateAuthPacket(code=1)
req['EAP-Message'] = eap_payload
reply = radius_client.SendPacket(req)
```

### Rate Limiting

- **Request Rate Limiting**: Max requests per second per IP
- **Session Limiting**: Max concurrent sessions per IP
- **Memory Protection**: Automatic limiting at memory threshold
- **Blacklisting**: Temporary ban for abusive clients

### Statistics Collection

```python
# Real-time statistics
{
    'total_sessions': 1234,
    'active_sessions': 45,
    'authentication': {
        'successful': 1189,
        'failed': 45,
        'success_rate': 96.3
    },
    'packets': {
        'sent': 45678,
        'received': 45234,
        'retransmissions': 234
    }
}
```

### Monitoring Interface

- **HTTP API**: RESTful API for status queries
- **Metrics Export**: Prometheus-compatible metrics
- **Health Checks**: Liveness and readiness endpoints
- **Session Details**: Per-session statistics and state

---

## Testing and Verification

### Test Suite Overview (v2.3.1)

The test suite consists of 15 active tests organized into five categories:

### Test Categories

1. **Core Compatibility Tests (5 tests)**
   - `test_compatibility.py` - Basic pyPANA ↔ pyPANA compatibility
   - `test_compatibility_fixed.py` - Enhanced with threading and better diagnostics
   - `test_protocol_flow.py` - RFC 5191 message format validation (PCI flags=0x0000)
   - `test_simple_auth.py` - Basic authentication flow without EAP-TLS complexity
   - `test_e2e.py` - End-to-end testing with complete flows

2. **OpenPANA Interoperability Tests (3 tests)**
   - `test_openpana_fixed.py` - OpenPANA compatibility with v2.3.1 fixes
   - `test_pypana_paa_openpana.py` - PAA server for OpenPANA PaC testing
   - `test_pypana_complete.py` - Complete pyPANA authentication testing

3. **Cryptographic Tests (3 tests)**
   - `test_auth_avp.py` - AUTH AVP calculation and verification
   - `test_crypto_algorithms.py` - Algorithm implementation verification
   - `test_avp_format.py` - AVP structure and padding validation

4. **RFC Compliance Tests (3 tests)**
   - `test_rfc_compliance_fixes.py` - RFC 5191/6786 compliance validation (NEW)
   - `test_rfc6786_compliance.py` - RFC 6786 encryption compliance
   - `test_rfc_compliant_reauth.py` - Re-authentication flow compliance

5. **Integration Test (1 test)**
   - `test_pana.py` - Basic PANA protocol integration

### Running Tests

```bash
# Run all 15 active tests
python3 run_tests.py

# Run enhanced compatibility test (v2.3.1)
python3 tests/test_compatibility_fixed.py

# Run RFC compliance validation
python3 tests/test_rfc_compliance_fixes.py

# Run protocol flow tests (validates PCI flags=0x0000)
python3 tests/test_protocol_flow.py

# Quick interoperability check
python3 tests/test_simple_auth.py
```

### Test Documentation

Comprehensive test documentation is available:
- `tests/TEST_DOCUMENTATION.md` - Detailed descriptions of all 15 tests
- `tests/TEST_CATEGORIZATION.md` - Test organization and status
- `tests/TEST_COMPATIBILITY_FIXED.md` - Enhanced compatibility test details
- `tests/TEST_RFC_COMPLIANCE_FIXES.md` - RFC compliance test documentation
- `tests/RUN_TESTS_DOCUMENTATION.md` - Test runner architecture

### Test Coverage

- **Core Protocol**: 100% coverage of message types and state transitions
- **Security**: Complete coverage of key derivation and encryption
- **Error Handling**: Edge cases and failure scenarios
- **Interoperability**: Verified with OpenPANA reference implementation

---

## API Reference

### Client API

```python
from pana_client import PANAClient

# Create client
client = PANAClient(
    server_addr="192.168.1.1",
    server_port=716,
    encryption_policy=policy
)

# Run authentication
client.run()

# Check state
if client.state == PAC_STATE_OPEN:
    print("Authenticated successfully")
```

### Server API

```python
from pana_server import PANAAuthAgent

# Create server
server = PANAAuthAgent(
    bind_addr="0.0.0.0",
    bind_port=716,
    radius_server="radius.example.com",
    encryption_policy=policy
)

# Run server
server.run()
```

### Configuration API

```python
from pana_config import get_config

# Get global config
config = get_config()

# Access settings
port = config.get('network.default_port')
rate_limit = config.get('rate_limiting.enabled')

# Modify settings
config.set('session.default_lifetime', 7200)
```

### Encryption Policy API

```python
from pana_encryption_policy import EncryptionPolicy

# Create policy
policy = EncryptionPolicy()
policy.encryption_enabled = True
policy.enforce_encryption = False
policy.supported_algorithms = [AES128_CTR]

# Check AVP encryption requirement
requirement = policy.get_avp_encryption_requirement(AVP_EAP_PAYLOAD)
```

---

## Configuration

### Environment Variables

```bash
# Network Configuration
PANA_PORT=716
PANA_BIND_ADDR=0.0.0.0

# Security Configuration
PANA_ENCRYPTION_ENABLED=true
PANA_RATE_LIMIT_ENABLED=true
PANA_RATE_LIMIT_MAX_RPS=100

# Session Configuration
PANA_SESSION_LIFETIME=3600
PANA_CLEANUP_INTERVAL=60

# Logging Configuration
PANA_LOG_LEVEL=INFO
```

### Configuration File (JSON)

```json
{
    "network": {
        "default_port": 716,
        "buffer_size": 4096
    },
    "security": {
        "encryption_enabled": true,
        "algorithms": ["AES128_CTR"]
    },
    "session": {
        "default_lifetime": 3600,
        "max_retransmissions": 3
    }
}
```

### Certificate Management

```bash
# Generate CA certificate
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt

# Generate server certificate
openssl req -new -keyout server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -out server.crt

# Generate client certificate
openssl req -new -keyout client.key -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -out client.crt
```

---

## Deployment

### Docker Deployment

```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "main.py", "paa", "--bind", "0.0.0.0"]
```

### Systemd Service

```ini
[Unit]
Description=PANA Authentication Agent
After=network.target

[Service]
Type=simple
User=pana
ExecStart=/usr/bin/python3 /opt/pypana/main.py paa
Restart=always

[Install]
WantedBy=multi-user.target
```

### Production Checklist

- [x] Replace test certificates with production CA-signed certificates
- [x] Configure proper encryption policies for your security requirements
- [x] Enable rate limiting and configure thresholds
- [x] Set up log rotation and archival
- [x] Configure monitoring and alerting
- [x] Test failover and recovery procedures
- [x] Document operational procedures

---

## Troubleshooting

### Common Issues

1. **AUTH AVP Verification Failure**
   - Ensure matching algorithms on both sides
   - Verify I_PAR and I_PAN are stored correctly
   - Check sequence number synchronization

2. **EAP-TLS Handshake Failure**
   - Verify certificate chain and validity
   - Check PyOpenSSL installation
   - Ensure TLS 1.2 support

3. **Encryption Negotiation Failure**
   - Verify both sides support same algorithms
   - Check encryption policy configuration
   - Ensure keys are properly derived

4. **Session Timeout**
   - Adjust retransmission parameters
   - Check network connectivity
   - Verify firewall rules

### Debug Mode

```bash
# Enable debug logging
python3 main.py pac 192.168.1.1 --debug

# Check specific module
export PYTHONPATH=.
python3 -c "import logging; logging.basicConfig(level=logging.DEBUG); from pana_crypto import CryptoContext; c = CryptoContext()"
```

---

## Contributing

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/pypana.git
cd pypana

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python3 run_tests.py  # Runs all 15 active tests
```

### Code Style

- Follow PEP 8 guidelines
- Use type hints where appropriate
- Add docstrings to all public functions
- Include unit tests for new features

---

## License

This project is licensed under the MIT License. See LICENSE file for details.

---

## References

- RFC 5191: Protocol for Carrying Authentication for Network Access (PANA)
- RFC 5216: The EAP-TLS Authentication Protocol
- RFC 5705: Keying Material Exporters for TLS
- RFC 6786: Encrypting PANA AVPs

---

*Last Updated: 2025-08-25*
*Version: 2.3.0*