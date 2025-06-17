# pyPANA - RFC5191 PANA Protocol Implementation

A complete Python implementation of the Protocol for carrying Authentication for Network Access (PANA) as defined in RFC5191. This implementation includes full EAP-TLS authentication support and is compatible with OpenSSL 3.x.

## What is PANA?

PANA (Protocol for carrying Authentication for Network Access) is a UDP-based protocol that enables network access authentication between a client device (PaC - PANA Client) and an access network (PAA - PANA Authentication Agent). It carries EAP (Extensible Authentication Protocol) messages to perform authentication without requiring link-layer modifications.

### Key Use Cases

- **Network Access Control**: Authenticate devices before granting network access
- **Guest Network Authentication**: Secure guest access without 802.1X
- **IoT Device Authentication**: Lightweight authentication for resource-constrained devices
- **Service Provider Networks**: Authentication in multi-tenant environments

## Features

- **RFC5191 Compliant**: Full implementation of PANA protocol specification
- **EAP-TLS Authentication**: Complete EAP-TLS (RFC5216) support with proper key derivation
- **Cryptographic Algorithms**:
  - PRF_HMAC_SHA2_256 (PRF algorithm)
  - AUTH_HMAC_SHA2_256_128 (Integrity algorithm)
  - AES128_CTR (Encryption algorithm)
- **OpenSSL 3.x Support**: Compatible with both OpenSSL 3.x and 1.1
- **State Machine**: Proper RFC5191 state machine implementation
- **Session Management**: Lifetime management and re-authentication support
- **Message Retransmission**: Reliable message delivery with R-bit support
- **Comprehensive Error Handling**: Robust validation and error recovery

## Requirements

- Python 3.7+
- OpenSSL 3.x or 1.1
- Python packages:
  - cryptography
  - pyOpenSSL

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/pyPANA.git
cd pyPANA

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Running the PANA Authentication Agent (PAA/Server)

```bash
# Run with default settings (binds to all interfaces on port 716)
sudo python pyPANA.py paa

# Run on specific interface and custom port
sudo python pyPANA.py paa --bind 192.168.1.100 --port 716
```

Note: Port 716 requires root/admin privileges. For testing, you can use a higher port.

### Running the PANA Client (PaC)

```bash
# Connect to PAA
python pyPANA.py pac 192.168.1.100

# Connect to PAA on custom port
python pyPANA.py pac 192.168.1.100 --port 716
```

### Example: Testing on Localhost

Terminal 1 (PAA):
```bash
python pyPANA.py paa
```

Terminal 2 (PaC):
```bash
python pyPANA.py pac 127.0.0.1
```

## Protocol Overview

### Message Flow

```
PaC (Client)                    PAA (Server)
     |                              |
     |------- PCI (Start) --------->|
     |                              |
     |<------ PAR (EAP-Req/Id) -----|
     |                              |
     |------- PAN (EAP-Resp/Id) --->|
     |                              |
     |<------ PAR (EAP-TLS) --------|
     |                              |
     |------- PAN (EAP-TLS) ------->|
     |         ...                  |
     |<------ PAR (EAP-Success) ----|
     |                              |
     |------- PAN (Complete) ------>|
     |                              |
     |        [Authenticated]       |
```

### Message Types

- **PCI**: PANA-Client-Initiation - Starts the authentication process
- **PAR/PAN**: PANA-Auth-Request/Answer - Carries EAP payloads
- **PNR/PNA**: PANA-Notification-Request/Answer - Keep-alive and notifications
- **PRR/PRA**: PANA-Reauth-Request/Answer - Session re-authentication
- **PTR/PTA**: PANA-Termination-Request/Answer - Session termination

## Advanced Usage

### Custom Configuration

Create a configuration file or modify the code constants:

```python
# Session parameters
DEFAULT_SESSION_LIFETIME = 3600  # 1 hour
RETRANSMIT_INTERVAL = 3.0       # seconds
MAX_RETRANSMISSIONS = 3

# Cryptographic algorithms
PRF_ALGORITHM = PRF_HMAC_SHA2_256
AUTH_ALGORITHM = AUTH_HMAC_SHA2_256_128
ENCR_ALGORITHM = AES128_CTR
```

### RADIUS Backend

`PANAAuthAgent` can proxy EAP authentication to an external RADIUS server.
Specify the server address, shared secret and port when creating the agent:

```python
from pyPANA import PANAAuthAgent

paa = PANAAuthAgent(
    bind_addr='0.0.0.0',
    bind_port=716,
    radius_server='192.168.1.10',
    radius_secret='topsecret',
    radius_port=1812
)
```


### Using with Certificates

For production use, replace the self-signed certificate generation with real certificates:

```python
# In your code
eap_handler = EAPTLSHandler(
    is_server=True,
    cert_file='/path/to/server.crt',
    key_file='/path/to/server.key'
)
```

### Integration Example

```python
from pyPANA import PANAClient

# Create and configure client
client = PANAClient('paa.example.com')

# Add custom authentication handling
def on_auth_success(session_key):
    print(f"Authenticated! Session key: {session_key.hex()}")
    # Use session key for subsequent communications

# Run authentication
client.run()
```

## Architecture

### Core Components

1. **PANAMessage**: Protocol message structure and serialization
2. **PANAClient (PaC)**: Client implementation with state machine
3. **PANAAuthAgent (PAA)**: Server implementation
4. **EAPTLSHandler**: EAP-TLS authentication handling
5. **CryptoContext**: Key derivation and cryptographic operations
6. **SessionManager**: Session lifecycle management
7. **RetransmissionManager**: Reliable message delivery

### State Machines

The implementation follows RFC5191 state machines:

**PaC States**: INITIAL → WAIT_PAN_OR_PAR → WAIT_EAP_MSG → WAIT_EAP_RESULT → OPEN

**PAA States**: INITIAL → WAIT_EAP_MSG → WAIT_PAN_OR_PAR → WAIT_SUCC_PAN → OPEN

## Security Considerations

1. **Certificate Validation**: The example uses self-signed certificates. In production:
   - Use certificates from a trusted CA
   - Enable proper certificate validation
   - Implement certificate revocation checking

2. **Key Storage**: Protect private keys and session keys:
   - Use secure key storage mechanisms
   - Implement proper key rotation
   - Clear keys from memory after use

3. **Network Security**:
   - PANA uses UDP - consider network-level protection
   - Implement rate limiting to prevent DoS attacks
   - Monitor for authentication failures

## Troubleshooting

### Common Issues

1. **Permission Denied (Port 716)**
   ```
   Solution: Run with sudo or use a port > 1024 for testing
   ```

2. **OpenSSL Not Found**
   ```
   Solution: Install OpenSSL 3.x or 1.1 and ensure it's in system path
   ```

3. **Module Import Errors**
   ```
   Solution: Install requirements: pip install -r requirements.txt
   ```

### Debug Mode

Enable detailed logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Development

### Running Tests

```bash
# Basic structure tests
python test_basic.py

# Full test suite (requires dependencies)
python test_pana.py
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Adding New Features

To extend the protocol:

1. Add new message types/AVPs in constants
2. Implement handlers in PANAClient/PANAAuthAgent
3. Update state machine transitions
4. Add tests for new functionality

## References

- [RFC5191](https://tools.ietf.org/html/rfc5191) - Protocol for Carrying Authentication for Network Access (PANA)
- [RFC5216](https://tools.ietf.org/html/rfc5216) - The EAP-TLS Authentication Protocol
- [RFC5705](https://tools.ietf.org/html/rfc5705) - Keying Material Exporters for TLS
- [RFC3748](https://tools.ietf.org/html/rfc3748) - Extensible Authentication Protocol (EAP)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Open an issue on GitHub
- Check existing issues for solutions
- Provide debug logs when reporting problems

## Acknowledgments

This implementation follows the specifications defined by the IETF in RFC5191 and related standards.