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
- **RADIUS Backend**: Optional RADIUS authentication support via `pyrad`

## Requirements

- Python 3.7+
- OpenSSL 3.x or 1.1
- Python packages:
  - cryptography
  - pyOpenSSL
  - pyrad (optional, for RADIUS backend)

**For RADIUS integration (optional):**
- FreeRADIUS server (or any RADIUS server)
- Network access to RADIUS server (UDP ports 1812/1813)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/pyPANA.git
cd pyPANA

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Basic Authentication (EAP-TLS only)

**Terminal 1 - PAA (Server):**
```bash
# Run with default settings (binds to all interfaces on port 716)
sudo python3 pyPANA.py paa

# Run on specific interface and custom port
sudo python3 pyPANA.py paa --bind 192.168.1.100 --port 716
```

**Terminal 2 - PaC (Client):**
```bash
# Connect to PAA
python3 pyPANA.py pac 192.168.1.100

# Connect to PAA on custom port
python3 pyPANA.py pac 192.168.1.100 --port 716
```

Note: Port 716 requires root/admin privileges. For testing, you can use a higher port.

### Example: Basic Testing on Localhost

**Terminal 1 (PAA):**
```bash
sudo python3 pyPANA.py paa --debug
```

**Terminal 2 (PaC):**
```bash
python3 pyPANA.py pac 127.0.0.1 --debug
```

This will perform EAP-TLS authentication using automatically generated self-signed certificates.

### Command Line Options

**PAA (Server) Options:**
```bash
python3 pyPANA.py paa [options]

Options:
  --bind ADDRESS        Bind to specific IP address (default: 0.0.0.0)
  --port PORT          UDP port to listen on (default: 716)
  --debug              Enable debug logging
  --radius-server IP   RADIUS server IP address
  --radius-port PORT   RADIUS server port (default: 1812)
  --radius-secret SECRET  RADIUS shared secret
  --radius-timeout SEC RADIUS request timeout (default: 5)
  --radius-retries N   RADIUS retry attempts (default: 3)
```

**PaC (Client) Options:**
```bash
python3 pyPANA.py pac SERVER_IP [options]

Options:
  --port PORT          PAA server port (default: 716)
  --debug              Enable debug logging
  --timeout SEC        Connection timeout (default: 10)
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

### Using RADIUS Backend Integration

pyPANA can integrate with a RADIUS server for user authentication. The PANA Authentication Agent (PAA) acts as a RADIUS client, forwarding authentication requests to the RADIUS server.

#### Setting up RADIUS Integration

1. **Install FreeRADIUS (example setup on Ubuntu/Debian):**

```bash
# Install FreeRADIUS server
sudo apt update
sudo apt install freeradius freeradius-utils

# Start the service
sudo systemctl start freeradius
sudo systemctl enable freeradius
```

2. **Configure FreeRADIUS:**

Edit `/etc/freeradius/3.0/clients.conf` to add pyPANA as a client:

```
client pana_agent {
    ipaddr = 127.0.0.1
    secret = testing123
    shortname = pana-agent
    nastype = other
}
```

3. **Add test users in `/etc/freeradius/3.0/users`:**

```
testuser    Cleartext-Password := "testpass"
            Reply-Message = "Welcome to PANA network"

alice       Cleartext-Password := "alice123"
            Reply-Message = "Alice authenticated successfully"

bob         Cleartext-Password := "bob456"
            Reply-Message = "Bob authenticated successfully"
```

4. **Restart FreeRADIUS:**

```bash
sudo systemctl restart freeradius

# Test RADIUS is working
radtest testuser testpass 127.0.0.1 0 testing123
```

#### Running pyPANA with RADIUS Backend

**Method 1: Using command line arguments:**

```bash
# Run PAA with RADIUS backend
sudo python3 pyPANA.py paa --radius-server 127.0.0.1 --radius-port 1812 --radius-secret testing123
```

**Method 2: Using configuration in code:**

```python
from pyPANA import PANAAuthAgent

# Create PAA with RADIUS configuration
agent = PANAAuthAgent(
    bind_addr='0.0.0.0',
    port=716,
    radius_server='127.0.0.1',
    radius_port=1812,
    radius_secret='testing123'
)

agent.run()
```

#### Complete RADIUS Setup Example

Here's a complete example of setting up pyPANA with RADIUS on the same machine:

**Terminal 1 - Setup FreeRADIUS:**

```bash
# Install and configure FreeRADIUS
sudo apt install freeradius freeradius-utils

# Add PANA client configuration
echo 'client pana_agent {
    ipaddr = 127.0.0.1
    secret = testing123
    shortname = pana-agent
    nastype = other
}' | sudo tee -a /etc/freeradius/3.0/clients.conf

# Add test user
echo 'testuser    Cleartext-Password := "testpass"
            Reply-Message = "Welcome to PANA network"' | sudo tee -a /etc/freeradius/3.0/users

# Restart FreeRADIUS
sudo systemctl restart freeradius

# Verify RADIUS is working
radtest testuser testpass 127.0.0.1 0 testing123
```

**Terminal 2 - Run PAA with RADIUS:**

```bash
# Run PANA Authentication Agent with RADIUS backend
sudo python3 pyPANA.py paa --radius-server 127.0.0.1 --radius-port 1812 --radius-secret testing123 --debug
```

**Terminal 3 - Run PANA Client:**

```bash
# Run PANA Client
python3 pyPANA.py pac 127.0.0.1 --debug
```

#### Authentication Flow with RADIUS

```
PaC (Client)         PAA (Server)         RADIUS Server
     |                    |                      |
     |-- PCI (Start) ---->|                      |
     |                    |                      |
     |<-- PAR (EAP-Req) --|                      |
     |                    |                      |
     |-- PAN (EAP-Resp) ->|-- Access-Request --->|
     |                    |                      |
     |                    |<-- Access-Accept ----|
     |                    |                      |
     |<-- PAR (Success) --|                      |
     |                    |                      |
     |-- PAN (Complete) ->|                      |
     |                    |                      |
     |   [Authenticated]  |                      |
```

#### RADIUS Configuration Options

You can customize the RADIUS integration:

```python
# Advanced RADIUS configuration
agent = PANAAuthAgent(
    radius_server='127.0.0.1',
    radius_port=1812,
    radius_secret='testing123',
    radius_timeout=5,           # Request timeout (seconds)
    radius_retries=3,           # Number of retries
    radius_nas_identifier='pana-agent',  # NAS identifier
    radius_nas_ip='192.168.1.100'       # NAS IP address
)
```

#### Troubleshooting RADIUS Integration

1. **RADIUS server not responding:**
```bash
# Check FreeRADIUS status
sudo systemctl status freeradius

# Check RADIUS logs
sudo tail -f /var/log/freeradius/radius.log

# Test RADIUS manually
radtest testuser testpass 127.0.0.1 0 testing123
```

2. **Authentication failures:**
```bash
# Enable debug mode in FreeRADIUS
sudo freeradius -X

# Check pyPANA debug logs for RADIUS errors
python3 pyPANA.py paa --radius-server 127.0.0.1 --debug
```

3. **Common issues:**
   - **Wrong shared secret**: Ensure the secret matches in both clients.conf and pyPANA
   - **Firewall blocking**: RADIUS uses UDP port 1812/1813
   - **User not found**: Check the users file in FreeRADIUS configuration
   - **IP restrictions**: Ensure the client IP is allowed in clients.conf

#### Integration with External RADIUS Servers

pyPANA can also work with external RADIUS servers like Microsoft NPS, Cisco ISE, or cloud-based AAA services:

```bash
# Connect to external RADIUS server
sudo python3 pyPANA.py paa \
  --radius-server radius.company.com \
  --radius-port 1812 \
  --radius-secret "your-shared-secret" \
  --radius-nas-identifier "pana-gateway-01"
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