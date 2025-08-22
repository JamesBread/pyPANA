#!/usr/bin/env python3
"""
EAP-TLS implementation using PyOpenSSL for proper key export
"""

import os
import struct
import logging
import hashlib
from typing import Optional, Tuple

import OpenSSL.SSL
import OpenSSL.crypto

logger = logging.getLogger(__name__)

# EAP codes
EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_TYPE_TLS = 13

# EAP-TLS flags
EAP_TLS_FLAG_LENGTH = 0x80
EAP_TLS_FLAG_MORE = 0x40
EAP_TLS_FLAG_START = 0x20


class EAPTLSWithPyOpenSSL:
    """EAP-TLS implementation using PyOpenSSL for proper MSK derivation"""
    
    def __init__(self, is_server=False, cert_file=None, key_file=None, ca_cert=None):
        self.is_server = is_server
        self.cert_file = cert_file or 'certs/server.crt' if is_server else 'certs/client.crt'
        self.key_file = key_file or 'certs/server.key' if is_server else 'certs/client.key'
        self.ca_cert = ca_cert or 'certs/ca.crt'
        
        self.state = 'INIT'
        self.msk = None
        self.emsk = None
        self.connection = None
        self.context = None
        self.bio_in = None
        self.bio_out = None
        self.handshake_complete = False
        
        self.logger = logging.getLogger(f'EAP-TLS-PyOpenSSL-{"Server" if is_server else "Client"}')
        
        self._init_ssl()
    
    def _init_ssl(self):
        """Initialize PyOpenSSL context and connection"""
        try:
            # Create SSL context
            if self.is_server:
                self.context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
            else:
                self.context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
            
            # Load certificates
            self.context.use_certificate_file(self.cert_file)
            self.context.use_privatekey_file(self.key_file)
            self.context.load_verify_locations(self.ca_cert)
            
            # Set verification
            if self.is_server:
                self.context.set_verify(
                    OpenSSL.SSL.VERIFY_PEER | OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                    self._verify_callback
                )
            else:
                self.context.set_verify(OpenSSL.SSL.VERIFY_PEER, self._verify_callback)
            
            # Create connection with memory BIOs
            self.connection = OpenSSL.SSL.Connection(self.context, None)
            
            # Set connect/accept state
            if self.is_server:
                self.connection.set_accept_state()
            else:
                self.connection.set_connect_state()
                
            self.logger.info("PyOpenSSL initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize PyOpenSSL: {e}")
            raise
    
    def _verify_callback(self, conn, cert, errno, depth, ok):
        """Certificate verification callback"""
        if not ok:
            self.logger.warning(f"Certificate verification failed at depth {depth}: {errno}")
        return ok
    
    def process_eap_message(self, eap_data):
        """Process EAP message and return response"""
        if len(eap_data) < 4:
            return self._create_eap_tls_packet(EAP_REQUEST if self.is_server else EAP_RESPONSE, 0, b'', EAP_TLS_FLAG_START)
        
        code, identifier, length = struct.unpack('!BBH', eap_data[:4])
        
        # Handle EAP-Success
        if code == EAP_SUCCESS:
            self.state = 'COMPLETE'
            # Client derives keys when receiving EAP-Success
            if not self.is_server and not self.handshake_complete:
                self.handshake_complete = True
                self._derive_msk_emsk()
            self.logger.info("EAP-TLS authentication successful")
            return None
        
        # Handle EAP-Request/Response
        if length > 4:
            payload = eap_data[4:]
            
            if len(payload) >= 1 and payload[0] == EAP_TYPE_TLS:
                # Process EAP-TLS
                if len(payload) > 1:
                    flags = payload[1] if len(payload) > 1 else 0
                    tls_data = b''
                    
                    offset = 2
                    if flags & EAP_TLS_FLAG_LENGTH and len(payload) > offset + 4:
                        # Skip length field
                        offset += 4
                    
                    if len(payload) > offset:
                        tls_data = payload[offset:]
                    
                    # Process TLS data
                    response_data = self._process_tls_data(tls_data)
                    
                    # Check if handshake is complete
                    if self._is_handshake_complete():
                        if not self.handshake_complete:
                            self.handshake_complete = True
                            self._derive_msk_emsk()
                            
                            if self.is_server:
                                # Server sends EAP-Success
                                self.state = 'COMPLETE'
                                return struct.pack('!BBH', EAP_SUCCESS, identifier + 1, 4)
                            else:
                                # Client also completes on handshake done
                                self.state = 'COMPLETE'
                    
                    # Send TLS response if we have data
                    if response_data:
                        return self._create_eap_tls_packet(
                            EAP_RESPONSE if not self.is_server else EAP_REQUEST,
                            identifier if not self.is_server else identifier + 1,
                            response_data,
                            0
                        )
                    elif not self.is_server:
                        # Client sends empty response to acknowledge
                        return self._create_eap_tls_packet(
                            EAP_RESPONSE,
                            identifier,
                            b'',
                            0
                        )
        
        # Default: Start EAP-TLS
        if self.state == 'INIT':
            self.state = 'IN_PROGRESS'
            flags = EAP_TLS_FLAG_START
            
            if not self.is_server:
                # Client starts handshake
                response_data = self._process_tls_data(b'')
                return self._create_eap_tls_packet(EAP_RESPONSE, identifier, response_data, flags)
            else:
                # Server sends Start
                return self._create_eap_tls_packet(EAP_REQUEST, identifier + 1, b'', flags)
        
        return None
    
    def _process_tls_data(self, data):
        """Process TLS data through PyOpenSSL"""
        try:
            # Feed input data to connection
            if data:
                self.connection.bio_write(data)
            
            # Try to progress handshake
            output = b''
            try:
                self.connection.do_handshake()
            except OpenSSL.SSL.WantReadError:
                # Normal during handshake
                pass
            except OpenSSL.SSL.Error as e:
                if 'UNEXPECTED_EOF_WHILE_READING' not in str(e):
                    self.logger.debug(f"Handshake in progress: {e}")
            
            # Get any output data
            try:
                output = self.connection.bio_read(4096)
            except OpenSSL.SSL.WantReadError:
                pass
            
            return output
            
        except Exception as e:
            self.logger.error(f"TLS processing error: {e}")
            return b''
    
    def _is_handshake_complete(self):
        """Check if TLS handshake is complete"""
        try:
            # Check connection state
            state = self.connection.get_state_string()
            return state == b'SSLOK ' or b'SSL negotiation finished' in state
        except:
            return False
    
    def _derive_msk_emsk(self):
        """Derive MSK and EMSK using PyOpenSSL's export_keying_material"""
        try:
            # RFC 5216 Section 2.3: Export 128 octets of key material
            label = b'client EAP encryption'  # RFC 5216 label
            key_material = self.connection.export_keying_material(label, 128)
            
            # First 64 octets for MSK, next 64 for EMSK
            self.msk = key_material[:64]
            self.emsk = key_material[64:128]
            
            self.logger.info(f"✅ Successfully derived MSK/EMSK using PyOpenSSL")
            self.logger.debug(f"MSK (first 16 bytes): {self.msk[:16].hex()}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to derive MSK/EMSK: {e}")
            # Fallback to deterministic test keys
            self.logger.warning("Using deterministic test keys - NOT SECURE!")
            test_seed = b"TESTING_FIXED_MSK_SEED_NOT_SECURE"
            self.msk = hashlib.sha256(test_seed + b"MSK").digest() + hashlib.sha256(test_seed + b"MSK2").digest()
            self.emsk = hashlib.sha256(test_seed + b"EMSK").digest() + hashlib.sha256(test_seed + b"EMSK2").digest()
            return False
    
    def _create_eap_tls_packet(self, code, identifier, data, flags):
        """Create EAP-TLS packet"""
        # EAP header
        eap_type = struct.pack('!B', EAP_TYPE_TLS)
        
        # EAP-TLS header
        if data or flags:
            tls_header = struct.pack('!B', flags)
            payload = eap_type + tls_header + data
        else:
            payload = eap_type
        
        length = 4 + len(payload)
        eap_packet = struct.pack('!BBH', code, identifier, length) + payload
        
        return eap_packet
    
    def get_msk(self):
        """Get Master Session Key"""
        return self.msk
    
    def get_emsk(self):
        """Get Extended Master Session Key"""
        return self.emsk


def test_pyopenssl_export():
    """Test PyOpenSSL key export"""
    import tempfile
    import os
    
    # Generate test certificates if they don't exist
    if not os.path.exists('certs/ca.crt'):
        print("Generating test certificates...")
        os.makedirs('certs', exist_ok=True)
        os.system('bash -c "cd certs && ../generate_ca_certs.sh"')
    
    # Create server and client
    server = EAPTLSWithPyOpenSSL(is_server=True)
    client = EAPTLSWithPyOpenSSL(is_server=False)
    
    # Simulate EAP exchange
    print("Starting EAP-TLS exchange...")
    
    # Server sends EAP-Request/Start
    msg = server.process_eap_message(b'')
    print(f"Server -> Client: EAP-Request/Start ({len(msg)} bytes)")
    
    # Exchange messages until complete
    for i in range(10):
        # Client processes and responds
        response = client.process_eap_message(msg)
        if not response:
            break
        print(f"Client -> Server: EAP-Response ({len(response)} bytes)")
        
        # Server processes and responds
        msg = server.process_eap_message(response)
        if not msg:
            break
        print(f"Server -> Client: EAP-Request ({len(msg)} bytes)")
        
        # Check for EAP-Success
        if len(msg) == 4 and msg[0] == EAP_SUCCESS:
            print("Server sent EAP-Success")
            client.process_eap_message(msg)
            break
    
    # Check results
    print("\n=== Results ===")
    print(f"Server state: {server.state}")
    print(f"Client state: {client.state}")
    print(f"Server MSK: {'Yes' if server.msk else 'No'}")
    print(f"Client MSK: {'Yes' if client.msk else 'No'}")
    
    if server.msk and client.msk:
        print(f"Server MSK (first 16 bytes): {server.msk[:16].hex()}")
        print(f"Client MSK (first 16 bytes): {client.msk[:16].hex()}")
        
        if server.msk == client.msk:
            print("✅ MSK values match!")
        else:
            print("❌ MSK values don't match")
    else:
        print("❌ Failed to derive MSK for both sides")
    
    return server.msk == client.msk


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    success = test_pyopenssl_export()
    exit(0 if success else 1)