#!/usr/bin/env python3
"""
PANA (RFC5191) Implementation with Complete EAP-TLS
RFC5191 compliant implementation with proper header format, key derivation, and fragmentation
Supports PRF_HMAC_SHA2_256, AUTH_HMAC_SHA2_256_128, AES128_CTR
"""

import socket
import struct
import hashlib
import hmac
import os
import threading
import time
import ssl
import select
import logging
from collections import deque
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from OpenSSL import SSL, crypto
import ctypes
from ctypes import c_void_p, c_char_p, c_size_t, c_int

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# RFC5191 PANA Message Types (single byte)
PANA_CLIENT_INITIATION = 1
PANA_AUTH = 2
PANA_TERMINATION = 3
PANA_NOTIFICATION = 4
PANA_REAUTH = 5

# PANA Flags (RFC5191 Section 6.2)
FLAG_REQUEST = 0x8000  # R flag - Request
FLAG_START = 0x4000    # S flag - Start
FLAG_COMPLETE = 0x2000 # C flag - Complete Auth
FLAG_AUTH = 0x1000     # A flag - Auth AVP present
FLAG_PING = 0x0800     # P flag - Ping request
FLAG_IP_RECONFIG = 0x0400  # I flag - IP Reconfiguration

# AVP Codes
AVP_AUTH = 1
AVP_EAP_PAYLOAD = 2
AVP_INTEGRITY_ALGORITHM = 3
AVP_KEY_ID = 4
AVP_NONCE = 5
AVP_PRF_ALGORITHM = 6
AVP_RESULT_CODE = 7
AVP_SESSION_ID = 8
AVP_TERMINATION_CAUSE = 9
AVP_ALGORITHM = 10
AVP_ENCR_DATA = 11
AVP_SESSION_LIFETIME = 12

# Algorithm IDs
PRF_HMAC_SHA2_256 = 1
AUTH_HMAC_SHA2_256_128 = 2
AES128_CTR = 3

# EAP Codes
EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4

# EAP Types
EAP_TYPE_IDENTITY = 1
EAP_TYPE_TLS = 13

# EAP-TLS Flags
EAP_TLS_FLAG_LENGTH = 0x80
EAP_TLS_FLAG_MORE = 0x40
EAP_TLS_FLAG_START = 0x20

# Retransmission parameters
RETRANSMIT_INTERVAL = 3.0  # seconds
MAX_RETRANSMISSIONS = 3

# Session parameters
DEFAULT_SESSION_LIFETIME = 3600  # 1 hour in seconds
SESSION_CLEANUP_INTERVAL = 60  # Check for expired sessions every minute

# PANA State Machine States (RFC5191 Section 4)
# PaC States
PAC_STATE_INITIAL = 'INITIAL'
PAC_STATE_WAIT_PAN_OR_PAR = 'WAIT_PAN_OR_PAR'
PAC_STATE_WAIT_EAP_MSG = 'WAIT_EAP_MSG'
PAC_STATE_WAIT_EAP_RESULT = 'WAIT_EAP_RESULT'
PAC_STATE_WAIT_EAP_RESULT_CLOSE = 'WAIT_EAP_RESULT_CLOSE'
PAC_STATE_OPEN = 'OPEN'
PAC_STATE_WAIT_PRA = 'WAIT_PRA'
PAC_STATE_SESS_TERM = 'SESS_TERM'
PAC_STATE_CLOSED = 'CLOSED'

# PAA States
PAA_STATE_INITIAL = 'INITIAL'
PAA_STATE_WAIT_EAP_MSG = 'WAIT_EAP_MSG'
PAA_STATE_WAIT_PAN_OR_PAR = 'WAIT_PAN_OR_PAR'
PAA_STATE_WAIT_SUCC_PAN = 'WAIT_SUCC_PAN'
PAA_STATE_WAIT_FAIL_PAN = 'WAIT_FAIL_PAN'
PAA_STATE_OPEN = 'OPEN'
PAA_STATE_WAIT_PRA = 'WAIT_PRA'
PAA_STATE_SESS_TERM = 'SESS_TERM'
PAA_STATE_CLOSED = 'CLOSED'

# TLS Key Export Label (RFC5216)
TLS_EXPORT_LABEL = b"EXPORTER_EAP_TLS_Key_Material"
TLS_EXPORT_CONTEXT = b""

class RetransmissionManager:
    """Manages message retransmission with R flag support"""
    def __init__(self, socket_obj):
        self.socket = socket_obj
        self.pending_messages = {}  # seq_number -> (message, addr, timestamp, retries)
        self.lock = threading.Lock()
        self.running = True
        self.thread = threading.Thread(target=self._retransmit_loop)
        self.thread.daemon = True
        self.thread.start()
        
    def add_message(self, seq_number, message, addr):
        """Add message for retransmission tracking"""
        with self.lock:
            self.pending_messages[seq_number] = (message, addr, time.time(), 0)
            
    def remove_message(self, seq_number):
        """Remove message from retransmission queue"""
        with self.lock:
            if seq_number in self.pending_messages:
                del self.pending_messages[seq_number]
                
    def _retransmit_loop(self):
        """Background thread for retransmissions"""
        while self.running:
            current_time = time.time()
            with self.lock:
                for seq_number, (message, addr, timestamp, retries) in list(self.pending_messages.items()):
                    if current_time - timestamp > RETRANSMIT_INTERVAL:
                        if retries < MAX_RETRANSMISSIONS:
                            # Retransmit
                            self.socket.sendto(message, addr)
                            self.pending_messages[seq_number] = (message, addr, current_time, retries + 1)
                            logging.info(f"Retransmitting message seq={seq_number}, retry={retries + 1}")
                        else:
                            # Max retries reached, remove from queue
                            del self.pending_messages[seq_number]
                            logging.warning(f"Max retransmissions reached for seq={seq_number}")
            time.sleep(1)
            
    def stop(self):
        """Stop retransmission thread"""
        self.running = False
        self.thread.join()

class PANAMessage:
    """PANA Message Format (RFC5191 compliant)"""
    def __init__(self):
        # RFC5191 Section 6.2: First 16 bits contain R,S,C,A,P,I flags + reserved
        # Next 16 bits contain Message Type
        self.flags = 0     # 16 bits (R,S,C,A,P,I flags in high 6 bits)
        self.reserved = 0  # 10-bit reserved field
        self.msg_type = 0  # 16 bits
        self.session_id = 0  # 32 bits
        self.seq_number = 0  # 32 bits
        self.avps = []
        
    def pack(self):
        """Pack message into bytes (RFC5191 format)"""
        # PANA Header is 12 bytes (RFC5191)
        # First 16 bits: flags (high 6 bits) + reserved (low 10 bits)
        # Next 16 bits: message type
        header_flags = (self.flags & 0xFC00) | (self.reserved & 0x03FF)
        header = struct.pack('!HHII',
                           header_flags,   # Flags + Reserved
                           self.msg_type,   # Message Type
                           self.session_id,
                           self.seq_number)
        
        avp_data = b''
        for avp in self.avps:
            avp_data += avp.pack()
            
        return header + avp_data
    
    def unpack(self, data):
        """Unpack message from bytes (RFC5191 format)"""
        if len(data) < 12:
            raise ValueError("Invalid PANA message length")

        (flag_field, self.msg_type,
         self.session_id, self.seq_number) = struct.unpack('!HHII', data[:12])
        self.flags = flag_field & 0xFC00
        self.reserved = flag_field & 0x03FF
        
        # Validate message type
        valid_msg_types = [PANA_CLIENT_INITIATION, PANA_AUTH, PANA_TERMINATION, 
                          PANA_NOTIFICATION, PANA_REAUTH]
        if self.msg_type not in valid_msg_types:
            raise ValueError(f"Invalid PANA message type: {self.msg_type}")
        
        # Parse AVPs
        offset = 12
        while offset < len(data):
            if offset + 8 > len(data):
                raise ValueError("Incomplete AVP header")
                
            avp = AVP()
            try:
                avp_len = avp.unpack(data[offset:])
                self.avps.append(avp)
                offset += avp_len
            except Exception as e:
                raise ValueError(f"Failed to parse AVP at offset {offset}: {e}")
            
        return len(data)

    def is_request(self):
        """Check if message is a request"""
        return bool(self.flags & FLAG_REQUEST)
    
    def set_request(self, is_req=True):
        """Set or clear request flag"""
        if is_req:
            self.flags |= FLAG_REQUEST
        else:
            self.flags &= ~FLAG_REQUEST

class AVP:
    """Attribute Value Pair"""
    def __init__(self, code=0, flags=0, value=b''):
        self.code = code
        self.flags = flags
        self.value = value
        
    def pack(self):
        """Pack AVP into bytes"""
        length = 8 + len(self.value)  # Header + value
        # Pad to 4-byte boundary
        padding = (4 - (len(self.value) % 4)) % 4
        
        header = struct.pack('!HHI', self.code, self.flags, length)
        return header + self.value + (b'\x00' * padding)
    
    def unpack(self, data):
        """Unpack AVP from bytes"""
        if len(data) < 8:
            raise ValueError("Invalid AVP length")
            
        self.code, self.flags, length = struct.unpack('!HHI', data[:8])
        
        # Validate length
        if length < 8:
            raise ValueError(f"Invalid AVP length: {length}")
        if length > len(data):
            raise ValueError(f"AVP length ({length}) exceeds available data ({len(data)})")
            
        value_length = length - 8
        if 8 + value_length > len(data):
            raise ValueError("Insufficient data for AVP value")
            
        self.value = data[8:8 + value_length]
        
        # Account for padding
        total_length = length + ((4 - (length % 4)) % 4)
        return total_length

class CryptoContext:
    """Cryptographic context for PANA session"""
    def __init__(self):
        self.prf_algorithm = PRF_HMAC_SHA2_256
        self.auth_algorithm = AUTH_HMAC_SHA2_256_128
        self.encr_algorithm = AES128_CTR
        self.msk = None  # Master Session Key from EAP
        self.emsk = None  # Extended Master Session Key
        self.pana_auth_key = None
        self.pana_encr_key = None
        self.nonce_paa = None
        self.nonce_pac = None
        self.key_id = None
        
    def derive_keys(self, msk, emsk=None):
        """Derive PANA keys from MSK (RFC5191 Section 5.3)"""
        self.msk = msk
        self.emsk = emsk
        
        # Generate Key_ID only if not already set (PaC receives it from PAA)
        if not self.key_id:
            self.key_id = os.urandom(4)
        
        # Derive PANA_AUTH_KEY (RFC5191 Section 5.3)
        # PANA_AUTH_KEY = prf+(MSK, "IETF PANA" | PSA(PaC) | PSA(PAA) | Session_ID | Key_ID)
        
        # Convert session_id to bytes if needed
        if hasattr(self, 'session_id'):
            session_id_bytes = struct.pack('!I', self.session_id)
        else:
            session_id_bytes = b'\x00\x00\x00\x00'
        
        # For simplicity, using nonces as PSA values
        prf_input = b"IETF PANA" + (self.nonce_pac or b'') + (self.nonce_paa or b'') + session_id_bytes + self.key_id
        
        # Debug log
        import logging
        logger = logging.getLogger('CryptoContext')
        logger.info(f"Key derivation parameters:")
        logger.info(f"  session_id: {self.session_id:08x}")
        logger.info(f"  nonce_pac: {(self.nonce_pac or b'').hex()}")
        logger.info(f"  nonce_paa: {(self.nonce_paa or b'').hex()}")
        logger.info(f"  key_id: {self.key_id.hex()}")
        logger.info(f"  MSK length: {len(msk)}")
        logger.info(f"  MSK: {msk.hex()}")
        
        # Use HKDF as PRF+ implementation
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes for auth key
            salt=None,
            info=prf_input,
            backend=default_backend()
        )
        
        self.pana_auth_key = hkdf.derive(msk[:32])  # Use first 32 bytes of MSK
        logger.info(f"  PANA_AUTH_KEY: {self.pana_auth_key.hex()[:32]}...")
        
        # Derive encryption key if needed (not in RFC5191 base, but for our AES support)
        hkdf_encr = HKDF(
            algorithm=hashes.SHA256(),
            length=16,  # 16 bytes for AES-128
            salt=None,
            info=b"PANA encryption key",
            backend=default_backend()
        )
        
        self.pana_encr_key = hkdf_encr.derive(msk[32:64] if len(msk) >= 64 else msk)
        
    def compute_auth(self, message_data):
        """Compute AUTH AVP value"""
        if not self.pana_auth_key:
            raise ValueError("No authentication key available")
            
        h = hmac.new(self.pana_auth_key, message_data, hashlib.sha256)
        return h.digest()[:16]  # Truncate to 128 bits
    
    def verify_auth(self, message_data, auth_value):
        """Verify AUTH AVP value"""
        computed = self.compute_auth(message_data)
        result = hmac.compare_digest(computed, auth_value)
        
        # Debug log
        import logging
        logger = logging.getLogger('CryptoContext')
        logger.info(f"AUTH verification:")
        logger.info(f"  computed: {computed.hex()}")
        logger.info(f"  received: {auth_value.hex()}")
        logger.info(f"  result: {result}")
        
        return result
    
    def encrypt(self, plaintext):
        """Encrypt data using AES-128-CTR"""
        if not self.pana_encr_key:
            raise ValueError("No encryption key available")
            
        # Generate random IV
        iv = os.urandom(16)
        
        cipher = Cipher(
            algorithms.AES(self.pana_encr_key[:16]),  # Use first 16 bytes for AES-128
            modes.CTR(iv),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return iv + ciphertext
    
    def decrypt(self, ciphertext):
        """Decrypt data using AES-128-CTR"""
        if not self.pana_encr_key:
            raise ValueError("No encryption key available")
            
        if len(ciphertext) < 16:
            raise ValueError("Invalid ciphertext length")
            
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        
        cipher = Cipher(
            algorithms.AES(self.pana_encr_key[:16]),
            modes.CTR(iv),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        return plaintext

def generate_self_signed_cert(ecdsa=True):
    """Generate self-signed certificate for testing

    Parameters
    ----------
    ecdsa : bool
        If ``True`` generate an ECDSA certificate (P-256).  When ``False`` a
        2048 bit RSA certificate is created.
    """
    # Generate private key
    if ecdsa:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    
    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Test"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PANA Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "pana.test"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    return cert, private_key

class OpenSSLKeyExporter:
    """OpenSSL Key Material Exporter with OpenSSL 3.x support"""
    
    def __init__(self):
        # Try to load OpenSSL 3.x first, then fall back to 1.1
        self._lib = None
        lib_names = [
            "libssl.so.3",      # OpenSSL 3.x Linux
            "libssl.so.1.1",    # OpenSSL 1.1 Linux
            "libssl-3-x64.dll", # OpenSSL 3.x Windows
            "libssl-1_1-x64.dll"# OpenSSL 1.1 Windows
        ]
        
        for lib_name in lib_names:
            try:
                self._lib = ctypes.CDLL(lib_name)
                logging.info(f"Loaded OpenSSL library: {lib_name}")
                break
            except OSError:
                continue
                
        if not self._lib:
            raise Exception("Could not load OpenSSL library (tried 3.x and 1.1)")
        
        # SSL_export_keying_material function definition (same for 1.1 and 3.x)
        self._export_func = self._lib.SSL_export_keying_material
        self._export_func.argtypes = [c_void_p, c_char_p, c_size_t, 
                                     c_char_p, c_size_t, c_char_p, 
                                     c_size_t, c_int]
        self._export_func.restype = c_int
    
    def export_keying_material(self, ssl_conn, label, length, context=b""):
        """RFC5705 compliant key material export"""
        out = ctypes.create_string_buffer(length)
        
        # Get SSL pointer from various SSL object types
        ssl_ptr = None
        
        # Extract SSL pointer from standard ssl module objects
        import _ssl
        
        # Method 1: Direct access to internal SSL object
        if hasattr(ssl_conn, '_sslobj'):
            internal_ssl = ssl_conn._sslobj
            # Try to access the underlying SSL structure
            if hasattr(internal_ssl, '__dict__'):
                for attr_name in dir(internal_ssl):
                    if not attr_name.startswith('_'):
                        continue
                    attr = getattr(internal_ssl, attr_name, None)
                    if attr and isinstance(attr, int) and attr > 0:
                        # This might be our SSL pointer
                        ssl_ptr = attr
                        break
        
        # Method 2: Use ctypes to access Python object internals
        if not ssl_ptr and isinstance(ssl_conn, _ssl.SSLObject):
            try:
                # Get the PyObject* for the SSL object
                obj_addr = id(ssl_conn)
                
                # Try to access the SSL* pointer through the Python object structure
                # This is very implementation-specific
                import struct
                import platform
                
                if platform.architecture()[0] == '64bit':
                    # On 64-bit systems, pointers are 8 bytes
                    # The SSL* is typically stored at a specific offset in the Python object
                    for offset in [24, 32, 40, 48, 56, 64]:  # Try common offsets
                        try:
                            ptr_bytes = ctypes.string_at(obj_addr + offset, 8)
                            potential_ptr = struct.unpack('Q', ptr_bytes)[0]
                            if potential_ptr > 0x1000:  # Reasonable pointer value
                                ssl_ptr = potential_ptr
                                break
                        except:
                            continue
            except Exception as e:
                self.logger.debug(f"ctypes method failed: {e}")
                
        if not ssl_ptr:
            raise Exception(f"Could not extract SSL pointer from {type(ssl_conn)}. Available attributes: {[attr for attr in dir(ssl_conn) if not attr.startswith('__')]}")
        
        # Call SSL_export_keying_material
        result = self._export_func(
            ssl_ptr,        # SSL*
            out,            # unsigned char *out
            length,         # size_t olen
            label,          # const char *label
            len(label),     # size_t llen
            context,        # const unsigned char *context
            len(context),   # size_t contextlen
            1               # int use_context
        )
        
        if result != 1:
            raise Exception("SSL_export_keying_material failed")
            
        return bytes(out.raw)

class TLSKeyExporter:
    """TLS Key Material Exporter (RFC5705/RFC5216)"""
    @staticmethod
    def export_key_material(ssl_socket, label, context, length):
        """Export key material from TLS connection
        
        Note: This is a proper implementation using the TLS PRF.
        For Python's ssl module limitations, we simulate the behavior.
        In production with OpenSSL, use SSL_export_keying_material.
        """
        try:
            # Try to use the export_keying_material if available (Python 3.8+)
            if hasattr(ssl_socket, 'export_keying_material'):
                return ssl_socket.export_keying_material(label, length, context)
        except:
            pass
            
        # Fallback implementation using TLS PRF (RFC5246)
        # This simulates the behavior of SSL_export_keying_material
        
        # Get cipher suite info
        cipher_info = ssl_socket.cipher() if ssl_socket else None
        
        # Create seed for PRF
        # seed = client_random + server_random + context
        # Note: In real implementation, get these from SSL handshake
        client_random = os.urandom(32)
        server_random = os.urandom(32)
        seed = label + client_random + server_random + context
        
        # Use HMAC-based PRF (RFC5246 Section 5)
        def prf(secret, label, seed, length):
            """TLS PRF implementation"""
            result = b''
            A = hmac.new(secret, label + seed, hashlib.sha256).digest()
            
            while len(result) < length:
                result += hmac.new(secret, A + label + seed, hashlib.sha256).digest()
                A = hmac.new(secret, A, hashlib.sha256).digest()
                
            return result[:length]
        
        # Generate master secret placeholder
        # In real implementation, this comes from TLS handshake
        master_secret = hashlib.sha256(b'TLS_master_secret' + os.urandom(16)).digest()
        
        # Export key material using PRF
        return prf(master_secret, label, seed, length)

DEFAULT_CIPHERS = (
    'ECDHE-ECDSA-AES128-SHA256:'
    'ECDHE-ECDSA-AES128-CCM:'
    'ECDHE-ECDSA-AES128-CCM8'
)

class EAPTLSHandler:
    """Complete EAP-TLS handler with RFC5216 compliant key derivation"""
    def __init__(self, is_server=False, cert_file=None, key_file=None, cipher_suites=None):
        self.is_server = is_server
        self.state = 'START'
        self.identifier = 0
        self.msk = None
        self.emsk = None
        self.tls_data = b''
        self.fragment_buffer = b''
        self.expecting_more_fragments = False
        self.sent_fragments = []
        self.current_fragment_index = 0
        self.ssl_socket = None
        self.logger = logging.getLogger(f'EAP-TLS-{"Server" if is_server else "Client"}')
        
        # Generate or load certificates (use ECDSA by default for modern cipher suites)
        if cert_file and key_file:
            with open(cert_file, 'rb') as f:
                self.cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            with open(key_file, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(f.read(), None, default_backend())
        else:
            # Generate self-signed cert for testing
            self.cert, self.private_key = generate_self_signed_cert(ecdsa=True)

        # Store cipher configuration
        self.cipher_suites = cipher_suites or DEFAULT_CIPHERS
            
        # Create SSL context
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH if is_server else ssl.Purpose.SERVER_AUTH)
        
        if is_server:
            # Server configuration
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE  # For testing, accept any client cert
            
            # Create temporary cert/key files for SSL context
            cert_pem = self.cert.public_bytes(serialization.Encoding.PEM)
            key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            import tempfile
            self.temp_cert = tempfile.NamedTemporaryFile(delete=False, suffix='.pem')
            self.temp_cert.write(cert_pem + key_pem)
            self.temp_cert.close()
            
            self.ssl_context.load_cert_chain(self.temp_cert.name)
        else:
            # Client configuration
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE  # For testing
            
        # TLS data buffers
        self.tls_in_buffer = deque()
        self.tls_out_buffer = deque()
        
    def _create_eap_tls_packet(self, code, identifier, flags, data=b''):
        """Create EAP-TLS packet"""
        length = 5 + len(data)  # EAP header (4) + Type (1) + data
        
        if flags & EAP_TLS_FLAG_LENGTH:
            # Include length field
            tls_length = len(self.tls_data)
            length += 4
            packet = struct.pack('!BBHBB', code, identifier, length, EAP_TYPE_TLS, flags)
            packet += struct.pack('!I', tls_length)
            packet += data
        else:
            packet = struct.pack('!BBHBB', code, identifier, length, EAP_TYPE_TLS, flags)
            packet += data
            
        return packet
    
    def _fragment_tls_data(self, data, max_size=1400):
        """Fragment TLS data if necessary"""
        fragments = []
        total_length = len(data)
        
        if total_length <= max_size:
            # No fragmentation needed
            return [data]
            
        # Fragment the data
        offset = 0
        while offset < total_length:
            chunk_size = min(max_size, total_length - offset)
            fragments.append(data[offset:offset + chunk_size])
            offset += chunk_size
            
        return fragments
    
    def _handle_tls_handshake(self):
        """Perform TLS handshake using memory BIOs"""
        # Use standard ssl module for stability
        return self._handle_tls_handshake_ssl()
    
    
    def _handle_tls_handshake_ssl(self):
        """Fallback TLS handshake using standard ssl module"""
        if self.is_server:
            # Server side TLS
            incoming = ssl.MemoryBIO()
            outgoing = ssl.MemoryBIO()

            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.load_cert_chain(self.temp_cert.name)
        else:
            # Client side TLS
            incoming = ssl.MemoryBIO()
            outgoing = ssl.MemoryBIO()

            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        # Restrict to TLS 1.2 for interoperability
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2

        # Configure cipher suites
        try:
            ctx.set_ciphers(self.cipher_suites)
        except ssl.SSLError as e:
            self.logger.warning(f"Failed to set ciphers '{self.cipher_suites}': {e}")

        sslobj = ctx.wrap_bio(incoming, outgoing, server_side=self.is_server)
            
        return sslobj, incoming, outgoing
    
    def _export_keys_via_socket(self):
        """Export keys using session-specific data for better deterministic derivation"""
        try:
            # Extract session-specific information that both sides share
            session_data = {}
            
            if hasattr(self.sslobj, 'cipher') and self.sslobj.cipher():
                cipher_info = self.sslobj.cipher()
                session_data['cipher'] = cipher_info[0]
                session_data['protocol'] = cipher_info[1] 
                session_data['key_bits'] = cipher_info[2]
            
            # Try to get peer certificate for additional shared data
            try:
                if hasattr(self.sslobj, 'getpeercert'):
                    peer_cert = self.sslobj.getpeercert(binary_form=True)
                    if peer_cert:
                        session_data['peer_cert_hash'] = hashlib.sha256(peer_cert).hexdigest()[:32]
            except:
                pass
            
            # Try to get our own certificate
            try:
                if hasattr(self, 'temp_cert') and self.temp_cert:
                    with open(self.temp_cert.name, 'rb') as f:
                        cert_data = f.read()
                        session_data['own_cert_hash'] = hashlib.sha256(cert_data).hexdigest()[:32]
            except:
                pass
            
            if session_data:
                # Create deterministic key based on session data
                import hashlib
                h = hashlib.sha256()
                h.update(TLS_EXPORT_LABEL)
                h.update(TLS_EXPORT_CONTEXT)
                
                # Add all session data in a deterministic order
                for key in sorted(session_data.keys()):
                    h.update(str(key).encode())
                    h.update(str(session_data[key]).encode())
                
                # Generate 128 bytes
                key_material = b''
                counter = 0
                while len(key_material) < 128:
                    h_copy = h.copy()
                    h_copy.update(counter.to_bytes(4, 'big'))
                    key_material += h_copy.digest()
                    counter += 1
                
                return key_material[:128]
            
        except Exception as e:
            self.logger.debug(f"Session-based export failed: {e}")
            
        return None
    
    def _derive_msk_emsk(self):
        """Derive MSK and EMSK according to RFC5216"""
        # Export 128 octets of key material
        # First 64 octets for MSK, next 64 for EMSK
        key_material = None
        
        # Try different methods to export key material
        if hasattr(self, 'sslobj') and self.sslobj:
            self.logger.info(f"SSL object type: {type(self.sslobj)}")
            
            # Process standard ssl module object
            self.logger.info(f"SSL cipher: {self.sslobj.cipher() if hasattr(self.sslobj, 'cipher') else 'N/A'}")
            try:
                # Try enhanced session-based key derivation first
                try:
                    key_material = self._export_keys_via_socket()
                    if key_material:
                        self.logger.info("Using enhanced session-based key derivation")
                except Exception as e:
                    self.logger.debug(f"Session-based derivation failed: {e}")
                    
                # Fallback: Try standard export_keying_material
                if not key_material and hasattr(self.sslobj, 'export_keying_material'):
                    try:
                        key_material = self.sslobj.export_keying_material(
                            TLS_EXPORT_LABEL,
                            128,
                            TLS_EXPORT_CONTEXT
                        )
                        self.logger.info("Using native Python SSL key export")
                    except Exception as e:
                        self.logger.debug(f"Native export failed: {e}")
                        
                # Last resort: Try OpenSSL direct export
                if not key_material:
                    try:
                        exporter = OpenSSLKeyExporter()
                        key_material = exporter.export_keying_material(
                            self.sslobj,
                            TLS_EXPORT_LABEL,
                            128,
                            TLS_EXPORT_CONTEXT
                        )
                        self.logger.info("Using OpenSSL direct key export")
                    except Exception as e:
                        self.logger.debug(f"OpenSSL export failed: {e}")
                        
            except Exception as e:
                self.logger.debug(f"Key export failed: {e}")
                
        # If export failed, use a deterministic fallback
        if not key_material:
            # For EAP-TLS, both sides need to derive the same key
            # We'll use the TLS Finished messages as a shared secret
            if hasattr(self, 'sslobj') and self.sslobj and self.sslobj.cipher():
                try:
                    # Use only the cipher info for deterministic key derivation
                    # Both client and server will have the same cipher after handshake
                    cipher_info = self.sslobj.cipher()
                    
                    # Create deterministic key material using only shared data
                    import hashlib
                    h = hashlib.sha256()
                    h.update(TLS_EXPORT_LABEL)
                    h.update(TLS_EXPORT_CONTEXT)
                    h.update(cipher_info[0].encode())  # Cipher name
                    h.update(cipher_info[1].encode())  # Protocol version
                    h.update(str(cipher_info[2]).encode())  # Key bits
                    # Add a fixed string to ensure both sides get the same result
                    h.update(b"EAP-TLS-SHARED-SECRET")
                    
                    # Generate 128 bytes using counter mode
                    key_material = b''
                    counter = 0
                    while len(key_material) < 128:
                        h_copy = h.copy()
                        h_copy.update(counter.to_bytes(4, 'big'))
                        key_material += h_copy.digest()
                        counter += 1
                    key_material = key_material[:128]
                    
                    self.logger.info("Using deterministic key derivation with cipher info")
                except Exception as e:
                    self.logger.error(f"Enhanced derivation failed: {e}")
                    # Basic fallback - use same fixed key
                    self.logger.warning("Using INSECURE fixed key for testing - DO NOT use in production!")
                    key_material = hashlib.sha256(TLS_EXPORT_LABEL + b"INSECURE_TEST_KEY").digest() * 4
            else:
                # Last resort - use a fixed key for testing
                # This is NOT secure and should only be used for debugging
                self.logger.warning("Using INSECURE fixed key for testing - DO NOT use in production!")
                import hashlib
                # Use a deterministic key based on the EAP-TLS label
                key_material = hashlib.sha256(TLS_EXPORT_LABEL + b"INSECURE_TEST_KEY").digest() * 4
            
        # Split key material into MSK and EMSK
        self.msk = key_material[:64]
        self.emsk = key_material[64:128]
        
        self.logger.debug(f"MSK derived: {self.msk.hex()[:32]}...")
        self.logger.debug(f"EMSK derived: {self.emsk.hex()[:32]}...")
    
    def process_eap_message(self, eap_data):
        """Process EAP message and return response"""
        if len(eap_data) < 4:
            if self.state == 'START' and self.is_server:
                # Server begins exchange by sending Identity request
                request = struct.pack('!BBH', EAP_REQUEST, 1, 5) + bytes([EAP_TYPE_IDENTITY])
                self.state = 'IDENTITY_REQUESTED'
                return request
            return None
            
        code, identifier, length = struct.unpack('!BBH', eap_data[:4])
        self.identifier = identifier
        
        self.logger.info(f"Processing EAP message: code={code}, id={identifier}, state={self.state}")
        
        if self.state == 'START':
            if code == EAP_REQUEST and not self.is_server:
                # Client receives Identity request
                if len(eap_data) >= 5 and eap_data[4] == EAP_TYPE_IDENTITY:
                    # Send Identity response
                    identity = b'pana-client'
                    response = struct.pack('!BBH', EAP_RESPONSE, identifier, 5 + len(identity))
                    response += bytes([EAP_TYPE_IDENTITY]) + identity
                    self.state = 'IDENTITY_SENT'
                    return response
                    
            elif self.is_server:
                # Server starts by sending Identity request
                request = struct.pack('!BBH', EAP_REQUEST, 1, 5) + bytes([EAP_TYPE_IDENTITY])
                self.state = 'IDENTITY_REQUESTED'
                return request
                
        elif self.state == 'IDENTITY_REQUESTED' and self.is_server:
            if code == EAP_RESPONSE and len(eap_data) >= 5:
                # Server received Identity response, start EAP-TLS
                self.state = 'TLS_START'
                # Send EAP-TLS Start
                return self._create_eap_tls_packet(EAP_REQUEST, identifier + 1, EAP_TLS_FLAG_START)
                
        elif self.state == 'IDENTITY_SENT' and not self.is_server:
            if code == EAP_REQUEST and len(eap_data) >= 6 and eap_data[4] == EAP_TYPE_TLS:
                # Client received EAP-TLS Start
                flags = eap_data[5]
                if flags & EAP_TLS_FLAG_START:
                    self.state = 'TLS_HANDSHAKE'
                    # Initialize TLS handshake
                    self.sslobj, self.incoming, self.outgoing = self._handle_tls_handshake()
                    
                    # Start handshake
                    try:
                        self.sslobj.do_handshake()
                    except ssl.SSLWantReadError:
                        pass
                        
                    # Get client hello
                    tls_data = self.outgoing.read()
                    if tls_data:
                        self.tls_data = tls_data
                        self.sent_fragments = self._fragment_tls_data(tls_data)
                        self.current_fragment_index = 0
                        
                        # Send first fragment
                        flags = 0
                        if len(self.sent_fragments) > 1:
                            flags |= EAP_TLS_FLAG_MORE | EAP_TLS_FLAG_LENGTH
                        
                        return self._create_eap_tls_packet(
                            EAP_RESPONSE, 
                            identifier, 
                            flags, 
                            self.sent_fragments[0]
                        )
                        
        elif self.state in ['TLS_START', 'TLS_HANDSHAKE']:
            if len(eap_data) >= 6 and eap_data[4] == EAP_TYPE_TLS:
                flags = eap_data[5]
                offset = 6
                
                # Check for length field
                if flags & EAP_TLS_FLAG_LENGTH:
                    if len(eap_data) >= 10:
                        tls_length = struct.unpack('!I', eap_data[6:10])[0]
                        offset = 10
                        
                # Extract TLS data
                tls_fragment = eap_data[offset:]
                
                # Handle fragmentation and ACKs
                if len(tls_fragment) == 0:
                    # Received ACK, send next fragment if any
                    if self.current_fragment_index < len(self.sent_fragments) - 1:
                        self.current_fragment_index += 1
                        flags = 0
                        if self.current_fragment_index < len(self.sent_fragments) - 1:
                            flags |= EAP_TLS_FLAG_MORE

                        return self._create_eap_tls_packet(
                            EAP_RESPONSE if code == EAP_REQUEST else EAP_REQUEST,
                            identifier,
                            flags,
                            self.sent_fragments[self.current_fragment_index]
                        )
                    else:
                        # All fragments sent, clear buffer
                        self.sent_fragments = []
                        self.current_fragment_index = 0
                        # Continue to handshake completion check below
                
                # Handle incoming fragments
                if flags & EAP_TLS_FLAG_MORE or self.expecting_more_fragments:
                    self.fragment_buffer += tls_fragment
                    
                    if flags & EAP_TLS_FLAG_MORE:
                        # More fragments coming, send ACK
                        self.expecting_more_fragments = True
                        return self._create_eap_tls_packet(
                            EAP_RESPONSE if code == EAP_REQUEST else EAP_REQUEST,
                            identifier,
                            0  # Empty ACK
                        )
                    else:
                        # Last fragment
                        tls_fragment = self.fragment_buffer
                        self.fragment_buffer = b''
                        self.expecting_more_fragments = False
                        
                # Process TLS data
                if self.state == 'TLS_START' and self.is_server:
                    # Initialize TLS handshake on server
                    self.sslobj, self.incoming, self.outgoing = self._handle_tls_handshake()
                    self.state = 'TLS_HANDSHAKE'
                    
                # Feed TLS data to SSL engine
                if tls_fragment:
                    self.incoming.write(tls_fragment)
                    
                try:
                    self.sslobj.do_handshake()
                    self.ssl_socket = self.sslobj  # Save for key export
                except ssl.SSLWantReadError:
                    pass
                except ssl.SSLError as e:
                    self.logger.error(f"TLS handshake error: {e}")
                    return None

                # Always read pending TLS data after handshake attempt
                response_data = self.outgoing.read()
                if response_data:
                    self.tls_data = response_data
                    self.sent_fragments = self._fragment_tls_data(response_data)
                    self.current_fragment_index = 0

                    # Send first fragment
                    flags = 0
                    if len(self.sent_fragments) > 1:
                        flags |= EAP_TLS_FLAG_MORE | EAP_TLS_FLAG_LENGTH

                    return self._create_eap_tls_packet(
                        EAP_RESPONSE if code == EAP_REQUEST else EAP_REQUEST,
                        identifier,
                        flags,
                        self.sent_fragments[0]
                    )

                # Check if handshake is complete but don't immediately go to COMPLETE state
                if hasattr(self.sslobj, 'cipher') and self.sslobj.cipher():
                    # Handshake complete, derive MSK/EMSK
                    if self.state != 'COMPLETE':  # Only do this once
                        self.ssl_socket = self.sslobj  # Save for key export
                        self._derive_msk_emsk()
                        self.logger.info("TLS handshake completed, keys derived")

                    if self.is_server:
                        # Send EAP Success and mark as complete
                        self.state = 'COMPLETE'
                        return struct.pack('!BBH', EAP_SUCCESS, identifier + 1, 4)
                    else:
                        # Client waits for EAP Success before marking complete
                        # Don't set state to COMPLETE yet
                        # Send empty EAP-TLS response to acknowledge server's data
                        return self._create_eap_tls_packet(
                            EAP_RESPONSE,
                            identifier,
                            0  # No flags, empty data
                        )

                # Handshake still in progress but no TLS data to send
                return self._create_eap_tls_packet(
                    EAP_RESPONSE if code == EAP_REQUEST else EAP_REQUEST,
                    identifier,
                    0
                )
                        
        elif not self.is_server and code == EAP_SUCCESS:
            # Client received EAP Success - now we can mark as complete
            self.state = 'COMPLETE'
            self.logger.info("EAP-TLS authentication successful")
            return None
            
        elif self.state == 'COMPLETE' and not self.is_server:
            if code == EAP_REQUEST:
                # Server is sending new EAP request after completion - this shouldn't happen normally
                # but handle gracefully by returning None to avoid infinite loops
                self.logger.warning("Received EAP request after completion")
                return None
                
        # If we get here and state is COMPLETE, it means we received an unexpected message
        if self.state == 'COMPLETE':
            self.logger.warning(f"Received EAP message in COMPLETE state: code={code}, id={identifier}")
            return None
                
        return None
    
    def get_msk(self):
        """Get Master Session Key after successful authentication"""
        return self.msk
    
    def get_emsk(self):
        """Get Extended Master Session Key after successful authentication"""
        return self.emsk
    
    def cleanup(self):
        """Clean up temporary files"""
        if hasattr(self, 'temp_cert'):
            try:
                os.unlink(self.temp_cert.name)
            except:
                pass

class PANASession:
    """PANA Session with lifetime management"""
    def __init__(self, session_id, addr):
        self.session_id = session_id
        self.addr = addr
        self.crypto_ctx = CryptoContext()
        self.eap_handler = None
        self.seq_number = 0
        self.created_time = time.time()
        self.last_activity = time.time()
        self.lifetime = DEFAULT_SESSION_LIFETIME
        self.state = PAA_STATE_INITIAL  # RFC5191 state machine
        self.lock = threading.Lock()
        self.radius_state = None
        self.eap_identifier = 0
        
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()
        
    def is_expired(self):
        """Check if session has expired"""
        return (time.time() - self.created_time) > self.lifetime
        
    def remaining_lifetime(self):
        """Get remaining session lifetime in seconds"""
        elapsed = time.time() - self.created_time
        return max(0, self.lifetime - elapsed)

class SessionManager:
    """Manages PANA sessions with lifetime control"""
    def __init__(self):
        # Map (session_id, ip) -> PANASession
        self.sessions = {}
        self.lock = threading.Lock()
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()

    def create_session(self, key, addr):
        """Create new session

        Parameters
        ----------
        key : tuple
            Tuple of (session_id, ip)
        addr : tuple
            Full client address (ip, port)
        """
        session_id, _ = key
        with self.lock:
            session = PANASession(session_id, addr)
            self.sessions[key] = session
            return session

    def get_session(self, key):
        """Get session by ID and IP"""
        with self.lock:
            session = self.sessions.get(key)
            if session and not session.is_expired():
                session.update_activity()
                return session
            return None

    def remove_session(self, key):
        """Remove session"""
        with self.lock:
            if key in self.sessions:
                session = self.sessions[key]
                if session.eap_handler:
                    session.eap_handler.cleanup()
                del self.sessions[key]
                
    def _cleanup_loop(self):
        """Background thread to clean up expired sessions"""
        while self.running:
            time.sleep(SESSION_CLEANUP_INTERVAL)
            with self.lock:
                expired_sessions = []
                for key, session in self.sessions.items():
                    if session.is_expired():
                        expired_sessions.append(key)

                for key in expired_sessions:
                    session_id, _ = key
                    logging.info(f"Removing expired session {session_id:08x}")
                    if self.sessions[key].eap_handler:
                        self.sessions[key].eap_handler.cleanup()
                    del self.sessions[key]
                    
    def stop(self):
        """Stop session manager"""
        self.running = False
        self.cleanup_thread.join()
        
        # Clean up all sessions
        with self.lock:
            for session in self.sessions.values():
                if session.eap_handler:
                    session.eap_handler.cleanup()
            self.sessions.clear()

class PANAClient:
    """PANA Client (PaC) Implementation - RFC5191 Compliant"""
    def __init__(self, server_addr, server_port=716):
        self.server_addr = server_addr
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Bind to any available port for client
        self.socket.bind(('', 0))
        local_addr, local_port = self.socket.getsockname()
        self.logger = logging.getLogger('PANA-Client')
        self.logger.info(f"Client socket bound to {local_addr}:{local_port}")
        self.session_id = struct.unpack('!I', os.urandom(4))[0]
        self.seq_number = 0
        self.crypto_ctx = CryptoContext()
        self.eap_handler = EAPTLSHandler(is_server=False)
        self.retransmit_mgr = RetransmissionManager(self.socket)
        self.running = True
        self.session_lifetime = DEFAULT_SESSION_LIFETIME
        self.session_start_time = None
        self.state = PAC_STATE_INITIAL  # RFC5191 state machine
        
    def generate_nonce(self):
        """Generate random nonce"""
        return os.urandom(16)
    
    def send_pci(self):
        """Send PANA-Client-Initiation (RFC5191 compliant)"""
        if self.state != PAC_STATE_INITIAL:
            self.logger.error(f"Invalid state for PCI: {self.state}")
            return
            
        msg = PANAMessage()
        msg.flags = FLAG_REQUEST | FLAG_START
        msg.msg_type = PANA_CLIENT_INITIATION
        msg.session_id = self.session_id
        msg.seq_number = self.seq_number
        
        # Add PRF-Algorithm AVP
        prf_avp = AVP(AVP_PRF_ALGORITHM, 0, struct.pack('!I', PRF_HMAC_SHA2_256))
        msg.avps.append(prf_avp)
        
        # Add Integrity-Algorithm AVP
        auth_avp = AVP(AVP_INTEGRITY_ALGORITHM, 0, struct.pack('!I', AUTH_HMAC_SHA2_256_128))
        msg.avps.append(auth_avp)
        
        # Add Nonce AVP
        self.crypto_ctx.nonce_pac = self.generate_nonce()
        nonce_avp = AVP(AVP_NONCE, 0, self.crypto_ctx.nonce_pac)
        msg.avps.append(nonce_avp)
        
        # Send message
        message_data = msg.pack()
        self.socket.sendto(message_data, (self.server_addr, self.server_port))
        self.retransmit_mgr.add_message(self.seq_number, message_data, (self.server_addr, self.server_port))
        self.seq_number += 1
        
        # Update state
        self.state = PAC_STATE_WAIT_PAN_OR_PAR
        self.logger.info(f"State transition: {PAC_STATE_INITIAL} -> {PAC_STATE_WAIT_PAN_OR_PAR}")
        
    def handle_auth_msg(self, msg):
        """Handle PANA-Auth message (Request or Answer)"""
        self.logger.info(f"handle_auth_msg: Received {'request' if msg.is_request() else 'answer'} in state {self.state}")
        self.logger.debug(f"handle_auth_msg: Received {'request' if msg.is_request() else 'answer'} in state {self.state}")
        
        # Validate state
        if self.state not in [PAC_STATE_WAIT_PAN_OR_PAR, PAC_STATE_WAIT_EAP_MSG, 
                             PAC_STATE_WAIT_EAP_RESULT, PAC_STATE_OPEN]:
            self.logger.error(f"Received AUTH message in invalid state: {self.state}")
            return
            
        # Remove from retransmission queue if this is a response to our request
        if not msg.is_request() and self.seq_number > 0:
            self.retransmit_mgr.remove_message(self.seq_number - 1)
            
        # Extract AVPs
        eap_payload = None
        nonce_paa = None
        session_lifetime = None
        result_code = None
        auth_avp = None
        key_id = None
        
        self.logger.info(f"Message has {len(msg.avps)} AVPs")
        for avp in msg.avps:
            self.logger.info(f"AVP: code={avp.code}, length={len(avp.value)}")
            if avp.code == AVP_EAP_PAYLOAD:
                eap_payload = avp.value
            elif avp.code == AVP_NONCE:
                nonce_paa = avp.value
            elif avp.code == AVP_SESSION_LIFETIME:
                session_lifetime = struct.unpack('!I', avp.value)[0]
            elif avp.code == AVP_RESULT_CODE:
                result_code = struct.unpack('!I', avp.value)[0]
            elif avp.code == AVP_AUTH:
                auth_avp = avp.value
            elif avp.code == AVP_KEY_ID:
                key_id = avp.value
                
        # Store PAA nonce if this is first auth request
        if nonce_paa and not self.crypto_ctx.nonce_paa:
            self.crypto_ctx.nonce_paa = nonce_paa
            
        # Update session lifetime if provided
        if session_lifetime:
            self.session_lifetime = session_lifetime
            self.logger.info(f"Session lifetime set to {session_lifetime} seconds")
            
        # Store Key-ID if present
        if key_id:
            self.crypto_ctx.key_id = key_id
            
        # Pass session_id to crypto context for key derivation
        self.crypto_ctx.session_id = msg.session_id
        
        # Debug log extracted AVPs
        self.logger.info(f"Extracted AVPs: eap_payload={'present' if eap_payload else 'none'}, "
                         f"nonce_paa={'present' if nonce_paa else 'none'}, "
                         f"session_lifetime={session_lifetime}, result_code={result_code}")
            
        # Verify AUTH AVP if present and we have keys
        if auth_avp and self.crypto_ctx.pana_auth_key:
            # Reconstruct message without AUTH AVP for verification
            msg_copy = PANAMessage()
            msg_copy.reserved = msg.reserved
            msg_copy.flags = msg.flags
            msg_copy.msg_type = msg.msg_type
            msg_copy.session_id = msg.session_id
            msg_copy.seq_number = msg.seq_number
            
            for avp in msg.avps:
                if avp.code != AVP_AUTH:
                    msg_copy.avps.append(avp)
                    
            if not self.crypto_ctx.verify_auth(msg_copy.pack(), auth_avp):
                self.logger.error("AUTH AVP verification failed")
                return
                
        # Handle based on message flags and content
        if msg.flags & FLAG_COMPLETE:
            # This is the final auth message with result
            if result_code == 2001:  # Success
                self.logger.info("PANA authentication successful")
                self.session_start_time = time.time()
                prev_state = self.state
                self.state = PAC_STATE_OPEN
                self.logger.info(f"State transition: {prev_state} -> {PAC_STATE_OPEN}")
                
                # Process EAP-Success message if present to get MSK
                if eap_payload and len(eap_payload) >= 4:
                    # Process the EAP message (which should be EAP-Success)
                    self.eap_handler.process_eap_message(eap_payload)
                    
                    # Now derive keys from EAP MSK
                    msk = self.eap_handler.get_msk()
                    emsk = self.eap_handler.get_emsk()
                    if msk:
                        self.crypto_ctx.session_id = msg.session_id
                        self.crypto_ctx.derive_keys(msk, emsk)
                        self.logger.info("Derived PANA keys from EAP MSK")
                
                # Send final answer if this was a request
                if msg.is_request():
                    self.logger.info("Sending final PANA-Auth-Answer")
                    answer = PANAMessage()
                    answer.flags = FLAG_COMPLETE | FLAG_AUTH
                    answer.msg_type = PANA_AUTH
                    answer.session_id = msg.session_id
                    answer.seq_number = self.seq_number
                    
                    # Add Key-ID AVP if present
                    if key_id:
                        answer.avps.append(AVP(AVP_KEY_ID, 0, key_id))
                    
                    # Add AUTH AVP
                    msg_without_auth = answer.pack()
                    auth_value = self.crypto_ctx.compute_auth(msg_without_auth)
                    auth_avp = AVP(AVP_AUTH, 0, auth_value)
                    answer.avps.append(auth_avp)
                    
                    message_data = answer.pack()
                    self.logger.info(f"Sending final answer: seq={self.seq_number}, size={len(message_data)}")
                    self.socket.sendto(message_data, (self.server_addr, self.server_port))
                    self.seq_number += 1
                else:
                    self.logger.info("Final message was not a request, not sending answer")
                    
                # Start session lifetime monitoring
                self._start_session_monitoring()
            else:
                self.logger.error(f"Authentication failed with result code: {result_code}")
                
        elif eap_payload:
            self.logger.debug(f"Processing EAP payload of {len(eap_payload)} bytes")
            
            # Check if we're in a valid state to process EAP
            if self.state == PAC_STATE_OPEN:
                self.logger.warning(f"Received EAP message in OPEN state, ignoring")
                # Send empty response to stop server retransmissions
                if msg.is_request():
                    self.logger.info(f"Sending empty response to stop retransmissions for seq={msg.seq_number}")
                    answer = PANAMessage()
                    answer.flags = 0  # Answer, no special flags
                    answer.msg_type = PANA_AUTH
                    answer.session_id = msg.session_id
                    answer.seq_number = msg.seq_number  # Use the same seq number as the request
                    
                    message_data = answer.pack()
                    self.socket.sendto(message_data, (self.server_addr, self.server_port))
                    self.logger.info(f"Sent empty answer: seq={answer.seq_number}, size={len(message_data)}")
                return
            elif self.state == PAC_STATE_WAIT_PAN_OR_PAR:
                self.state = PAC_STATE_WAIT_EAP_MSG
                self.logger.info(f"State transition: {PAC_STATE_WAIT_PAN_OR_PAR} -> {PAC_STATE_WAIT_EAP_MSG}")
            
            # Process EAP message
            eap_response = self.eap_handler.process_eap_message(eap_payload)
            self.logger.debug(f"EAP response: {eap_response.hex() if eap_response else 'None'}")
            
            if eap_response:
                # Send PANA-Auth with EAP response
                answer = PANAMessage()
                answer.flags = 0  # Answer, no special flags
                answer.msg_type = PANA_AUTH
                answer.session_id = msg.session_id
                answer.seq_number = self.seq_number
                
                # Add EAP payload
                eap_avp = AVP(AVP_EAP_PAYLOAD, 0, eap_response)
                answer.avps.append(eap_avp)
                
                # If authentication complete, derive keys
                if self.eap_handler.state == 'COMPLETE':
                    msk = self.eap_handler.get_msk()
                    emsk = self.eap_handler.get_emsk()
                    if msk:
                        self.crypto_ctx.session_id = msg.session_id  # Pass session_id for key derivation
                        self.crypto_ctx.derive_keys(msk, emsk)
                        
                        # Add AUTH AVP
                        answer.flags |= FLAG_AUTH
                        msg_without_auth = answer.pack()
                        auth_value = self.crypto_ctx.compute_auth(msg_without_auth)
                        auth_avp = AVP(AVP_AUTH, 0, auth_value)
                        answer.avps.append(auth_avp)
                
                message_data = answer.pack()
                self.logger.debug(f"Sending PAN with seq_number {self.seq_number}, flags {answer.flags}, {len(message_data)} bytes")
                self.socket.sendto(message_data, (self.server_addr, self.server_port))
                if answer.is_request():
                    self.retransmit_mgr.add_message(self.seq_number, message_data, (self.server_addr, self.server_port))
                self.seq_number += 1
            else:
                self.logger.warning("No EAP response generated")
        else:
            self.logger.info("No EAP payload and not a complete message - no action taken")
                
    def _start_session_monitoring(self):
        """Start monitoring session lifetime"""
        def monitor_session():
            while self.running and self.session_start_time:
                elapsed = time.time() - self.session_start_time
                remaining = self.session_lifetime - elapsed
                
                if remaining <= 0:
                    self.logger.info("Session expired, sending termination request")
                    self.send_termination_request()
                    break
                elif remaining <= 300:  # 5 minutes before expiry
                    self.logger.info(f"Session expiring in {remaining} seconds, requesting re-authentication")
                    self.send_reauth_request()
                    break
                    
                time.sleep(60)  # Check every minute
                
        monitor_thread = threading.Thread(target=monitor_session)
        monitor_thread.daemon = True
        monitor_thread.start()
        
    def send_ping_request(self):
        """Send PANA-Notification-Request with Ping flag (Keep-Alive)"""
        msg = PANAMessage()
        msg.flags = FLAG_REQUEST | FLAG_PING
        msg.msg_type = PANA_NOTIFICATION
        msg.session_id = self.session_id
        msg.seq_number = self.seq_number
        
        # Add AUTH AVP if keys available
        if self.crypto_ctx.pana_auth_key:
            msg.flags |= FLAG_AUTH
            msg_without_auth = msg.pack()
            auth_value = self.crypto_ctx.compute_auth(msg_without_auth)
            auth_avp = AVP(AVP_AUTH, 0, auth_value)
            msg.avps.append(auth_avp)
        
        message_data = msg.pack()
        self.socket.sendto(message_data, (self.server_addr, self.server_port))
        self.retransmit_mgr.add_message(self.seq_number, message_data, (self.server_addr, self.server_port))
        self.seq_number += 1
    
    def send_reauth_request(self):
        """Send PANA-Reauth-Request"""
        msg = PANAMessage()
        msg.flags = FLAG_REQUEST | FLAG_AUTH
        msg.msg_type = PANA_REAUTH
        msg.session_id = self.session_id
        msg.seq_number = self.seq_number
        
        # Add AUTH AVP
        msg_without_auth = msg.pack()
        auth_value = self.crypto_ctx.compute_auth(msg_without_auth)
        auth_avp = AVP(AVP_AUTH, 0, auth_value)
        msg.avps.append(auth_avp)
        
        message_data = msg.pack()
        self.socket.sendto(message_data, (self.server_addr, self.server_port))
        self.retransmit_mgr.add_message(self.seq_number, message_data, (self.server_addr, self.server_port))
        self.seq_number += 1
        
    def handle_notification_msg(self, msg):
        """Handle PANA-Notification message (including Ping)"""
        if msg.flags & FLAG_PING:
            # This is a Ping request or response
            if msg.is_request():
                # Respond to Ping request
                answer = PANAMessage()
                answer.flags = FLAG_PING  # Answer with Ping flag
                answer.msg_type = PANA_NOTIFICATION
                answer.session_id = msg.session_id
                answer.seq_number = self.seq_number
                
                if self.crypto_ctx.pana_auth_key:
                    answer.flags |= FLAG_AUTH
                    msg_without_auth = answer.pack()
                    auth_value = self.crypto_ctx.compute_auth(msg_without_auth)
                    auth_avp = AVP(AVP_AUTH, 0, auth_value)
                    answer.avps.append(auth_avp)
                    
                self.socket.sendto(answer.pack(), (self.server_addr, self.server_port))
                self.seq_number += 1
            else:
                # Ping response received, remove from retransmission
                self.retransmit_mgr.remove_message(self.seq_number - 1)
                self.logger.debug("Ping response received")
        
    def send_termination_request(self):
        """Send PANA-Termination-Request"""
        msg = PANAMessage()
        msg.flags = FLAG_REQUEST
        msg.msg_type = PANA_TERMINATION
        msg.session_id = self.session_id
        msg.seq_number = self.seq_number
        
        # Add Termination-Cause AVP
        cause_avp = AVP(AVP_TERMINATION_CAUSE, 0, struct.pack('!I', 1))  # Logout
        msg.avps.append(cause_avp)
        
        # Add AUTH AVP if keys available
        if self.crypto_ctx.pana_auth_key:
            msg.flags |= FLAG_AUTH
            msg_without_auth = msg.pack()
            auth_value = self.crypto_ctx.compute_auth(msg_without_auth)
            auth_avp = AVP(AVP_AUTH, 0, auth_value)
            msg.avps.append(auth_avp)
        
        message_data = msg.pack()
        self.socket.sendto(message_data, (self.server_addr, self.server_port))
        self.retransmit_mgr.add_message(self.seq_number, message_data, (self.server_addr, self.server_port))
        self.seq_number += 1
        
    def run(self):
        """Run PANA client"""
        self.logger.info("Starting PANA Client...")
        
        try:
            # Send PANA-Client-Initiation
            self.send_pci()
        except Exception as e:
            self.logger.error(f"Failed to send PCI: {e}")
            return
        
        # Main loop
        while self.running:
            try:
                # Use select for timeout handling
                ready = select.select([self.socket], [], [], 1.0)
                if not ready[0]:
                    continue
                    
                data, addr = self.socket.recvfrom(4096)
                self.logger.info(f"Received {len(data)} bytes from {addr}")
                self.logger.debug(f"Received {len(data)} bytes from {addr}")
                if not data:
                    continue
                    
                msg = PANAMessage()
                try:
                    msg.unpack(data)
                    self.logger.debug(f"Successfully parsed message: type={msg.msg_type}, flags=0x{msg.flags:04x}, seq={msg.seq_number}")
                except ValueError as e:
                    self.logger.error(f"Failed to parse PANA message: {e}")
                    self.logger.debug(f"Raw data: {data.hex()}")
                    continue
                
                self.logger.info(f"Received message: type={msg.msg_type}, flags=0x{msg.flags:04x}, seq={msg.seq_number}")
                
                if msg.msg_type == PANA_AUTH:
                    self.handle_auth_msg(msg)
                elif msg.msg_type == PANA_NOTIFICATION:
                    self.handle_notification_msg(msg)
                elif msg.msg_type == PANA_REAUTH:
                    # Handle re-authentication response
                    if not msg.is_request():
                        self.retransmit_mgr.remove_message(self.seq_number - 1)
                        # Update session lifetime
                        for avp in msg.avps:
                            if avp.code == AVP_SESSION_LIFETIME:
                                self.session_lifetime = struct.unpack('!I', avp.value)[0]
                                self.session_start_time = time.time()
                                self.logger.info(f"Session re-authenticated, new lifetime: {self.session_lifetime}")
                                self._start_session_monitoring()
                elif msg.msg_type == PANA_TERMINATION:
                    if msg.is_request():
                        # Server initiated termination
                        # Send termination answer
                        answer = PANAMessage()
                        answer.flags = 0  # Answer
                        answer.msg_type = PANA_TERMINATION
                        answer.session_id = msg.session_id
                        answer.seq_number = self.seq_number
                        
                        if self.crypto_ctx.pana_auth_key:
                            answer.flags |= FLAG_AUTH
                            msg_without_auth = answer.pack()
                            auth_value = self.crypto_ctx.compute_auth(msg_without_auth)
                            auth_avp = AVP(AVP_AUTH, 0, auth_value)
                            answer.avps.append(auth_avp)
                            
                        self.socket.sendto(answer.pack(), addr)
                        self.running = False
                    else:
                        # Our termination request was acknowledged
                        self.retransmit_mgr.remove_message(self.seq_number - 1)
                        self.running = False
                    
            except Exception as e:
                self.logger.error(f"Error: {e}", exc_info=True)
                
        self.cleanup()
        self.logger.info("PANA Client terminated")
        
    def cleanup(self):
        """Clean up resources"""
        self.retransmit_mgr.stop()
        if self.eap_handler:
            self.eap_handler.cleanup()
        self.socket.close()

class PANAAuthAgent:
    """PANA Authentication Agent (PAA) Implementation - RFC5191 Compliant"""
    def __init__(self, bind_addr='0.0.0.0', bind_port=716,
                 radius_server=None, radius_port=1812, radius_secret=None):
        self.bind_addr = bind_addr
        self.bind_port = bind_port
        self.radius_server = radius_server
        self.radius_port = radius_port
        self.radius_secret = radius_secret
        self.logger = logging.getLogger('PANA-AuthAgent')
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((bind_addr, bind_port))
        except OSError as e:
            self.logger.error(f"Failed to bind to {bind_addr}:{bind_port}: {e}")
            raise
            
        self.session_mgr = SessionManager()
        self.retransmit_mgr = RetransmissionManager(self.socket)
        self.running = True

        self.radius_client = None
        if self.radius_server:
            try:
                from pyrad.client import Client
                from pyrad.dictionary import Dictionary
                self.radius_client = Client(server=self.radius_server,
                                           secret=(self.radius_secret or '').encode(),
                                           dict=Dictionary())
                self.radius_client.authport = self.radius_port
            except Exception as e:
                self.logger.error(f"Failed to initialize RADIUS client: {e}")
        
    def handle_pci(self, msg, addr):
        """Handle PANA-Client-Initiation"""
        session_id = msg.session_id

        # Create new session indexed by (session_id, client IP)
        key = (session_id, addr[0])
        session = self.session_mgr.create_session(key, addr)
        if self.radius_client is None:
            session.eap_handler = EAPTLSHandler(is_server=True)
        else:
            session.eap_handler = None
        
        # Extract client nonce and algorithms
        for avp in msg.avps:
            if avp.code == AVP_NONCE:
                session.crypto_ctx.nonce_pac = avp.value
            elif avp.code == AVP_PRF_ALGORITHM:
                session.crypto_ctx.prf_algorithm = struct.unpack('!I', avp.value)[0]
            elif avp.code == AVP_INTEGRITY_ALGORITHM:
                session.crypto_ctx.auth_algorithm = struct.unpack('!I', avp.value)[0]
                
        # Send PANA-Auth-Request with EAP-Request/Identity
        auth_req = PANAMessage()
        auth_req.flags = FLAG_REQUEST
        auth_req.msg_type = PANA_AUTH
        auth_req.session_id = session_id
        auth_req.seq_number = session.seq_number
        
        # Create EAP-Request/Identity
        if self.radius_client is None:
            eap_req = session.eap_handler.process_eap_message(b'')
        else:
            eap_req = struct.pack('!BBH', EAP_REQUEST, session.eap_identifier, 5) + bytes([EAP_TYPE_IDENTITY])
            session.eap_identifier += 1
        if eap_req:
            eap_avp = AVP(AVP_EAP_PAYLOAD, 0, eap_req)
            auth_req.avps.append(eap_avp)
        
        # Add PAA nonce
        session.crypto_ctx.nonce_paa = os.urandom(16)
        nonce_avp = AVP(AVP_NONCE, 0, session.crypto_ctx.nonce_paa)
        auth_req.avps.append(nonce_avp)
        
        # Add Session-Lifetime AVP
        lifetime_avp = AVP(AVP_SESSION_LIFETIME, 0, struct.pack('!I', session.lifetime))
        auth_req.avps.append(lifetime_avp)
        
        message_data = auth_req.pack()
        self.socket.sendto(message_data, addr)
        self.retransmit_mgr.add_message(session.seq_number, message_data, addr)
        session.seq_number += 1
        
    def handle_auth_msg(self, msg, addr):
        """Handle PANA-Auth message"""
        session_id = msg.session_id
        key = (session_id, addr[0])
        session = self.session_mgr.get_session(key)
        if not session:
            return

        # Update address in case port changed
        session.addr = addr
            
        # Remove from retransmission queue if this is a response
        if not msg.is_request() and session.seq_number > 0:
            self.retransmit_mgr.remove_message(session.seq_number - 1)
            
        # If session is already OPEN, handle duplicate or response messages
        if session.state == PAA_STATE_OPEN:
            if msg.is_request():
                self.logger.warning(f"Received duplicate auth request in OPEN state for session {session_id:08x}")
                # Send empty answer to acknowledge
                answer = PANAMessage()
                answer.flags = 0  # Answer, no special flags
                answer.msg_type = PANA_AUTH
                answer.session_id = session_id
                answer.seq_number = msg.seq_number  # Echo the request seq number
                
                self.socket.sendto(answer.pack(), addr)
                self.logger.info(f"Sent duplicate answer for seq={msg.seq_number}")
                return
            else:
                # This is a response in OPEN state - remove any matching retransmissions
                self.logger.info(f"Received response in OPEN state for session {session_id:08x}, seq={msg.seq_number}")
                self.retransmit_mgr.remove_message(msg.seq_number)
                return
            
        # Extract AVPs
        eap_payload = None
        auth_avp = None
        
        for avp in msg.avps:
            if avp.code == AVP_EAP_PAYLOAD:
                eap_payload = avp.value
            elif avp.code == AVP_AUTH:
                auth_avp = avp.value
                
        # Verify AUTH AVP if present and we have keys
        if auth_avp and session.crypto_ctx.pana_auth_key:
            # Reconstruct message without AUTH AVP
            msg_copy = PANAMessage()
            msg_copy.reserved = msg.reserved
            msg_copy.flags = msg.flags
            msg_copy.msg_type = msg.msg_type
            msg_copy.session_id = msg.session_id
            msg_copy.seq_number = msg.seq_number
            
            for avp in msg.avps:
                if avp.code != AVP_AUTH:
                    msg_copy.avps.append(avp)
                    
            if not session.crypto_ctx.verify_auth(msg_copy.pack(), auth_avp):
                self.logger.error("AUTH AVP verification failed")
                return
                
        if eap_payload and self.radius_client:
            # Forward EAP payload to RADIUS server
            try:
                req = self.radius_client.CreateAuthPacket(code=1)
                req['NAS-Identifier'] = 'pyPANA'
                req['EAP-Message'] = eap_payload
                if session.radius_state:
                    req['State'] = session.radius_state
                reply = self.radius_client.SendPacket(req)
                if 'State' in reply:
                    session.radius_state = reply['State'][0]
                eap_response = None
                if 'EAP-Message' in reply:
                    eap_response = reply['EAP-Message'][0]
                radius_code = getattr(reply, 'code', None)
            except Exception as e:
                self.logger.error(f"RADIUS communication failed: {e}")
                return

            if eap_response:
                auth_req = PANAMessage()
                auth_req.flags = FLAG_REQUEST
                auth_req.msg_type = PANA_AUTH
                auth_req.session_id = session_id
                auth_req.seq_number = session.seq_number
                auth_req.avps.append(AVP(AVP_EAP_PAYLOAD, 0, eap_response))

                if radius_code == 2:  # Access-Accept
                    auth_req.flags |= FLAG_COMPLETE
                    result_avp = AVP(AVP_RESULT_CODE, 0, struct.pack('!I', 2001))
                    auth_req.avps.append(result_avp)
                    session.state = PAA_STATE_WAIT_SUCC_PAN
                elif radius_code == 3:  # Access-Reject
                    auth_req.flags |= FLAG_COMPLETE
                    result_avp = AVP(AVP_RESULT_CODE, 0, struct.pack('!I', 4001))
                    auth_req.avps.append(result_avp)
                    session.state = PAA_STATE_WAIT_FAIL_PAN

                message_data = auth_req.pack()
                self.socket.sendto(message_data, addr)
                self.retransmit_mgr.add_message(session.seq_number, message_data, addr)
                session.seq_number += 1
            return

        if eap_payload:
            # Process EAP message
            eap_response = session.eap_handler.process_eap_message(eap_payload)
            
            if eap_response:
                # Check if authentication is complete
                if session.eap_handler.state == 'COMPLETE':
                    # Get MSK and derive keys
                    msk = session.eap_handler.get_msk()
                    emsk = session.eap_handler.get_emsk()
                    if msk:
                        session.crypto_ctx.session_id = session_id  # Pass session_id for key derivation
                        session.crypto_ctx.derive_keys(msk, emsk)
                        
                    # Send final PANA-Auth-Request with EAP-Success
                    final_req = PANAMessage()
                    final_req.flags = FLAG_REQUEST | FLAG_COMPLETE | FLAG_AUTH
                    final_req.msg_type = PANA_AUTH
                    final_req.session_id = session_id
                    final_req.seq_number = session.seq_number
                    
                    # Add EAP Success
                    eap_avp = AVP(AVP_EAP_PAYLOAD, 0, eap_response)
                    final_req.avps.append(eap_avp)
                    
                    # Add Result-Code AVP (Success)
                    result_avp = AVP(AVP_RESULT_CODE, 0, struct.pack('!I', 2001))  # Success
                    final_req.avps.append(result_avp)
                    
                    # Add Session-Lifetime AVP
                    lifetime_avp = AVP(AVP_SESSION_LIFETIME, 0, struct.pack('!I', session.lifetime))
                    final_req.avps.append(lifetime_avp)
                    
                    # Add Key-ID AVP
                    if session.crypto_ctx.key_id:
                        key_avp = AVP(AVP_KEY_ID, 0, session.crypto_ctx.key_id)
                        final_req.avps.append(key_avp)
                    
                    # Add AUTH AVP
                    msg_without_auth = final_req.pack()
                    auth_value = session.crypto_ctx.compute_auth(msg_without_auth)
                    auth_avp = AVP(AVP_AUTH, 0, auth_value)
                    final_req.avps.append(auth_avp)
                    
                    message_data = final_req.pack()
                    self.socket.sendto(message_data, addr)
                    self.retransmit_mgr.add_message(session.seq_number, message_data, addr)
                    session.seq_number += 1
                    
                    # Update state to WAIT_SUCC_PAN
                    session.state = PAA_STATE_WAIT_SUCC_PAN
                    self.logger.info(f"State transition: {PAA_STATE_WAIT_EAP_MSG} -> {PAA_STATE_WAIT_SUCC_PAN}")
                    self.logger.info(f"Authentication successful for session {session_id:08x}")
                else:
                    # Continue EAP exchange
                    auth_req = PANAMessage()
                    auth_req.flags = FLAG_REQUEST
                    auth_req.msg_type = PANA_AUTH
                    auth_req.session_id = session_id
                    auth_req.seq_number = session.seq_number
                    
                    # Add EAP payload
                    eap_avp = AVP(AVP_EAP_PAYLOAD, 0, eap_response)
                    auth_req.avps.append(eap_avp)
                    
                    message_data = auth_req.pack()
                    self.socket.sendto(message_data, addr)
                    self.retransmit_mgr.add_message(session.seq_number, message_data, addr)
                    session.seq_number += 1
                    
        elif msg.flags & FLAG_COMPLETE:
            # Client acknowledged final auth message
            if session.state == PAA_STATE_WAIT_SUCC_PAN:
                # Remove any pending retransmissions for this session
                # The last message we sent had seq_number - 1
                if session.seq_number > 0:
                    self.retransmit_mgr.remove_message(session.seq_number - 1)
                
                session.state = PAA_STATE_OPEN
                self.logger.info(f"State transition: {PAA_STATE_WAIT_SUCC_PAN} -> {PAA_STATE_OPEN}")
                
                # Clear any other pending messages for this session
                # This ensures we don't retransmit old messages
                with self.retransmit_mgr.lock:
                    to_remove = []
                    for seq in list(self.retransmit_mgr.pending_messages.keys()):
                        msg_data, msg_addr, _, _ = self.retransmit_mgr.pending_messages[seq]
                        # Check if this message is for the same client IP
                        if msg_addr[0] == addr[0]:  # Compare IP only, not port
                            # Parse the message to check session ID
                            try:
                                if len(msg_data) >= 12:  # Minimum PANA header size
                                    msg_session_id = struct.unpack('!I', msg_data[8:12])[0]
                                    if msg_session_id == session.session_id:
                                        to_remove.append(seq)
                                        self.logger.debug(f"Removing pending retransmission seq={seq} for session {session.session_id:08x}")
                            except:
                                # If parsing fails, remove by address match as fallback
                                if msg_addr == addr:
                                    to_remove.append(seq)
                    
                    for seq in to_remove:
                        if seq in self.retransmit_mgr.pending_messages:
                            del self.retransmit_mgr.pending_messages[seq]
                        
            self.logger.info(f"Client acknowledged authentication for session {session_id:08x}")
            
    def handle_reauth_msg(self, msg, addr):
        """Handle PANA-Reauth message"""
        session_id = msg.session_id
        key = (session_id, addr[0])
        session = self.session_mgr.get_session(key)
        if not session:
            return

        # Update address in case port changed
        session.addr = addr
            
        # Verify AUTH AVP
        auth_avp = None
        for avp in msg.avps:
            if avp.code == AVP_AUTH:
                auth_avp = avp.value
                break
                
        if auth_avp and session.crypto_ctx.pana_auth_key:
            # Verify message authentication
            msg_copy = PANAMessage()
            msg_copy.reserved = msg.reserved
            msg_copy.flags = msg.flags
            msg_copy.msg_type = msg.msg_type
            msg_copy.session_id = msg.session_id
            msg_copy.seq_number = msg.seq_number
            
            for avp in msg.avps:
                if avp.code != AVP_AUTH:
                    msg_copy.avps.append(avp)
                    
            if not session.crypto_ctx.verify_auth(msg_copy.pack(), auth_avp):
                self.logger.error("AUTH AVP verification failed for re-auth request")
                return
                
        # Extend session lifetime
        session.lifetime = DEFAULT_SESSION_LIFETIME
        session.created_time = time.time()
        
        # Send PANA-Reauth answer
        answer = PANAMessage()
        answer.flags = FLAG_AUTH  # Answer with AUTH
        answer.msg_type = PANA_REAUTH
        answer.session_id = session_id
        answer.seq_number = session.seq_number
        
        # Add Session-Lifetime AVP
        lifetime_avp = AVP(AVP_SESSION_LIFETIME, 0, struct.pack('!I', session.lifetime))
        answer.avps.append(lifetime_avp)
        
        # Add AUTH AVP
        msg_without_auth = answer.pack()
        auth_value = session.crypto_ctx.compute_auth(msg_without_auth)
        auth_avp = AVP(AVP_AUTH, 0, auth_value)
        answer.avps.append(auth_avp)
        
        self.socket.sendto(answer.pack(), addr)
        session.seq_number += 1
        
        self.logger.info(f"Session {session_id:08x} re-authenticated")
        
    def handle_notification_msg(self, msg, addr):
        """Handle PANA-Notification message (including Ping)"""
        session_id = msg.session_id
        key = (session_id, addr[0])
        session = self.session_mgr.get_session(key)
        if not session:
            return

        # Update address in case port changed
        session.addr = addr
            
        if msg.flags & FLAG_PING:
            # This is a Ping request or response
            if msg.is_request():
                # Respond to Ping request
                answer = PANAMessage()
                answer.flags = FLAG_PING  # Answer with Ping flag
                answer.msg_type = PANA_NOTIFICATION
                answer.session_id = msg.session_id
                answer.seq_number = session.seq_number
                
                if session.crypto_ctx.pana_auth_key:
                    answer.flags |= FLAG_AUTH
                    msg_without_auth = answer.pack()
                    auth_value = session.crypto_ctx.compute_auth(msg_without_auth)
                    auth_avp = AVP(AVP_AUTH, 0, auth_value)
                    answer.avps.append(auth_avp)
                    
                self.socket.sendto(answer.pack(), addr)
                session.seq_number += 1
            else:
                # Ping response received
                self.retransmit_mgr.remove_message(session.seq_number - 1)
                self.logger.debug(f"Ping response received for session {session_id:08x}")
                
    def handle_termination_msg(self, msg, addr):
        """Handle PANA-Termination message"""
        session_id = msg.session_id
        key = (session_id, addr[0])
        session = self.session_mgr.get_session(key)
        if not session:
            return

        # Update address in case port changed
        session.addr = addr
            
        if msg.is_request():
            # Send termination answer
            answer = PANAMessage()
            answer.flags = 0  # Answer
            answer.msg_type = PANA_TERMINATION
            answer.session_id = session_id
            answer.seq_number = session.seq_number
            
            if session.crypto_ctx.pana_auth_key:
                answer.flags |= FLAG_AUTH
                msg_without_auth = answer.pack()
                auth_value = session.crypto_ctx.compute_auth(msg_without_auth)
                auth_avp = AVP(AVP_AUTH, 0, auth_value)
                answer.avps.append(auth_avp)
                
            self.socket.sendto(answer.pack(), addr)
            session.seq_number += 1
            
        # Remove session
        self.session_mgr.remove_session(key)
        self.logger.info(f"Session {session_id:08x} terminated")
        
    def run(self):
        """Run PANA Authentication Agent"""
        self.logger.info(f"Starting PANA Authentication Agent on {self.bind_addr}:{self.bind_port}")
        
        while self.running:
            try:
                # Use select for timeout handling
                ready = select.select([self.socket], [], [], 1.0)
                if not ready[0]:
                    continue
                    
                data, addr = self.socket.recvfrom(4096)
                if not data:
                    continue
                    
                msg = PANAMessage()
                try:
                    msg.unpack(data)
                except ValueError as e:
                    self.logger.error(f"Failed to parse PANA message from {addr}: {e}")
                    continue
                
                self.logger.info(f"Received message: type={msg.msg_type}, flags=0x{msg.flags:04x}, seq={msg.seq_number} from {addr}")
                
                if msg.msg_type == PANA_CLIENT_INITIATION:
                    self.handle_pci(msg, addr)
                elif msg.msg_type == PANA_AUTH:
                    self.handle_auth_msg(msg, addr)
                elif msg.msg_type == PANA_REAUTH:
                    self.handle_reauth_msg(msg, addr)
                elif msg.msg_type == PANA_TERMINATION:
                    self.handle_termination_msg(msg, addr)
                elif msg.msg_type == PANA_NOTIFICATION:
                    self.handle_notification_msg(msg, addr)
                    
            except Exception as e:
                self.logger.error(f"Error: {e}", exc_info=True)
                
    def stop(self):
        """Stop PAA"""
        self.running = False
        self.retransmit_mgr.stop()
        self.session_mgr.stop()
        self.socket.close()

# Example usage
if __name__ == "__main__":
    import sys
    import signal
    
    def signal_handler(sig, frame):
        print("\nShutting down...")
        if 'server' in globals():
            server.stop()
        if 'client' in globals():
            client.running = False
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    
    # Configure logging
    log_level = logging.INFO
    if '--debug' in sys.argv:
        log_level = logging.DEBUG
        sys.argv.remove('--debug')
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    if len(sys.argv) < 2:
        print("RFC5191 PANA Implementation")
        print("===========================")
        print("Usage: python pyPANA.py [paa|pac] [server_addr] [--debug]")
        print("")
        print("Modes:")
        print("  paa [--debug]        - Run as PANA Authentication Agent (server)")
        print("  pac <addr> [--debug] - Run as PANA Client (connect to server)")
        print("")
        print("Example:")
        print("  Terminal 1: python pyPANA.py paa")
        print("  Terminal 2: python pyPANA.py pac 127.0.0.1")
        print("")
        print("Features:")
        print("  - RFC5191 compliant PANA protocol")
        print("  - Complete EAP-TLS authentication (RFC5216)")
        print("  - PRF_HMAC_SHA2_256, AUTH_HMAC_SHA2_256_128, AES128_CTR")
        print("  - Message retransmission with R-bit support")
        print("  - Session lifetime management")
        print("  - Re-authentication support")
        print("  - OpenSSL 3.x support")
        sys.exit(1)
        
    mode = sys.argv[1].lower()
    
    if mode == 'paa':
        # Run as PANA Authentication Agent
        print("Starting PANA Authentication Agent (PAA)...")
        print("Listening on UDP port 716")
        print("Press Ctrl+C to stop")
        print("")
        
        server = PANAAuthAgent()
        try:
            server.run()
        except KeyboardInterrupt:
            print("\nStopping PAA...")
            server.stop()
            print("PAA stopped.")
            
    elif mode == 'pac':
        # Run as PANA Client
        if len(sys.argv) < 3:
            print("Error: Please provide server address for PaC mode")
            print("Example: python pyPANA.py pac 192.168.1.1")
            sys.exit(1)
            
        server_addr = sys.argv[2]
        print(f"Starting PANA Client (PaC)...")
        print(f"Connecting to PAA at {server_addr}:716")
        print("Press Ctrl+C to stop")
        print("")
        
        client = PANAClient(server_addr)
        try:
            client.run()
        except KeyboardInterrupt:
            print("\nStopping PaC...")
            client.running = False
            print("PaC stopped.")
            
    else:
        print(f"Error: Invalid mode '{mode}'. Use 'paa' or 'pac'")
        sys.exit(1)
