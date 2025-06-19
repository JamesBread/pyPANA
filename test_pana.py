#!/usr/bin/env python3
"""
Simple test script for pyPANA implementation
Tests basic message creation and parsing.

Requirements: cryptography, pyOpenSSL
Install with: ``pip install -r requirements.txt``
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

missing = []
try:
    import cryptography
except ImportError:
    missing.append("cryptography")
try:
    from OpenSSL import crypto  # noqa: F401
except ImportError:
    missing.append("pyOpenSSL")

if missing:
    print("Skipping tests due to missing dependencies: {}".format(", ".join(missing)))
    print("Install required packages with: pip install -r requirements.txt")
    sys.exit(0)

from pyPANA import (
    PANAMessage, AVP, CryptoContext,
    FLAG_REQUEST, FLAG_START, FLAG_AUTH,
    PANA_CLIENT_INITIATION, PANA_AUTH,
    AVP_NONCE, AVP_AUTH, AVP_EAP_PAYLOAD,
    PRF_HMAC_SHA2_256, AUTH_HMAC_SHA2_256_128,
    EAPTLSHandler, EAP_REQUEST, EAP_RESPONSE, EAP_TYPE_TLS
)
import struct

def test_message_creation():
    """Test PANA message creation and serialization"""
    print("Testing PANA message creation...")
    
    # Create a PCI message
    msg = PANAMessage()
    msg.flags = FLAG_REQUEST | FLAG_START
    msg.msg_type = PANA_CLIENT_INITIATION
    msg.session_id = 0x12345678
    msg.seq_number = 1
    
    # Add nonce AVP
    nonce_avp = AVP(AVP_NONCE, 0, b'1234567890123456')
    msg.avps.append(nonce_avp)
    
    # Pack the message
    packed = msg.pack()
    print(f"Created PCI message, length: {len(packed)} bytes")
    
    # Unpack and verify
    msg2 = PANAMessage()
    msg2.unpack(packed)
    
    assert msg2.flags == msg.flags
    assert msg2.msg_type == msg.msg_type
    assert msg2.session_id == msg.session_id
    assert msg2.seq_number == msg.seq_number
    assert len(msg2.avps) == 1
    assert msg2.avps[0].code == AVP_NONCE
    assert msg2.avps[0].value == b'1234567890123456'
    
    print("✓ Message creation and parsing successful")

def test_crypto_context():
    """Test cryptographic context"""
    print("\nTesting cryptographic context...")
    
    ctx = CryptoContext()
    ctx.prf_algorithm = PRF_HMAC_SHA2_256
    ctx.auth_algorithm = AUTH_HMAC_SHA2_256_128
    
    # Simulate MSK
    msk = b'0' * 64  # 64 bytes
    ctx.derive_keys(msk)
    
    assert ctx.pana_auth_key is not None
    assert ctx.pana_encr_key is not None
    
    # Test auth computation
    test_data = b"test message data"
    auth1 = ctx.compute_auth(test_data)
    auth2 = ctx.compute_auth(test_data)
    
    assert auth1 == auth2
    assert len(auth1) == 16  # 128 bits
    
    # Test verification
    assert ctx.verify_auth(test_data, auth1)
    assert not ctx.verify_auth(test_data + b'x', auth1)
    
    print("✓ Crypto context tests passed")

def test_avp_handling():
    """Test AVP creation and parsing"""
    print("\nTesting AVP handling...")
    
    # Create various AVPs
    avps = [
        AVP(AVP_NONCE, 0, b'nonce_value_here'),
        AVP(AVP_EAP_PAYLOAD, 0, b'\x01\x02\x00\x04'),  # Simple EAP packet
        AVP(AVP_AUTH, 0, b'0123456789abcdef'),
    ]
    
    for avp in avps:
        packed = avp.pack()
        avp2 = AVP()
        length = avp2.unpack(packed)
        
        assert avp2.code == avp.code
        assert avp2.flags == avp.flags
        assert avp2.value == avp.value
        assert length == len(packed)
    
    print("✓ AVP handling tests passed")

def test_encryption():
    """Test encryption/decryption"""
    print("\nTesting encryption...")
    
    ctx = CryptoContext()
    ctx.pana_encr_key = b'0123456789abcdef'  # 16 bytes for AES-128
    
    plaintext = b"This is a test message for encryption"
    
    # Encrypt
    ciphertext = ctx.encrypt(plaintext)
    assert len(ciphertext) >= len(plaintext) + 16  # IV + data
    
    # Decrypt
    decrypted = ctx.decrypt(ciphertext)
    assert decrypted == plaintext

    print("✓ Encryption tests passed")

def test_auth_verification_with_reserved():
    """Test AUTH verification when reserved bits are set"""
    print("\nTesting AUTH verification with reserved bits...")

    ctx = CryptoContext()
    ctx.pana_auth_key = b'A' * 32

    msg = PANAMessage()
    msg.flags = FLAG_REQUEST | FLAG_AUTH
    msg.reserved = 0x0155
    msg.msg_type = PANA_AUTH
    msg.session_id = 0x1234
    msg.seq_number = 1
    msg.avps.append(AVP(AVP_EAP_PAYLOAD, 0, b'data'))

    msg_no_auth = msg.pack()
    auth_val = ctx.compute_auth(msg_no_auth)
    msg.avps.append(AVP(AVP_AUTH, 0, auth_val))

    packed = msg.pack()

    parsed = PANAMessage()
    parsed.unpack(packed)
    assert parsed.reserved == msg.reserved

    auth_value = None
    msg_copy = PANAMessage()
    msg_copy.reserved = parsed.reserved
    msg_copy.flags = parsed.flags
    msg_copy.msg_type = parsed.msg_type
    msg_copy.session_id = parsed.session_id
    msg_copy.seq_number = parsed.seq_number
    for avp in parsed.avps:
        if avp.code == AVP_AUTH:
            auth_value = avp.value
        else:
            msg_copy.avps.append(avp)

    assert auth_value is not None
    assert ctx.verify_auth(msg_copy.pack(), auth_value)
    print("✓ AUTH verification with reserved bits passed")

def test_session_manager_indexing():
    """Test SessionManager indexing by session ID and IP"""
    print("\nTesting SessionManager indexing...")

    from pyPANA import SessionManager

    mgr = SessionManager()
    sid = 0xdeadbeef
    ip = '192.0.2.1'
    key = (sid, ip)
    session = mgr.create_session(key, (ip, 12345))

    # Retrieve using correct key
    assert mgr.get_session(key) is session

    # Mismatched IP should not return a session
    assert mgr.get_session((sid, '192.0.2.2')) is None

    mgr.remove_session(key)

def test_eaptls_server_start():
    """Ensure server-side EAP handler sends Identity request with no input"""
    handler = EAPTLSHandler(is_server=True)
    req = handler.process_eap_message(b"")
    assert req is not None
    code, ident, length = struct.unpack('!BBH', req[:4])
    assert code == EAP_REQUEST
    assert ident == 1

def test_eaptls_client_final_fragment():
    """Ensure client sends final TLS fragment before waiting for Success"""

    class DummyBIO:
        def __init__(self, data=b''):
            self._data = data
        def read(self):
            data = self._data
            self._data = b''
            return data
        def write(self, data):
            pass

    class DummySSL:
        def __init__(self):
            pass
        def do_handshake(self):
            pass
        def cipher(self):
            return ("TLS_AES_128_GCM_SHA256", "TLSv1.2", 128)
        def export_keying_material(self, label, length, context):
            return b"\x00" * length

    client = EAPTLSHandler(is_server=False)
    client.state = 'TLS_HANDSHAKE'
    client._derive_msk_emsk = lambda: None
    client.sslobj = DummySSL()
    client.incoming = DummyBIO()
    client.outgoing = DummyBIO(b'finaltls')

    # Server sends final TLS fragment
    fragment = struct.pack('!BBHBB', EAP_REQUEST, 1, 7, EAP_TYPE_TLS, 0) + b'X'
    resp = client.process_eap_message(fragment)

    assert resp is not None
    code, ident, length = struct.unpack('!BBH', resp[:4])
    assert code == EAP_RESPONSE
    assert resp[4] == EAP_TYPE_TLS
    assert resp.endswith(b'finaltls')

def main():
    """Run all tests"""
    print("pyPANA Basic Tests")
    print("==================\n")
    
    try:
        test_message_creation()
        test_crypto_context()
        test_avp_handling()
        test_encryption()
        test_auth_verification_with_reserved()
        test_session_manager_indexing()
        test_eaptls_server_start()
        test_eaptls_client_final_fragment()

        print("\n✅ All tests passed!")
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
