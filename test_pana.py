#!/usr/bin/env python3
"""
Simple test script for pyPANA implementation
Tests basic message creation and parsing
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pyPANA import (
    PANAMessage, AVP, CryptoContext,
    FLAG_REQUEST, FLAG_START, FLAG_AUTH,
    PANA_CLIENT_INITIATION, PANA_AUTH,
    AVP_NONCE, AVP_AUTH, AVP_EAP_PAYLOAD,
    PRF_HMAC_SHA2_256, AUTH_HMAC_SHA2_256_128
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

def main():
    """Run all tests"""
    print("pyPANA Basic Tests")
    print("==================\n")
    
    try:
        test_message_creation()
        test_crypto_context()
        test_avp_handling()
        test_encryption()
        
        print("\n✅ All tests passed!")
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()