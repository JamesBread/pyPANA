#!/usr/bin/env python3
"""Test PANA protocol flow with v2.3.0 fixes"""

import socket
import struct
import time
import sys

sys.path.insert(0, '.')

from pana_messages import PANAMessage, AVP
from pana_constants import *

def test_pci_format():
    """Test that PCI is correctly formatted"""
    print("1. Testing PCI Format")
    print("-" * 40)
    
    # Create PCI as PaC would
    pci = PANAMessage()
    pci.msg_type = PANA_CLIENT_INITIATION
    pci.flags = FLAG_REQUEST | FLAG_START
    pci.session_id = 0
    pci.seq_number = 0
    
    pci_data = pci.pack()
    
    print(f"   PCI size: {len(pci_data)} bytes")
    print(f"   PCI hex: {pci_data.hex()}")
    print(f"   Has AVPs: {'Yes' if len(pci.avps) > 0 else 'No'}")
    
    if len(pci_data) == 16 and len(pci.avps) == 0:
        print("   ✅ PCI format correct (16 bytes, no AVPs)")
        return True
    else:
        print("   ❌ PCI format incorrect")
        return False

def test_par_format():
    """Test PAR format with S-bit"""
    print("\n2. Testing Initial PAR Format")
    print("-" * 40)
    
    # Create initial PAR as PAA would
    par = PANAMessage()
    par.msg_type = PANA_AUTH
    par.flags = FLAG_REQUEST | FLAG_START
    par.session_id = 0x12345678
    par.seq_number = 1
    
    # Add nonce (20 bytes)
    from pana_crypto import CryptoContext
    ctx = CryptoContext()
    nonce = ctx.generate_nonce()
    par.add_avp(AVP(AVP_NONCE, 0, nonce))
    
    # Add algorithm AVPs
    par.add_avp(AVP(AVP_PRF_ALGORITHM, 0, struct.pack('!I', PRF_HMAC_SHA1)))
    par.add_avp(AVP(AVP_INTEGRITY_ALGORITHM, 0, struct.pack('!I', AUTH_HMAC_SHA1_160)))
    
    par_data = par.pack()
    
    print(f"   PAR size: {len(par_data)} bytes")
    print(f"   Session ID: 0x{par.session_id:08x}")
    print(f"   Flags: 0x{par.flags:04x} (S-bit: {'Set' if par.flags & FLAG_START else 'Not set'})")
    print(f"   Nonce length: {len(nonce)} bytes")
    print(f"   AVP count: {len(par.avps)}")
    
    if len(nonce) == 20 and (par.flags & FLAG_START):
        print("   ✅ PAR format correct (S-bit set, 20-byte nonce)")
        return True
    else:
        print("   ❌ PAR format incorrect")
        return False

def test_pan_format():
    """Test PAN format with S-bit and nonce"""
    print("\n3. Testing Initial PAN Format")
    print("-" * 40)
    
    # Create initial PAN as PaC would
    pan = PANAMessage()
    pan.msg_type = PANA_AUTH
    pan.flags = FLAG_START  # Answer with S-bit
    pan.session_id = 0x12345678
    pan.seq_number = 1  # Same as request
    
    # Add nonce (20 bytes) - moved from PCI
    from pana_crypto import CryptoContext
    ctx = CryptoContext()
    nonce = ctx.generate_nonce()
    pan.add_avp(AVP(AVP_NONCE, 0, nonce))
    
    # Add selected algorithms
    pan.add_avp(AVP(AVP_PRF_ALGORITHM, 0, struct.pack('!I', PRF_HMAC_SHA1)))
    pan.add_avp(AVP(AVP_INTEGRITY_ALGORITHM, 0, struct.pack('!I', AUTH_HMAC_SHA1_160)))
    
    pan_data = pan.pack()
    
    print(f"   PAN size: {len(pan_data)} bytes")
    print(f"   Flags: 0x{pan.flags:04x} (S-bit: {'Set' if pan.flags & FLAG_START else 'Not set'})")
    print(f"   Nonce length: {len(nonce)} bytes")
    print(f"   AVP count: {len(pan.avps)}")
    
    if len(nonce) == 20 and (pan.flags & FLAG_START):
        print("   ✅ PAN format correct (S-bit set, 20-byte nonce)")
        return True
    else:
        print("   ❌ PAN format incorrect")
        return False

def test_auth_avp():
    """Test AUTH AVP calculation"""
    print("\n4. Testing AUTH AVP Calculation")
    print("-" * 40)
    
    from pana_crypto import CryptoContext
    
    ctx = CryptoContext()
    ctx.pana_auth_key = b'test_key' * 4  # 32 bytes
    
    # Create a test message
    msg = PANAMessage()
    msg.msg_type = PANA_AUTH
    msg.flags = FLAG_REQUEST
    msg.session_id = 0x12345678
    msg.seq_number = 5
    
    # Pack without AUTH
    msg_data = msg.pack()
    
    # Calculate AUTH
    auth = ctx.compute_auth(msg_data)
    
    print(f"   Auth algorithm: {ctx.auth_algorithm} (SHA1_160={AUTH_HMAC_SHA1_160})")
    print(f"   Message size: {len(msg_data)} bytes")
    print(f"   AUTH AVP length: {len(auth)} bytes")
    print(f"   AUTH AVP hex: {auth.hex()[:40]}...")
    
    # Verify
    verified = ctx.verify_auth(msg_data, auth)
    
    if len(auth) == 20 and verified:
        print("   ✅ AUTH AVP correct (20 bytes, SHA1-160)")
        return True
    else:
        print("   ❌ AUTH AVP incorrect")
        return False

def main():
    print("=" * 60)
    print("PANA Protocol Flow Test (v2.3.0)")
    print("=" * 60)
    
    results = []
    
    # Run tests
    results.append(test_pci_format())
    results.append(test_par_format())
    results.append(test_pan_format())
    results.append(test_auth_avp())
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(results)
    total = len(results)
    
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("✅ All protocol tests passed!")
        print("✅ Ready for interoperability testing")
        return 0
    else:
        print("❌ Some tests failed")
        print("⚠️  Protocol may not be fully compatible")
        return 1

if __name__ == "__main__":
    sys.exit(main())