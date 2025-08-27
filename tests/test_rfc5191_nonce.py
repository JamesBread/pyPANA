#!/usr/bin/env python3
"""
RFC 5191 Compliant Nonce Exchange Test

Tests that nonces are exchanged according to RFC 5191 Section 4.1:
"A Nonce AVP MUST be included in the first PANA-Auth-Request and
PANA-Auth-Answer messages following the initial PANA-Auth-Request and
PANA-Auth-Answer messages (i.e., with the 'S' (Start) bit set)"
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket
import threading
import time
import struct
from pana_messages import PANAMessage, AVP
from pana_constants import *

def check_message(msg_name, msg, expected_flags, expected_avps):
    """Check if message has expected flags and AVPs"""
    errors = []
    
    # Check flags
    has_r = bool(msg.flags & FLAG_REQUEST)
    has_s = bool(msg.flags & FLAG_START)
    has_c = bool(msg.flags & FLAG_COMPLETE)
    
    if 'R' in expected_flags and not has_r:
        errors.append(f"{msg_name}: Missing R-bit")
    if 'S' in expected_flags and not has_s:
        errors.append(f"{msg_name}: Missing S-bit")
    if 'R' not in expected_flags and has_r:
        errors.append(f"{msg_name}: Unexpected R-bit")
    if 'S' not in expected_flags and has_s:
        errors.append(f"{msg_name}: Unexpected S-bit")
        
    # Check AVPs
    avp_codes = [avp.code for avp in msg.avps]
    
    for expected in expected_avps:
        if expected == 'nonce':
            if AVP_NONCE not in avp_codes:
                errors.append(f"{msg_name}: Missing Nonce AVP")
        elif expected == 'no-nonce':
            if AVP_NONCE in avp_codes:
                errors.append(f"{msg_name}: Unexpected Nonce AVP (violates RFC 5191)")
        elif expected == 'eap':
            if AVP_EAP_PAYLOAD not in avp_codes:
                errors.append(f"{msg_name}: Missing EAP-Payload AVP")
        elif expected == 'no-eap':
            if AVP_EAP_PAYLOAD in avp_codes:
                errors.append(f"{msg_name}: Unexpected EAP-Payload AVP")
                
    return errors

def test_rfc5191_nonce_exchange():
    """Test RFC 5191 compliant nonce exchange"""
    print("\n=== Testing RFC 5191 Compliant Nonce Exchange ===\n")
    
    # Start servers
    import subprocess
    import signal
    
    # Start PAA
    paa_proc = subprocess.Popen(
        ['python3', 'main.py', 'paa', '--port', '5559', '--bind', '127.0.0.1'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    time.sleep(2)  # Let PAA start
    
    # Start PaC
    pac_proc = subprocess.Popen(
        ['python3', 'main.py', 'pac', '127.0.0.1', '--port', '5559'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, 'PANA_TEST_MODE': '1'}  # Stop after initial exchange
    )
    
    time.sleep(3)  # Let exchange happen
    
    # Capture output
    paa_out, paa_err = paa_proc.communicate(timeout=1)
    pac_out, pac_err = pac_proc.communicate(timeout=1)
    
    # Kill processes
    paa_proc.kill()
    pac_proc.kill()
    
    # Analyze logs
    print("PAA Output:")
    print(paa_err.decode()[:500])
    print("\nPaC Output:")
    print(pac_err.decode()[:500])
    
    # Check for RFC compliance
    errors = []
    
    # Check PAA logs
    paa_logs = paa_err.decode()
    if "Generated PAA nonce for later use" not in paa_logs:
        errors.append("PAA: Not generating nonce correctly")
    if "Added PAA nonce to first non-initial PAR" not in paa_logs:
        errors.append("PAA: Not adding nonce to first non-initial PAR")
        
    # Check PaC logs  
    pac_logs = pac_err.decode()
    if "Generated client nonce for later use" not in pac_logs:
        errors.append("PaC: Not generating nonce correctly")
    if "Added client nonce to first non-initial PAN" not in pac_logs:
        errors.append("PaC: Not adding nonce to first non-initial PAN")
    
    return errors

def main():
    """Main test runner"""
    print("=" * 60)
    print("RFC 5191 Nonce Exchange Compliance Test")
    print("=" * 60)
    
    errors = test_rfc5191_nonce_exchange()
    
    print("\n" + "=" * 60)
    if not errors:
        print("✅ ALL TESTS PASSED")
        print("Nonce exchange is RFC 5191 compliant")
        return 0
    else:
        print("❌ TESTS FAILED")
        for error in errors:
            print(f"  - {error}")
        return 1

if __name__ == "__main__":
    sys.exit(main())