#!/usr/bin/env python3
"""End-to-end test for pyPANA with v2.3.0 fixes"""

import sys
import time
import threading
import socket

sys.path.insert(0, '.')

from pana_server import PANAAuthAgent
from pana_client import PANAClient

def run_paa():
    """Run PAA in a thread"""
    try:
        paa = PANAAuthAgent('127.0.0.1', 5556)
        print("PAA: Started on 127.0.0.1:5556")
        paa.run()
    except Exception as e:
        print(f"PAA Error: {e}")

def run_pac():
    """Run PaC after PAA starts"""
    time.sleep(2)  # Let PAA start
    try:
        pac = PANAClient('127.0.0.1', 5556)
        print("PaC: Connecting to 127.0.0.1:5556")
        pac.run()
        
        # Check authentication status
        if pac.state == 5:  # PAC_STATE_OPEN
            print("✅ PaC: Authentication SUCCESSFUL (State: OPEN)")
            return True
        else:
            print(f"❌ PaC: Authentication failed (State: {pac.state})")
            return False
    except Exception as e:
        print(f"PaC Error: {e}")
        return False

def main():
    print("=== pyPANA End-to-End Test (v2.3.0) ===\n")
    
    # Start PAA in background thread
    paa_thread = threading.Thread(target=run_paa, daemon=True)
    paa_thread.start()
    
    # Run PaC
    success = run_pac()
    
    print("\n=== Test Result ===")
    if success:
        print("✅ Authentication successful with v2.3.0 fixes!")
    else:
        print("❌ Authentication failed")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
