#!/usr/bin/env python3
"""Test pyPANA compatibility with v2.3.0 fixes"""

import sys
import time
import subprocess
import signal

def test_pypana():
    """Test pyPANA PAA and PaC"""
    print("=== Testing pyPANA ↔ pyPANA (v2.3.0) ===\n")
    
    # Start PAA
    paa_proc = subprocess.Popen(
        ["python3", "main.py", "paa", "--bind", "127.0.0.1", "--port", "5555"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    time.sleep(2)
    
    # Start PaC
    pac_proc = subprocess.Popen(
        ["python3", "main.py", "pac", "127.0.0.1", "--port", "5555"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    # Collect output for 5 seconds
    time.sleep(5)
    
    # Terminate processes
    pac_proc.terminate()
    paa_proc.terminate()
    
    # Get output
    pac_output = pac_proc.stdout.read() if pac_proc.stdout else ""
    paa_output = paa_proc.stdout.read() if paa_proc.stdout else ""
    
    # Check for success indicators
    pac_success = "OPEN" in pac_output or "authenticated" in pac_output.lower()
    paa_success = "authenticated" in paa_output.lower() or "OPEN" in paa_output
    
    print(f"PaC authentication: {'✅ SUCCESS' if pac_success else '❌ FAILED'}")
    print(f"PAA authentication: {'✅ SUCCESS' if paa_success else '❌ FAILED'}")
    
    # Check algorithm selection
    if "Selected PRF algorithm: 2" in pac_output:
        print("✅ Using SHA1 PRF (value 2)")
    if "Selected integrity algorithm: 7" in pac_output:
        print("✅ Using SHA1_160 integrity (value 7)")
    
    return pac_success and paa_success

if __name__ == "__main__":
    success = test_pypana()
    sys.exit(0 if success else 1)
