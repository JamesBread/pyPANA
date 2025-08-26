#!/usr/bin/env python3
"""
pyPANA v2.3.0互換性テスト (Fixed version)
Test pyPANA compatibility with v2.3.0 fixes
"""

import sys
import time
import subprocess
import threading
import queue

def read_output(proc, output_queue):
    """Read output from process continuously"""
    for line in iter(proc.stdout.readline, ''):
        if line:
            output_queue.put(line.strip())
        else:
            break

def test_pypana():
    """Test pyPANA PAA and PaC"""
    print("=== Testing pyPANA ↔ pyPANA (v2.3.0) ===\n")
    
    # Create output queues
    paa_queue = queue.Queue()
    pac_queue = queue.Queue()
    
    # Start PAA
    paa_proc = subprocess.Popen(
        ["python3", "main.py", "paa", "--bind", "127.0.0.1", "--port", "5557", "--debug"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    # Start output reader thread for PAA
    paa_thread = threading.Thread(target=read_output, args=(paa_proc, paa_queue))
    paa_thread.daemon = True
    paa_thread.start()
    
    time.sleep(2)
    
    # Start PaC
    pac_proc = subprocess.Popen(
        ["python3", "main.py", "pac", "127.0.0.1", "--port", "5557", "--debug"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    # Start output reader thread for PaC
    pac_thread = threading.Thread(target=read_output, args=(pac_proc, pac_queue))
    pac_thread.daemon = True
    pac_thread.start()
    
    # Collect output for 8 seconds
    time.sleep(8)
    
    # Collect all output
    pac_output = []
    paa_output = []
    
    while not pac_queue.empty():
        pac_output.append(pac_queue.get())
    
    while not paa_queue.empty():
        paa_output.append(paa_queue.get())
    
    # Terminate processes
    pac_proc.terminate()
    paa_proc.terminate()
    
    # Convert output to strings
    pac_output_str = '\n'.join(pac_output)
    paa_output_str = '\n'.join(paa_output)
    
    # Check for success indicators
    pac_success = "State transition" in pac_output_str and "OPEN" in pac_output_str
    paa_success = "State transition" in paa_output_str and "OPEN" in paa_output_str
    
    print(f"PaC authentication: {'✅ SUCCESS' if pac_success else '❌ FAILED'}")
    print(f"PAA authentication: {'✅ SUCCESS' if paa_success else '❌ FAILED'}")
    
    # Show state transitions
    if not pac_success:
        print("\nPaC state transitions:")
        for line in pac_output:
            if "State transition" in line:
                print(f"  {line}")
    
    if not paa_success:
        print("\nPAA state transitions:")
        for line in paa_output:
            if "State transition" in line:
                print(f"  {line}")
    
    # Check algorithm selection
    for line in pac_output:
        if "Selected PRF algorithm: 2" in line:
            print("✅ Using SHA1 PRF (value 2)")
            break
    
    for line in pac_output:
        if "Selected integrity algorithm: 7" in line:
            print("✅ Using SHA1_160 integrity (value 7)")
            break
    
    return pac_success and paa_success

if __name__ == "__main__":
    success = test_pypana()
    sys.exit(0 if success else 1)