#!/usr/bin/env python3
"""
Test script to verify SHA2 algorithm preference in pyPANA.

This script tests both default (SHA1 preference) and SHA2 preference modes.
"""

import sys
import time
import subprocess
import signal

def test_algorithms(prefer_sha2=False):
    """Test PANA authentication with specified algorithm preference"""
    
    print(f"\n{'='*60}")
    print(f"Testing with prefer_sha2={prefer_sha2}")
    print(f"{'='*60}\n")
    
    # Start PAA server
    server_cmd = ['python3', 'main.py', 'paa', '--debug']
    if prefer_sha2:
        server_cmd.append('--prefer-sha2')
    
    print(f"Starting PAA server: {' '.join(server_cmd)}")
    server_proc = subprocess.Popen(
        server_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    
    # Wait for server to start
    time.sleep(2)
    
    # Start PAC client
    client_cmd = ['python3', 'main.py', 'pac', '127.0.0.1', '--debug']
    if prefer_sha2:
        client_cmd.append('--prefer-sha2')
    
    print(f"Starting PAC client: {' '.join(client_cmd)}")
    client_proc = subprocess.Popen(
        client_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    
    # Collect output for analysis
    server_output = []
    client_output = []
    
    # Let them run for a bit
    timeout = time.time() + 10
    
    while time.time() < timeout:
        # Read server output
        try:
            line = server_proc.stdout.readline()
            if line:
                server_output.append(line.strip())
                if 'Selected' in line or 'algorithm' in line.lower():
                    print(f"[SERVER] {line.strip()}")
        except:
            pass
        
        # Read client output
        try:
            line = client_proc.stdout.readline()
            if line:
                client_output.append(line.strip())
                if 'Selected' in line or 'algorithm' in line.lower():
                    print(f"[CLIENT] {line.strip()}")
        except:
            pass
        
        # Check for authentication success
        if any('authentication successful' in line.lower() for line in server_output + client_output):
            print("\n✅ Authentication successful!")
            break
        
        time.sleep(0.1)
    
    # Terminate processes
    server_proc.terminate()
    client_proc.terminate()
    
    try:
        server_proc.wait(timeout=2)
        client_proc.wait(timeout=2)
    except:
        server_proc.kill()
        client_proc.kill()
    
    # Analyze algorithm selection
    print("\n" + "="*40)
    print("Algorithm Analysis:")
    print("="*40)
    
    # Check for PRF algorithm selection
    prf_selected = None
    for line in client_output:
        if 'Selected PRF algorithm' in line:
            if '5' in line or 'SHA2_256' in line:
                prf_selected = 'SHA2-256'
            elif '2' in line or 'SHA1' in line:
                prf_selected = 'SHA1'
            print(f"PRF Algorithm: {prf_selected}")
            break
    
    # Check for integrity algorithm selection
    integrity_selected = None
    for line in client_output:
        if 'Selected integrity algorithm' in line:
            if '12' in line or 'SHA2_256_128' in line:
                integrity_selected = 'SHA2-256-128'
            elif '7' in line or 'SHA1_160' in line:
                integrity_selected = 'SHA1-160'
            print(f"Integrity Algorithm: {integrity_selected}")
            break
    
    # Check AUTH AVP size (SHA1-160 = 20 bytes, SHA2-256-128 = 16 bytes)
    for line in server_output + client_output:
        if 'AUTH AVP' in line:
            if '20 bytes' in line or 'length: 20' in line:
                print("AUTH AVP size: 20 bytes (SHA1-160)")
            elif '16 bytes' in line or 'length: 16' in line:
                print("AUTH AVP size: 16 bytes (SHA2-256-128)")
            break
    
    return prf_selected, integrity_selected

def main():
    print("Testing pyPANA Algorithm Selection")
    print("===================================\n")
    
    # Test default (SHA1 preference)
    prf1, integrity1 = test_algorithms(prefer_sha2=False)
    
    # Wait between tests
    time.sleep(2)
    
    # Test SHA2 preference
    prf2, integrity2 = test_algorithms(prefer_sha2=True)
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print("\nDefault mode (OpenPANA compatible):")
    print(f"  PRF: {prf1}")
    print(f"  Integrity: {integrity1}")
    print("\nSHA2 preference mode (more secure):")
    print(f"  PRF: {prf2}")
    print(f"  Integrity: {integrity2}")
    
    if prf1 == 'SHA1' and integrity1 == 'SHA1-160':
        print("\n✅ Default mode correctly prefers SHA1 for compatibility")
    else:
        print("\n❌ Default mode did not select SHA1 as expected")
    
    if prf2 == 'SHA2-256' and integrity2 == 'SHA2-256-128':
        print("✅ SHA2 preference mode correctly selects SHA2 algorithms")
    else:
        print("❌ SHA2 preference mode did not select SHA2 as expected")

if __name__ == '__main__':
    main()