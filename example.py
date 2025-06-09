#!/usr/bin/env python3
"""
Example usage of pyPANA implementation
Demonstrates basic PANA client and server setup
"""

import sys
import threading
import time

# This example assumes pyPANA.py is in the same directory
from pyPANA import PANAClient, PANAAuthAgent

def run_paa():
    """Run PANA Authentication Agent in a thread"""
    print("Starting PAA (server)...")
    paa = PANAAuthAgent(bind_addr='127.0.0.1', bind_port=7160)  # Use non-privileged port
    
    # Run for 30 seconds then stop
    def stop_after_timeout():
        time.sleep(30)
        paa.running = False
        print("PAA timeout - stopping...")
    
    timeout_thread = threading.Thread(target=stop_after_timeout)
    timeout_thread.daemon = True
    timeout_thread.start()
    
    try:
        paa.run()
    except Exception as e:
        print(f"PAA error: {e}")
    finally:
        paa.stop()
        print("PAA stopped")

def run_pac():
    """Run PANA Client"""
    print("Starting PaC (client)...")
    time.sleep(2)  # Give server time to start
    
    pac = PANAClient('127.0.0.1', server_port=7160)  # Connect to non-privileged port
    
    # Run for 25 seconds then stop
    def stop_after_timeout():
        time.sleep(25)
        pac.running = False
        print("PaC timeout - stopping...")
    
    timeout_thread = threading.Thread(target=stop_after_timeout)
    timeout_thread.daemon = True
    timeout_thread.start()
    
    try:
        pac.run()
    except Exception as e:
        print(f"PaC error: {e}")
    finally:
        pac.cleanup()
        print("PaC stopped")

def main():
    """Run example PANA session"""
    print("pyPANA Example - Local Authentication")
    print("=====================================")
    print()
    print("This example runs PAA and PaC on localhost")
    print("Using port 7160 (non-privileged)")
    print()
    
    # Start PAA in background thread
    paa_thread = threading.Thread(target=run_paa)
    paa_thread.daemon = True
    paa_thread.start()
    
    # Run PaC in main thread
    run_pac()
    
    # Wait for PAA thread to finish
    paa_thread.join(timeout=5)
    
    print("\nExample completed")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == 'server':
            # Run only server
            paa = PANAAuthAgent(bind_addr='0.0.0.0', bind_port=7160)
            print("Running PAA on port 7160...")
            print("Press Ctrl+C to stop")
            try:
                paa.run()
            except KeyboardInterrupt:
                print("\nStopping PAA...")
                paa.stop()
        elif sys.argv[1] == 'client':
            # Run only client
            server = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'
            pac = PANAClient(server, server_port=7160)
            print(f"Connecting to PAA at {server}:7160...")
            try:
                pac.run()
            except KeyboardInterrupt:
                print("\nStopping PaC...")
                pac.running = False
                pac.cleanup()
        else:
            print("Usage: python example.py [server|client [server_ip]]")
    else:
        # Run both in same process
        main()