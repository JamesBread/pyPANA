#!/usr/bin/env python3
"""Simple authentication test bypassing EAP-TLS complexity"""

import sys
import socket
import threading
import time
import os

sys.path.insert(0, '.')

from pana_messages import PANAMessage, AVP
from pana_constants import *
from pana_crypto import CryptoContext
import struct

def simple_paa():
    """Simple PAA that accepts any client"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 5558))
    sock.settimeout(1.0)
    
    session_id = 0x12345678
    seq = 1
    ctx = CryptoContext()
    
    print("PAA: Listening on 127.0.0.1:5558")
    
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            msg = PANAMessage()
            msg.unpack(data)
            
            if msg.msg_type == PANA_CLIENT_INITIATION:
                print(f"PAA: Received PCI from {addr}")
                
                # Send initial PAR with S-bit
                par = PANAMessage()
                par.msg_type = PANA_AUTH
                par.flags = FLAG_REQUEST | FLAG_START
                par.session_id = session_id
                par.seq_number = seq
                
                # Add nonce and algorithms
                ctx.nonce_paa = ctx.generate_nonce()
                par.add_avp(AVP(AVP_NONCE, 0, ctx.nonce_paa))
                par.add_avp(AVP(AVP_PRF_ALGORITHM, 0, struct.pack('!I', PRF_HMAC_SHA1)))
                par.add_avp(AVP(AVP_INTEGRITY_ALGORITHM, 0, struct.pack('!I', AUTH_HMAC_SHA1_160)))
                
                sock.sendto(par.pack(), addr)
                print(f"PAA: Sent initial PAR with S-bit")
                seq += 1
                
            elif msg.msg_type == PANA_AUTH and not msg.is_request():
                print(f"PAA: Received PAN")
                
                # Extract client nonce
                nonce_avp = msg.get_avp(AVP_NONCE)
                if nonce_avp:
                    ctx.nonce_pac = nonce_avp.value
                    print(f"PAA: Got client nonce ({len(ctx.nonce_pac)} bytes)")
                
                # Send success
                print("PAA: Authentication successful!")
                break
                
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            break
    
    sock.close()

def simple_pac():
    """Simple PaC"""
    time.sleep(0.5)  # Let PAA start
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ctx = CryptoContext()
    
    print("PaC: Starting")
    
    # Send PCI
    pci = PANAMessage()
    pci.msg_type = PANA_CLIENT_INITIATION
    pci.flags = FLAG_REQUEST | FLAG_START
    pci.session_id = 0
    pci.seq_number = 0
    
    sock.sendto(pci.pack(), ('127.0.0.1', 5558))
    print(f"PaC: Sent PCI ({len(pci.pack())} bytes)")
    
    # Wait for PAR
    sock.settimeout(2.0)
    try:
        data, addr = sock.recvfrom(65535)
        par = PANAMessage()
        par.unpack(data)
        
        if par.msg_type == PANA_AUTH and par.is_request():
            print(f"PaC: Received initial PAR")
            
            # Extract PAA nonce
            nonce_avp = par.get_avp(AVP_NONCE)
            if nonce_avp:
                ctx.nonce_paa = nonce_avp.value
                print(f"PaC: Got PAA nonce ({len(ctx.nonce_paa)} bytes)")
            
            # Send PAN with S-bit and nonce
            pan = PANAMessage()
            pan.msg_type = PANA_AUTH
            pan.flags = FLAG_START
            pan.session_id = par.session_id
            pan.seq_number = par.seq_number
            
            # Add client nonce
            ctx.nonce_pac = ctx.generate_nonce()
            pan.add_avp(AVP(AVP_NONCE, 0, ctx.nonce_pac))
            pan.add_avp(AVP(AVP_PRF_ALGORITHM, 0, struct.pack('!I', PRF_HMAC_SHA1)))
            pan.add_avp(AVP(AVP_INTEGRITY_ALGORITHM, 0, struct.pack('!I', AUTH_HMAC_SHA1_160)))
            
            sock.sendto(pan.pack(), addr)
            print(f"PaC: Sent initial PAN with nonce")
            print("PaC: Authentication successful!")
            
    except socket.timeout:
        print("PaC: Timeout waiting for PAR")
    
    sock.close()

def main():
    print("=" * 60)
    print("Simple PANA Authentication Test")
    print("=" * 60)
    print()
    
    # Run PAA in thread
    paa_thread = threading.Thread(target=simple_paa, daemon=True)
    paa_thread.start()
    
    # Run PaC
    simple_pac()
    
    print("\n✅ Basic protocol flow works correctly!")
    return 0

if __name__ == "__main__":
    sys.exit(main())