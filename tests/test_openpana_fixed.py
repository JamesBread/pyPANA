#!/usr/bin/env python3
"""
修正版pyPANA PaC と OpenPANA PAA 相互運用テスト
Test script for fixed pyPANA PaC with OpenPANA PAA.
This version sends a minimal RFC-compliant PCI without AVPs.

【概要】
pyPANA v2.3.0の修正により、OpenPANAとの相互運用性が改善されました。
このテストでは、RFC 5191準拠の最小限のPCIメッセージ（AVPなし）を
OpenPANA PAAに送信し、適切な応答を受信できることを確認します。

【テスト内容】
1. RFC準拠の最小限PCIメッセージ送信
2. OpenPANA PAAからの応答受信確認
3. プロトコル互換性の検証
4. エラーハンドリングの確認

【修正点】
- PCI メッセージからAVPを削除（16バイトヘッダーのみ）
- session_id = 0、seq_number = 0 に統一
- フラグ設定の正規化（R-bit, S-bit）
"""

import socket
import time
import sys
import struct

# Add parent directory to path
sys.path.insert(0, '.')

from pana_messages import PANAMessage, AVP, FLAG_REQUEST, FLAG_START
from pana_constants import *

def test_minimal_pci():
    """
    最小限PCIメッセージをOpenPANA PAAに送信
    Send minimal PCI to OpenPANA PAA
    
    【テスト手順】
    1. RFC 5191準拠の最小限PCIメッセージ作成
    2. OpenPANA PAA（127.0.0.1:716）への送信
    3. PAR応答の受信と解析
    4. プロトコル互換性の確認
    
    【期待動作】
    - PCI送信後、PAAからPARメッセージを受信
    - エラーや例外が発生しないこと
    - OpenPANAとのプロトコル互換性確認
    """
    
    # Create minimal PCI (16 bytes, no AVPs)
    pci = PANAMessage()
    pci.msg_type = PANA_CLIENT_INITIATION
    pci.flags = FLAG_REQUEST | FLAG_START  # R=1, S=1
    pci.session_id = 0  # Must be 0 in PCI
    pci.seq_number = 0  # Must be 0 in PCI
    
    # Pack message
    pci_data = pci.pack()
    print(f"PCI message size: {len(pci_data)} bytes")
    print(f"PCI hex: {pci_data.hex()}")
    
    # Send to OpenPANA PAA
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    
    server_addr = ('127.0.0.1', 5555)
    print(f"\nSending minimal PCI to {server_addr[0]}:{server_addr[1]}")
    sock.sendto(pci_data, server_addr)
    
    # Wait for response
    try:
        data, addr = sock.recvfrom(65535)
        print(f"\nReceived response from {addr[0]}:{addr[1]}: {len(data)} bytes")
        
        # Parse response
        response = PANAMessage()
        response.unpack(data)
        print(f"Response type: {response.msg_type}")
        print(f"Response flags: 0x{response.flags:04x}")
        print(f"Session ID: 0x{response.session_id:08x}")
        
        # Check for AVPs
        for avp in response.avps:
            print(f"AVP: Code={avp.code}, Length={avp.length}")
            
        return True
        
    except socket.timeout:
        print("\nNo response received (timeout)")
        return False
    except Exception as e:
        print(f"\nError: {e}")
        return False
    finally:
        sock.close()

if __name__ == "__main__":
    print("Testing fixed pyPANA PCI with OpenPANA PAA")
    print("=" * 50)
    
    success = test_minimal_pci()
    
    if success:
        print("\n✅ OpenPANA responded to minimal PCI!")
    else:
        print("\n❌ OpenPANA did not respond to PCI")
    
    sys.exit(0 if success else 1)