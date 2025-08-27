#!/usr/bin/env python3
"""
EAP識別子シーケンステスト
Test EAP identifier sequence management

【概要】
RFC 3748準拠のEAP識別子管理をテストします。
サーバーは各新規RequestでIDをインクリメントし、
クライアントは受信したRequest IDをResponseで使用します。

【修正内容】
v2.3.1でサーバーがEAP-TLSハンドシェイク中に
識別子をインクリメントしない問題を修正。
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eap_tls import EAPTLSHandler
import struct

def extract_eap_info(packet):
    """EAPパケットから情報を抽出"""
    if not packet or len(packet) < 4:
        return None, None, None
    code, identifier, length = struct.unpack('!BBH', packet[:4])
    return code, identifier, length

def test_server_id_sequence():
    """サーバーのEAP ID管理をテスト"""
    print("\n=== Testing Server EAP ID Sequence ===")
    
    server = EAPTLSHandler(is_server=True)
    client = EAPTLSHandler(is_server=False)
    
    # Track ID sequence
    id_sequence = []
    
    # 1. Server sends initial Request/Identity
    req = server.process_eap_message(b'')
    code, id_val, _ = extract_eap_info(req)
    print(f"Server → Request/Identity (ID={id_val})")
    id_sequence.append(('Request', id_val))
    assert id_val == 1, f"Initial Request should have ID=1, got {id_val}"
    
    # 2. Client responds with Identity
    resp = client.process_eap_message(req)
    code, id_val, _ = extract_eap_info(resp)
    print(f"Client → Response/Identity (ID={id_val})")
    id_sequence.append(('Response', id_val))
    assert id_val == 1, f"Response should echo Request ID=1, got {id_val}"
    
    # 3. Server sends EAP-TLS Start
    req = server.process_eap_message(resp)
    code, id_val, _ = extract_eap_info(req)
    print(f"Server → Request/EAP-TLS Start (ID={id_val})")
    id_sequence.append(('Request', id_val))
    assert id_val == 2, f"EAP-TLS Start should have ID=2, got {id_val}"
    
    # 4. Client responds with Client Hello
    resp = client.process_eap_message(req)
    if resp:
        code, id_val, _ = extract_eap_info(resp)
        print(f"Client → Response/Client Hello (ID={id_val})")
        id_sequence.append(('Response', id_val))
        assert id_val == 2, f"Response should echo Request ID=2, got {id_val}"
        
        # 5. Server continues handshake
        req = server.process_eap_message(resp)
        if req:
            code, id_val, _ = extract_eap_info(req)
            print(f"Server → Request/Server Hello (ID={id_val})")
            id_sequence.append(('Request', id_val))
            assert id_val == 3, f"Next Request should have ID=3, got {id_val}"
    
    print("\n✅ Server correctly increments EAP ID for each Request")
    return True

def test_retransmission_detection():
    """再送検出のテスト"""
    print("\n=== Testing Retransmission Detection ===")
    
    # Simulate the problematic scenario from pypana_rev1.json
    server_ids = []
    
    # Before fix: Server would send multiple Requests with same ID
    # After fix: Server increments ID for each new Request
    
    server = EAPTLSHandler(is_server=True)
    
    # Get initial Request
    req1 = server.process_eap_message(b'')
    _, id1, _ = extract_eap_info(req1)
    server_ids.append(id1)
    
    # Simulate Identity Response
    identity_resp = struct.pack('!BBH', 2, 1, 16) + b'\x01pana-client'
    
    # Get EAP-TLS Start
    req2 = server.process_eap_message(identity_resp)
    _, id2, _ = extract_eap_info(req2)
    server_ids.append(id2)
    
    # Simulate Client Hello (simplified)
    client_hello = struct.pack('!BBH', 2, 2, 10) + b'\x0d\x00' + b'test'
    
    # Get next Request - this should have incremented ID
    req3 = server.process_eap_message(client_hello)
    if req3:
        _, id3, _ = extract_eap_info(req3)
        server_ids.append(id3)
    
    print(f"Server ID sequence: {server_ids}")
    
    # Check for duplicates (which would cause retransmission detection)
    if len(server_ids) != len(set(server_ids)):
        print("❌ FAILED: Duplicate IDs detected - would trigger retransmission!")
        return False
    
    # Check for proper increment
    for i in range(1, len(server_ids)):
        if server_ids[i] != (server_ids[i-1] + 1) % 256:
            print(f"❌ FAILED: ID not properly incremented at position {i}")
            return False
    
    print("✅ No duplicate IDs - retransmission detection won't trigger")
    return True

def main():
    """メインテスト実行"""
    print("=" * 60)
    print("EAP Identifier Sequence Test")
    print("Testing fix for EAP-TLS ID increment issue")
    print("=" * 60)
    
    all_passed = True
    
    try:
        # Test 1: Server ID sequence
        if not test_server_id_sequence():
            all_passed = False
            
        # Test 2: Retransmission detection
        if not test_retransmission_detection():
            all_passed = False
            
    except Exception as e:
        print(f"\n❌ Test error: {e}")
        import traceback
        traceback.print_exc()
        all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✅ ALL TESTS PASSED")
        print("EAP identifier management is RFC 3748 compliant")
    else:
        print("❌ SOME TESTS FAILED")
        print("Check the output above for details")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())