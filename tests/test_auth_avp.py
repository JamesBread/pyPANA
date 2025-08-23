#!/usr/bin/env python3
"""
AUTH AVP計算と検証のテスト
Test AUTH AVP calculation and verification

【概要】
PANAメッセージのAUTH AVP（認証値）の計算と検証機能をテストします。
AUTH AVPはメッセージの完全性を保証する重要な要素です。

【テスト内容】
1. テストメッセージの作成
2. AUTH AVP値の計算
3. メッセージへのAUTH AVP追加
4. パースと検証
5. AUTH値の一致確認
"""
import sys
import logging
sys.path.insert(0, '.')
logging.basicConfig(level=logging.DEBUG)

from pana_messages import PANAMessage, AVP
from pana_constants import *
from pana_crypto import CryptoContext
import struct

def test_auth_avp():
    """
    AUTH AVP計算テスト
    Test AUTH AVP calculation
    
    【テスト手順】
    1. PANAメッセージの作成とAVP追加
    2. AUTH値の計算
    3. メッセージのパースと検証
    4. 計算されたAUTH値と受信したAUTH値の比較
    
    Returns:
        bool: テストが成功した場合True
    """
    print("=" * 60)
    print("Testing AUTH AVP Calculation")
    print("=" * 60)
    
    # Create a test message
    # テストメッセージの作成
    msg = PANAMessage()
    msg.flags = FLAG_REQUEST
    msg.msg_type = PANA_AUTH
    msg.session_id = 0x12345678
    msg.seq_number = 1
    
    # Add some AVPs
    # いくつかのAVPを追加
    msg.add_avp(AVP(AVP_EAP_PAYLOAD, 0, b'\x01\x02\x00\x05\x01'))  # EAP-Request/Identity
    msg.add_avp(AVP(AVP_RESULT_CODE, 0, struct.pack('!I', 0)))  # Success
    
    # Create crypto context with test key
    # テストキーで暗号化コンテキストを作成
    crypto = CryptoContext()
    crypto.auth_algorithm = AUTH_HMAC_SHA2_256_128
    crypto.pana_auth_key = b'test_key_1234567890' * 2  # 38 bytes
    
    print("\n1. Original message:")
    print(f"   Flags: 0x{msg.flags:04x}")
    print(f"   Type: {msg.msg_type}")
    print(f"   Session ID: 0x{msg.session_id:08x}")
    print(f"   Sequence: {msg.seq_number}")
    print(f"   AVPs: {len(msg.avps)}")
    for avp in msg.avps:
        print(f"     - Code {avp.code}: {len(avp.value)} bytes")
    
    # Pack message without AUTH
    # AUTH無しでメッセージをパック
    msg_without_auth = msg.pack()
    print(f"\n2. Message without AUTH: {len(msg_without_auth)} bytes")
    print(f"   First 32 bytes: {msg_without_auth[:32].hex()}")
    
    # Compute AUTH
    # AUTH値を計算
    auth_value = crypto.compute_auth(msg_without_auth)
    print(f"\n3. Computed AUTH: {auth_value.hex()} ({len(auth_value)} bytes)")
    
    # Add AUTH AVP
    # AUTH AVPを追加
    msg.add_avp(AVP(AVP_AUTH, 0, auth_value))
    print(f"\n4. Added AUTH AVP as AVP #{len(msg.avps)}")
    
    # Pack complete message
    # 完全なメッセージをパック
    complete_msg = msg.pack()
    print(f"\n5. Complete message: {len(complete_msg)} bytes")
    
    # Now verify
    # 検証を実行
    print("\n6. Verification:")
    
    # Parse the complete message
    # 完全なメッセージをパース
    parsed = PANAMessage()
    parsed.unpack(complete_msg)
    
    print(f"   Parsed {len(parsed.avps)} AVPs:")
    auth_avp_found = None
    for i, avp in enumerate(parsed.avps):
        print(f"     - AVP {i+1}: Code {avp.code}, Length {len(avp.value)}")
        if avp.code == AVP_AUTH:
            auth_avp_found = avp.value
            print(f"       AUTH AVP found at position {i+1}")
    
    if not auth_avp_found:
        print("   ERROR: No AUTH AVP found!")
        return False
    
    # Reconstruct without AUTH for verification
    # 検証用にAUTH無しでメッセージを再構築
    verify_msg = PANAMessage()
    verify_msg.reserved = parsed.reserved
    verify_msg.flags = parsed.flags
    verify_msg.msg_type = parsed.msg_type
    verify_msg.session_id = parsed.session_id
    verify_msg.seq_number = parsed.seq_number
    
    for avp in parsed.avps:
        if avp.code != AVP_AUTH:
            verify_msg.add_avp(avp)
    
    verify_data = verify_msg.pack()
    print(f"\n7. Message for verification: {len(verify_data)} bytes")
    print(f"   Should match original: {verify_data == msg_without_auth}")
    
    # Verify AUTH
    # AUTH値を検証
    computed_auth = crypto.compute_auth(verify_data)
    print(f"\n8. Verification AUTH: {computed_auth.hex()}")
    print(f"   Received AUTH:      {auth_avp_found.hex()}")
    print(f"   Match: {computed_auth == auth_avp_found}")
    
    if computed_auth == auth_avp_found:
        print("\n✅ AUTH AVP verification successful!")
        print("   AUTH AVPの計算と検証が正常に完了しました")
        return True
    else:
        print("\n❌ AUTH AVP verification failed!")
        print("   AUTH AVPの検証が失敗しました")
        print("\nDebugging info:")
        print(f"  Original message length: {len(msg_without_auth)}")
        print(f"  Verify message length: {len(verify_data)}")
        if len(msg_without_auth) != len(verify_data):
            print("  ERROR: Message lengths don't match!")
        return False

if __name__ == "__main__":
    success = test_auth_avp()
    sys.exit(0 if success else 1)