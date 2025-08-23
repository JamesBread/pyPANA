#!/usr/bin/env python3
"""
pyPANA暗号化アルゴリズムテスト
Test all cryptographic algorithms in pyPANA:
- PRF_HMAC_SHA2_256 for key derivation
- AUTH_HMAC_SHA2_256_128 for message authentication
- AES128_CTR for encryption

【概要】
pyPANAで使用される全ての暗号化アルゴリズムの動作を検証します。
RFC 5191およびRFC 6786に準拠した実装をテストします。

【テスト対象アルゴリズム】
1. PRF_HMAC_SHA2_256: キー導出用（RFC 5191）
2. AUTH_HMAC_SHA2_256_128: メッセージ認証用（RFC 5191）
3. AES128_CTR: 暗号化用（RFC 6786）
4. 統合された暗号化処理のテスト
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import struct
import hashlib
import hmac
from pana_crypto import CryptoContext
from pana_messages import PANAMessage, AVP
from pana_constants import *

def test_prf_hmac_sha2_256():
    """
    PRF_HMAC_SHA2_256キー導出テスト
    Test PRF_HMAC_SHA2_256 key derivation
    
    【テスト内容】
    1. SHA-256ベースのPRFによるキー導出
    2. PANA_AUTH_KEY、PANA_PAC_ENCR_KEY、PANA_PAA_ENCR_KEYの生成
    3. キー長の検証（SHA-256: 32バイト認証キー）
    4. キーの一意性確認
    """
    print("Testing PRF_HMAC_SHA2_256...")
    
    ctx = CryptoContext()
    ctx.prf_algorithm = PRF_HMAC_SHA2_256
    ctx.session_id = 0x12345678
    ctx.key_id = b'\xaa\xbb\xcc\xdd'
    ctx.nonce_pac = b'pac_nonce_16byte'  # 16 bytes
    ctx.nonce_paa = b'paa_nonce_16byte'  # 16 bytes
    ctx.i_par = b'\x00\x01\x02\x03'
    ctx.i_pan = b'\x04\x05\x06\x07'
    
    # Test MSK
    msk = b'master_session_key_from_eap_' + b'0' * 35  # 64 bytes total
    
    # Derive keys with SHA-256
    ctx.derive_keys(msk, PRF_HMAC_SHA2_256)
    
    # Verify keys were derived
    assert ctx.pana_auth_key is not None, "AUTH key not derived"
    assert ctx.pana_pac_encr_key is not None, "PAC encryption key not derived"
    assert ctx.pana_paa_encr_key is not None, "PAA encryption key not derived"
    
    # Verify key lengths (SHA-256 based PRF produces 32-byte auth key)
    assert len(ctx.pana_auth_key) == 32, f"AUTH key should be 32 bytes for SHA-256, got {len(ctx.pana_auth_key)}"
    assert len(ctx.pana_pac_encr_key) == 16, f"PAC ENCR key should be 16 bytes, got {len(ctx.pana_pac_encr_key)}"
    assert len(ctx.pana_paa_encr_key) == 16, f"PAA ENCR key should be 16 bytes, got {len(ctx.pana_paa_encr_key)}"
    
    # Verify keys are different
    assert ctx.pana_auth_key != ctx.pana_pac_encr_key
    assert ctx.pana_auth_key != ctx.pana_paa_encr_key
    assert ctx.pana_pac_encr_key != ctx.pana_paa_encr_key
    
    print(f"  ✓ Derived PANA_AUTH_KEY: {ctx.pana_auth_key.hex()}")
    print(f"  ✓ Derived PANA_PAC_ENCR_KEY: {ctx.pana_pac_encr_key.hex()}")
    print(f"  ✓ Derived PANA_PAA_ENCR_KEY: {ctx.pana_paa_encr_key.hex()}")
    print("  ✓ PRF_HMAC_SHA2_256 working correctly")
    return True

def test_auth_hmac_sha2_256_128():
    """
    AUTH_HMAC_SHA2_256_128メッセージ認証テスト
    Test AUTH_HMAC_SHA2_256_128 for message authentication
    
    【テスト内容】
    1. SHA-256ベース128ビットHMACの生成
    2. PANAメッセージの認証値計算
    3. 認証値の検証機能テスト
    4. 改ざんメッセージの検出確認
    """
    print("\nTesting AUTH_HMAC_SHA2_256_128...")
    
    ctx = CryptoContext()
    ctx.auth_algorithm = AUTH_HMAC_SHA2_256_128
    ctx.pana_auth_key = b'test_auth_key_16'  # 16 bytes
    
    # Create test message
    msg = PANAMessage()
    msg.msg_type = PANA_AUTH
    msg.session_id = 0x87654321
    msg.seq_number = 42
    msg.flags = FLAG_REQUEST
    
    # Add test AVP
    msg.add_avp(AVP(AVP_NONCE, 0, b'test_nonce_value'))
    
    # Pack message
    message_data = msg.pack()
    
    # Generate AUTH with SHA2-256-128
    auth_value = ctx.compute_auth(message_data)
    
    # Verify AUTH properties
    assert auth_value is not None, "AUTH value not generated"
    assert len(auth_value) == 16, f"AUTH should be 16 bytes (128 bits), got {len(auth_value)}"
    
    # Verify AUTH verification works
    assert ctx.verify_auth(message_data, auth_value), "AUTH verification failed"
    
    # Verify wrong AUTH fails
    wrong_auth = b'wrong_auth_value'
    assert not ctx.verify_auth(message_data, wrong_auth), "Wrong AUTH should fail"
    
    # Verify modified message fails
    modified_data = message_data[:-1] + b'\x00'
    assert not ctx.verify_auth(modified_data, auth_value), "Modified message should fail AUTH"
    
    print(f"  ✓ Generated AUTH value (128-bit): {auth_value.hex()}")
    print("  ✓ AUTH verification works correctly")
    print("  ✓ AUTH_HMAC_SHA2_256_128 working correctly")
    return True

def test_aes128_ctr():
    """
    AES128_CTR暗号化テスト
    Test AES128_CTR encryption
    
    【テスト内容】
    1. AES-128 CTRモードによる双方向暗号化
    2. PaC→PAA および PAA→PaC 暗号化
    3. RFC 6786準拠のナンス構築
    4. 異なるキーによる暗号文の違い確認
    """
    print("\nTesting AES128_CTR...")
    
    ctx = CryptoContext()
    ctx.encr_algorithm = AES128_CTR
    ctx.session_id = 0xaabbccdd
    ctx.key_id = b'\x11\x22\x33\x44'
    ctx.pana_pac_encr_key = b'sixteen_byte_key'  # 16 bytes for AES-128
    ctx.pana_paa_encr_key = b'another_16_bytes'  # 16 bytes for AES-128
    
    # Test data
    plaintext = b'This is a test message for AES-128-CTR encryption!'
    sequence_number = 100
    
    # Test PaC -> PAA encryption
    print("  Testing PaC -> PAA direction...")
    ciphertext_pac = ctx.encrypt_for_paa(plaintext, sequence_number)
    assert ciphertext_pac != plaintext, "Ciphertext should differ from plaintext"
    
    # Decrypt
    decrypted_pac = ctx.decrypt_from_pac(ciphertext_pac, sequence_number)
    assert decrypted_pac == plaintext, "Decryption failed"
    print(f"    ✓ Encrypted {len(plaintext)} bytes")
    print(f"    ✓ Decrypted successfully")
    
    # Test PAA -> PaC encryption
    print("  Testing PAA -> PaC direction...")
    ciphertext_paa = ctx.decrypt_from_paa(plaintext, sequence_number)  # In CTR mode, encrypt/decrypt are same
    assert ciphertext_paa != plaintext, "Ciphertext should differ from plaintext"
    
    # Decrypt
    decrypted_paa = ctx.encrypt_for_pac(ciphertext_paa, sequence_number)
    assert decrypted_paa == plaintext, "Decryption failed"
    print(f"    ✓ Encrypted {len(plaintext)} bytes")
    print(f"    ✓ Decrypted successfully")
    
    # Verify different keys produce different ciphertexts
    assert ciphertext_pac != ciphertext_paa, "Different keys should produce different ciphertexts"
    
    # Test nonce construction (RFC 6786)
    nonce = ctx.build_aes_ctr_nonce(sequence_number)
    assert len(nonce) == 12, f"Nonce should be 12 bytes, got {len(nonce)}"
    expected_nonce = b'\x11\x22\x33\x44\xaa\xbb\xcc\xdd\x00\x00\x00\x64'  # key_id + session_id + seq_num
    assert nonce == expected_nonce, f"Nonce mismatch: got {nonce.hex()}, expected {expected_nonce.hex()}"
    
    print("  ✓ Bidirectional encryption/decryption works")
    print("  ✓ RFC 6786 nonce format correct")
    print("  ✓ AES128_CTR working correctly")
    return True

def test_integrated_crypto():
    """
    統合暗号化処理テスト
    Test all algorithms working together in a realistic scenario
    
    【テスト内容】
    1. 全アルゴリズムの統合動作確認
    2. 現実的なシナリオでの暗号化処理
    3. EAP MSKシミュレーション
    4. メッセージ認証と暗号化の組み合わせテスト
    """
    print("\nTesting integrated cryptographic operations...")
    
    # Setup crypto context with all algorithms
    ctx = CryptoContext()
    ctx.prf_algorithm = PRF_HMAC_SHA2_256
    ctx.auth_algorithm = AUTH_HMAC_SHA2_256_128
    ctx.encr_algorithm = AES128_CTR
    ctx.session_id = 0x12345678
    ctx.key_id = b'\xde\xad\xbe\xef'
    ctx.nonce_pac = b'client_nonce1234'
    ctx.nonce_paa = b'server_nonce5678'
    ctx.i_par = b'\x10\x20\x30\x40'
    ctx.i_pan = b'\x50\x60\x70\x80'
    
    # Simulate EAP MSK
    msk = hashlib.sha256(b'simulated_eap_authentication').digest() * 2  # 64 bytes
    
    # Derive all keys using PRF_HMAC_SHA2_256
    ctx.derive_keys(msk, PRF_HMAC_SHA2_256)
    print("  ✓ Derived all keys with PRF_HMAC_SHA2_256")
    
    # Create and authenticate a message
    msg = PANAMessage()
    msg.msg_type = PANA_AUTH
    msg.session_id = ctx.session_id
    msg.seq_number = 1
    msg.flags = FLAG_REQUEST | FLAG_COMPLETE
    
    # Add some AVPs
    msg.add_avp(AVP(AVP_NONCE, 0, ctx.nonce_pac))
    msg.add_avp(AVP(AVP_SESSION_LIFETIME, 0, struct.pack('!I', 3600)))
    
    # Pack message
    message_data = msg.pack()
    
    # Generate AUTH using AUTH_HMAC_SHA2_256_128
    auth_value = ctx.compute_auth(message_data)
    auth_avp = AVP(AVP_AUTH, 0, auth_value)
    msg.add_avp(auth_avp)
    print(f"  ✓ Generated AUTH with AUTH_HMAC_SHA2_256_128: {auth_value.hex()[:32]}...")
    
    # Encrypt sensitive data using AES128_CTR
    sensitive_data = b'secret_network_key_12345'
    encrypted = ctx.encrypt_for_paa(sensitive_data, msg.seq_number)
    print(f"  ✓ Encrypted data with AES128_CTR: {len(encrypted)} bytes")
    
    # Verify decryption
    decrypted = ctx.decrypt_from_pac(encrypted, msg.seq_number)
    assert decrypted == sensitive_data, "Decryption failed"
    print("  ✓ Successfully decrypted data")
    
    # Verify AUTH
    assert ctx.verify_auth(message_data, auth_value), "AUTH verification failed"
    print("  ✓ AUTH verification successful")
    
    print("\n✅ All algorithms working correctly together!")
    return True

def main():
    """
    全暗号化アルゴリズムテストを実行
    Run all cryptographic algorithm tests
    
    【実行内容】
    1. 各アルゴリズムテストを順次実行
    2. テスト結果の集計と報告
    3. 失敗したテストの詳細表示
    
    Returns:
        bool: 全テストが成功した場合True
    """
    print("=" * 60)
    print("pyPANA Cryptographic Algorithms Test")
    print("=" * 60)
    
    tests = [
        ("PRF_HMAC_SHA2_256", test_prf_hmac_sha2_256),
        ("AUTH_HMAC_SHA2_256_128", test_auth_hmac_sha2_256_128),
        ("AES128_CTR", test_aes128_ctr),
        ("Integrated Crypto", test_integrated_crypto),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"✗ {name} test failed: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("✅ All cryptographic algorithms are properly implemented!")
        print("\nSupported algorithms:")
        print("  • PRF: PRF_HMAC_SHA2_256 (SHA-256 based)")
        print("  • AUTH: AUTH_HMAC_SHA2_256_128 (SHA-256 truncated to 128 bits)")
        print("  • Encryption: AES128_CTR (AES-128 in Counter mode)")
    else:
        print("❌ Some tests failed - review implementation")
    
    return failed == 0

if __name__ == "__main__":
    import sys
    sys.exit(0 if main() else 1)