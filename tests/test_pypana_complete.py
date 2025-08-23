#!/usr/bin/env python3
"""
pyPANA 完全動作テスト（PaC ↔ PAA）
Test pyPANA PaC with pyPANA PAA

【概要】
pyPANA実装のPaC（クライアント）とPAA（認証エージェント）間の
完全な認証フローをテストします。プロセス間通信による実際の
ネットワーク通信環境での動作を確認し、実用的な相互運用性を検証します。

【テスト内容】
1. pyPANA PAA プロセスの起動と初期化
2. pyPANA PaC プロセスの起動と認証開始
3. 完全なPANA認証フローの実行
4. 認証結果の確認と成功判定
5. プロセス終了と清掃処理

【検証項目】
- プロセス間でのUDP通信動作
- RFC 5191準拠のメッセージ交換
- EAP-TLS認証フローの完了
- セッション確立とOPEN状態の達成
"""
import subprocess
import time
import sys
import os

def test_pypana():
    """
    pyPANA 完全動作テスト実行
    
    【テスト手順】
    1. PAA（認証エージェント）プロセス起動
    2. PaC（クライアント）プロセス起動  
    3. 認証フローの実行と監視
    4. 結果の収集と評価
    5. プロセスの適切な終了
    
    Returns:
        bool: テストが成功した場合True
    """
    print("=" * 60)
    print("Testing pyPANA PaC <-> pyPANA PAA")
    print("pyPANA 完全動作テスト（PaC ↔ PAA）")
    print("=" * 60)
    
    # Start PAA  
    # PAA（認証エージェント）を起動
    print("\n1. Starting pyPANA PAA on port 5562...")
    print("   PAA（認証エージェント）をポート5562で起動中...")
    paa_proc = subprocess.Popen(
        [sys.executable, 'main.py', 'paa', '--port', '5562'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    time.sleep(2)  # PAAの初期化を待機
    
    # Start PaC
    # PaC（クライアント）を起動
    print("2. Starting pyPANA PaC...")
    print("   PaC（クライアント）を起動中...")
    pac_proc = subprocess.Popen(
        [sys.executable, 'main.py', 'pac', '127.0.0.1', '--port', '5562'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    # Let them run
    print("3. Waiting for authentication...")
    time.sleep(8)
    
    # Terminate
    pac_proc.terminate()
    paa_proc.terminate()
    
    # Get output
    pac_output = pac_proc.stdout.read()
    paa_output = paa_proc.stdout.read()
    
    # Check results
    print("\n4. Results:")
    print("-" * 40)
    
    # Check PAA
    if "Processing PCI" in paa_output:
        print("✓ PAA received PCI")
    else:
        print("✗ PAA did not receive PCI")
    
    if "Sending PAR" in paa_output or "EAP-Request" in paa_output:
        print("✓ PAA sent PAR with EAP-Request")
    else:
        print("✗ PAA did not send PAR")
    
    # Check PaC
    if "Sending PCI" in pac_output or "WAIT_PAN_OR_PAR" in pac_output:
        print("✓ PaC sent PCI")
    else:
        print("✗ PaC did not send PCI")
    
    if "Received PAR" in pac_output or "EAP-Request" in pac_output:
        print("✓ PaC received PAR")
    else:
        print("✗ PaC did not receive PAR")
    
    if "Authentication successful" in pac_output or "OPEN state" in pac_output:
        print("✓ Authentication completed successfully!")
        success = True
    else:
        print("✗ Authentication did not complete")
        success = False
    
    print("\n5. Sample logs:")
    print("-" * 40)
    print("PAA key events:")
    for line in paa_output.split('\n'):
        if any(x in line for x in ['PCI', 'PAR', 'PAN', 'EAP', 'authenticated']):
            print(f"  {line[:80]}")
            if len([x for x in ['PCI', 'PAR', 'PAN'] if x in line]) >= 2:
                break
    
    print("\nPaC key events:")
    for line in pac_output.split('\n'):
        if any(x in line for x in ['PCI', 'PAR', 'PAN', 'State', 'authenticated']):
            print(f"  {line[:80]}")
            if len([x for x in ['PCI', 'PAR', 'PAN'] if x in line]) >= 2:
                break
    
    if success:
        print("\n✅ TEST PASSED - pyPANA PaC and PAA work correctly together!")
    else:
        print("\n⚠️ TEST INCOMPLETE - Authentication did not finish (may need more time)")
    
    return success

if __name__ == "__main__":
    success = test_pypana()
    sys.exit(0 if success else 1)