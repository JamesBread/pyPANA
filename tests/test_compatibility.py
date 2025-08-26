#!/usr/bin/env python3
"""
pyPANA v2.3.0互換性テスト
Test pyPANA compatibility with v2.3.0 fixes

【概要】
pyPANA v2.3.0の修正により、PAA（認証エージェント）とPaC（クライアント）間の
相互運用性をテストします。SHA1アルゴリズムの優先使用など、
OpenPANAとの互換性を確認します。

【テスト内容】
1. pyPANA PAA と pyPANA PaC の通信テスト
2. 認証フローの検証
3. アルゴリズム選択の確認（SHA1優先）
4. プロセス間通信の安定性確認
"""

import sys
import time
import subprocess
import signal

def test_pypana():
    """
    pyPANA PAA と PaC のテスト
    Test pyPANA PAA and PaC
    
    【テスト手順】
    1. PAA（認証エージェント）プロセスを起動
    2. PaC（クライアント）プロセスを起動
    3. 認証フローを実行
    4. 出力から成功指標を確認
    5. アルゴリズム選択を検証
    
    Returns:
        bool: テストが成功した場合True
    """
    print("=== Testing pyPANA ↔ pyPANA (v2.3.0) ===\n")
    
    # Start PAA
    # PAA（認証エージェント）を起動
    paa_proc = subprocess.Popen(
        ["python3", "main.py", "paa", "--bind", "127.0.0.1", "--port", "5555"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    time.sleep(2)
    
    # Start PaC
    # PaC（クライアント）を起動
    pac_proc = subprocess.Popen(
        ["python3", "main.py", "pac", "127.0.0.1", "--port", "5555"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    # Collect output for 8 seconds (allow more time for authentication)
    time.sleep(8)
    
    # Terminate processes
    pac_proc.terminate()
    paa_proc.terminate()
    
    # Wait for processes to finish and get output
    pac_proc.wait(timeout=2)
    paa_proc.wait(timeout=2)
    
    # Read all remaining output
    pac_output = pac_proc.stdout.read() if pac_proc.stdout else ""
    paa_output = paa_proc.stdout.read() if paa_proc.stdout else ""
    
    # Check for success indicators
    # 成功指標をチェック
    pac_success = "OPEN" in pac_output or "authenticated" in pac_output.lower()
    paa_success = "authenticated" in paa_output.lower() or "OPEN" in paa_output
    
    print(f"PaC authentication: {'✅ SUCCESS' if pac_success else '❌ FAILED'}")
    print(f"PAA authentication: {'✅ SUCCESS' if paa_success else '❌ FAILED'}")
    
    # Check algorithm selection
    # アルゴリズム選択をチェック（OpenPANA互換性のためSHA1優先）
    if "Selected PRF algorithm: 2" in pac_output:
        print("✅ Using SHA1 PRF (value 2)")
    if "Selected integrity algorithm: 7" in pac_output:
        print("✅ Using SHA1_160 integrity (value 7)")
    
    return pac_success and paa_success

if __name__ == "__main__":
    success = test_pypana()
    sys.exit(0 if success else 1)
