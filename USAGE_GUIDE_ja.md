# pyPANA 使用ガイド

このガイドでは、pyPANAをコマンドラインツールとして実行する方法と、Pythonライブラリとして使用する方法を説明します。

## 目次
- [インストール](#インストール)
- [コマンドラインでの使用](#コマンドラインでの使用)
  - [PAA（サーバー）として実行](#paaサーバーとして実行)
  - [PaC（クライアント）として実行](#pacクライアントとして実行)
- [Pythonライブラリとしての使用](#pythonライブラリとしての使用)
  - [基本的な使用例](#基本的な使用例)
  - [高度な使用例](#高度な使用例)
- [テストスクリプトの例](#テストスクリプトの例)
- [トラブルシューティング](#トラブルシューティング)

## インストール

```bash
# リポジトリをクローン
git clone https://github.com/JamesBread/pyPANA.git
cd pyPANA

# 依存関係をインストール
pip install -r requirements.txt

# 証明書を生成（初回のみ）
python3 generate_certs.py
```

## コマンドラインでの使用

pyPANAは、PAA（認証エージェント/サーバー）またはPaC（クライアント）として実行できます。

### PAA（サーバー）として実行

#### 基本的な起動

```bash
# デフォルト設定で起動（ポート716、すべてのインターフェース）
sudo python3 main.py paa

# カスタムポートで起動（root権限不要）
python3 main.py paa --port 5555

# 特定のインターフェースにバインド
python3 main.py paa --bind 127.0.0.1 --port 5555

# デバッグモード有効
python3 main.py paa --port 5555 --debug
```

#### PAAのコマンドラインオプション

| オプション | 説明 | デフォルト値 |
|-----------|------|-------------|
| `--bind ADDRESS` | バインドするIPアドレス | 0.0.0.0 |
| `--port PORT` | リッスンするUDPポート | 716 |
| `--debug` | デバッグログを有効化 | False |
| `--radius-server IP` | RADIUSサーバーのIP | なし |
| `--radius-port PORT` | RADIUSサーバーのポート | 1812 |
| `--radius-secret SECRET` | RADIUS共有シークレット | なし |

#### 実行例

```bash
# ローカルテスト用（デバッグモード）
python3 main.py paa --bind 127.0.0.1 --port 5555 --debug

# 本番環境用（RADIUSバックエンド使用）
sudo python3 main.py paa \
  --radius-server 192.168.1.10 \
  --radius-secret "shared-secret" \
  --debug
```

### PaC（クライアント）として実行

#### 基本的な接続

```bash
# PAAに接続（デフォルトポート）
python3 main.py pac 192.168.1.100

# カスタムポートのPAAに接続
python3 main.py pac 192.168.1.100 --port 5555

# ローカルホストのPAAに接続（テスト用）
python3 main.py pac 127.0.0.1 --port 5555 --debug
```

#### PaCのコマンドラインオプション

| オプション | 説明 | デフォルト値 |
|-----------|------|-------------|
| `SERVER_IP` | PAAサーバーのIPアドレス | 必須 |
| `--port PORT` | PAAサーバーのポート | 716 |
| `--debug` | デバッグログを有効化 | False |
| `--timeout SEC` | 接続タイムアウト | 10 |
| `--enable-encryption` | RFC 6786 AVP暗号化を有効化 | False |

#### 実行例

```bash
# ローカルテスト（デバッグモード）
python3 main.py pac 127.0.0.1 --port 5555 --debug

# 暗号化を有効にして接続
python3 main.py pac 192.168.1.100 --enable-encryption --debug

# タイムアウトを設定して接続
python3 main.py pac 192.168.1.100 --timeout 30
```

## Pythonライブラリとしての使用

pyPANAは、Pythonアプリケーションに組み込んで使用することもできます。

### 基本的な使用例

#### PAAサーバーの実装

```python
#!/usr/bin/env python3
"""
基本的なPAAサーバーの実装例
"""
import logging
from pana_server import PANAAuthAgent

# ログ設定
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    # PAAサーバーを作成
    paa = PANAAuthAgent(
        bind_addr='127.0.0.1',  # バインドアドレス
        bind_port=5555,          # ポート番号
        use_eap_tls=True         # EAP-TLS認証を使用
    )
    
    print("PAA サーバーを起動しています...")
    print("接続を待機中: 127.0.0.1:5555")
    
    try:
        # サーバーを実行
        paa.run()
    except KeyboardInterrupt:
        print("\nサーバーを停止しています...")
    finally:
        paa.cleanup()
        print("サーバーが停止しました")

if __name__ == "__main__":
    main()
```

#### PaCクライアントの実装

```python
#!/usr/bin/env python3
"""
基本的なPaCクライアントの実装例
"""
import logging
from pana_client import PANAClient

# ログ設定
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    # PaCクライアントを作成
    pac = PANAClient(
        server_addr='127.0.0.1',  # PAAサーバーのアドレス
        server_port=5555           # PAAサーバーのポート
    )
    
    print("PAAサーバーに接続しています...")
    
    try:
        # 認証を開始
        result = pac.start_authentication()
        
        if result:
            print("認証成功！")
            print(f"セッションID: 0x{pac.session_id:08x}")
            
            # 認証後の処理
            # ...
            
            # セッションを終了
            pac.terminate_session()
        else:
            print("認証失敗")
            
    except Exception as e:
        print(f"エラーが発生しました: {e}")
    finally:
        pac.cleanup()

if __name__ == "__main__":
    main()
```

### 高度な使用例

#### カスタム認証ハンドラー付きPAA

```python
#!/usr/bin/env python3
"""
カスタム認証ハンドラーを使用したPAAサーバー
"""
import logging
from pana_server import PANAAuthAgent
from pana_messages import PANAMessage
from pana_constants import PANA_SUCCESS, PANA_AUTHENTICATION_REJECTED

class CustomPAA(PANAAuthAgent):
    """カスタム認証ロジックを持つPAA"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.authenticated_users = {}
    
    def handle_authentication_result(self, session_id, result, user_identity=None):
        """認証結果をカスタム処理"""
        if result == PANA_SUCCESS:
            self.authenticated_users[session_id] = {
                'identity': user_identity,
                'auth_time': time.time(),
                'status': 'authenticated'
            }
            self.logger.info(f"ユーザー {user_identity} を認証しました")
            
            # カスタム処理（例：アクセス権限の設定）
            self.grant_network_access(session_id, user_identity)
        else:
            self.logger.warning(f"認証失敗: セッション 0x{session_id:08x}")
    
    def grant_network_access(self, session_id, user_identity):
        """ネットワークアクセスを許可する（カスタム実装）"""
        # ここにネットワークアクセス制御のロジックを実装
        print(f"ネットワークアクセスを許可: {user_identity}")
        # 例：ファイアウォールルールの更新、VLANの割り当てなど

def main():
    # カスタムPAAを作成
    paa = CustomPAA(
        bind_addr='0.0.0.0',
        bind_port=5555,
        use_eap_tls=True
    )
    
    print("カスタムPAAサーバーを起動しています...")
    
    try:
        paa.run()
    except KeyboardInterrupt:
        print("\nシャットダウン中...")
    finally:
        # 認証済みユーザーの統計を表示
        print(f"\n認証済みユーザー数: {len(paa.authenticated_users)}")
        for session_id, info in paa.authenticated_users.items():
            print(f"  - {info['identity']} (セッション: 0x{session_id:08x})")

if __name__ == "__main__":
    main()
```

#### イベントコールバック付きPaC

```python
#!/usr/bin/env python3
"""
イベントコールバックを使用したPaCクライアント
"""
import logging
import time
from pana_client import PANAClient
from pana_constants import PAC_STATE_OPEN

class CustomPaC(PANAClient):
    """イベントドリブンなPaCクライアント"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.auth_complete = False
        self.session_key = None
    
    def on_state_change(self, old_state, new_state):
        """状態変更時のコールバック"""
        print(f"状態変更: {old_state} -> {new_state}")
        
        if new_state == PAC_STATE_OPEN:
            self.auth_complete = True
            print("認証が完了しました！")
            self.on_authenticated()
    
    def on_authenticated(self):
        """認証成功時の処理"""
        # セッションキーを取得
        if hasattr(self, 'msk'):
            self.session_key = self.msk
            print(f"セッションキー取得: {self.session_key.hex()[:16]}...")
        
        # 認証後のアプリケーション処理
        self.start_application()
    
    def start_application(self):
        """アプリケーション固有の処理"""
        print("アプリケーションを開始します...")
        # ここにアプリケーションロジックを実装
        
    def send_keepalive(self):
        """定期的なキープアライブ送信"""
        while self.auth_complete:
            time.sleep(30)  # 30秒ごと
            if self.state == PAC_STATE_OPEN:
                self.send_pnr_ping()
                print("キープアライブを送信しました")

def main():
    # カスタムPaCを作成
    pac = CustomPaC(
        server_addr='127.0.0.1',
        server_port=5555
    )
    
    try:
        # 認証を開始
        print("認証を開始しています...")
        result = pac.start_authentication()
        
        if result:
            # キープアライブループ
            pac.send_keepalive()
        else:
            print("認証に失敗しました")
            
    except Exception as e:
        print(f"エラー: {e}")
    finally:
        pac.cleanup()

if __name__ == "__main__":
    main()
```

## テストスクリプトの例

### OpenPANA互換性テスト

```python
#!/usr/bin/env python3
"""
OpenPANA互換性テストスクリプト
tests/test_pypana_paa_openpana.py を参照
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pana_server import PANAAuthAgent
from pana_constants import *

def run_openpana_compatible_paa():
    """OpenPANA互換のPAAを実行"""
    
    # OpenPANA互換設定
    paa = PANAAuthAgent(
        bind_addr='127.0.0.1',
        bind_port=5555,
        use_eap_tls=True
    )
    
    # SHA1アルゴリズムを優先（OpenPANAとの互換性）
    paa.supported_auth_algorithms = [AUTH_HMAC_SHA1_160, AUTH_HMAC_SHA2_256_128]
    paa.supported_prf_algorithms = [PRF_HMAC_SHA1, PRF_HMAC_SHA2_256]
    
    print("OpenPANA互換PAAを起動しました")
    print("OpenPANA PaCでテスト: openpac -i 127.0.0.1 -p 5555 -t eap-tls")
    
    try:
        paa.run()
    except KeyboardInterrupt:
        print("\n停止しています...")

if __name__ == "__main__":
    run_openpana_compatible_paa()
```

### 統合テストスクリプト

```python
#!/usr/bin/env python3
"""
PAA-PaC統合テスト
"""
import threading
import time
import sys
from pana_server import PANAAuthAgent
from pana_client import PANAClient

def run_paa():
    """バックグラウンドでPAAを実行"""
    paa = PANAAuthAgent(
        bind_addr='127.0.0.1',
        bind_port=6666,
        use_eap_tls=True
    )
    paa.run()

def run_pac():
    """PaCを実行して認証をテスト"""
    time.sleep(2)  # PAAの起動を待つ
    
    pac = PANAClient(
        server_addr='127.0.0.1',
        server_port=6666
    )
    
    result = pac.start_authentication()
    
    if result:
        print("✓ 認証成功")
        return True
    else:
        print("✗ 認証失敗")
        return False

def main():
    print("統合テストを開始します...")
    
    # PAAをバックグラウンドスレッドで起動
    paa_thread = threading.Thread(target=run_paa, daemon=True)
    paa_thread.start()
    
    # PaCを実行
    success = run_pac()
    
    # 結果を表示
    if success:
        print("\n統合テスト: 成功 ✓")
        return 0
    else:
        print("\n統合テスト: 失敗 ✗")
        return 1

if __name__ == "__main__":
    sys.exit(main())
```

### パフォーマンステスト

```python
#!/usr/bin/env python3
"""
複数クライアントの同時接続テスト
"""
import concurrent.futures
import time
from pana_client import PANAClient

def authenticate_client(client_id, server_addr='127.0.0.1', server_port=5555):
    """単一クライアントの認証を実行"""
    try:
        pac = PANAClient(server_addr, server_port)
        start_time = time.time()
        
        result = pac.start_authentication()
        
        elapsed = time.time() - start_time
        
        if result:
            print(f"クライアント {client_id}: 認証成功 ({elapsed:.2f}秒)")
            pac.terminate_session()
            return True, elapsed
        else:
            print(f"クライアント {client_id}: 認証失敗")
            return False, elapsed
            
    except Exception as e:
        print(f"クライアント {client_id}: エラー - {e}")
        return False, 0
    finally:
        pac.cleanup()

def run_performance_test(num_clients=10):
    """複数クライアントの同時認証テスト"""
    print(f"{num_clients}個のクライアントで同時認証テストを開始...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_clients) as executor:
        futures = []
        for i in range(num_clients):
            future = executor.submit(authenticate_client, i+1)
            futures.append(future)
        
        # 結果を収集
        results = []
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    
    # 統計を計算
    successful = sum(1 for r in results if r[0])
    avg_time = sum(r[1] for r in results) / len(results) if results else 0
    
    print(f"\n=== テスト結果 ===")
    print(f"成功: {successful}/{num_clients}")
    print(f"平均認証時間: {avg_time:.2f}秒")
    
    return successful == num_clients

if __name__ == "__main__":
    # 注意: PAAサーバーが起動していることを確認してください
    run_performance_test(5)  # 5クライアントでテスト
```

## トラブルシューティング

### よくある問題と解決方法

#### 1. ポート権限エラー

**問題**: "Permission denied" エラーが発生する

**解決方法**:
```bash
# オプション1: sudo を使用
sudo python3 main.py paa

# オプション2: 高いポート番号を使用（推奨）
python3 main.py paa --port 5555
```

#### 2. 証明書エラー

**問題**: "証明書が見つかりません" エラー

**解決方法**:
```bash
# 証明書を生成
python3 generate_certs.py

# または手動で証明書ディレクトリを作成
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 365 -nodes
```

#### 3. 接続タイムアウト

**問題**: PaCがPAAに接続できない

**解決方法**:
```bash
# 1. PAAが起動していることを確認
ps aux | grep "main.py paa"

# 2. ファイアウォールを確認
sudo ufw status

# 3. 正しいIPアドレスとポートを使用
python3 main.py pac 127.0.0.1 --port 5555 --debug

# 4. タイムアウトを延長
python3 main.py pac 127.0.0.1 --timeout 30
```

#### 4. 認証失敗

**問題**: 認証が常に失敗する

**解決方法**:
```bash
# デバッグログを有効化して詳細を確認
python3 main.py paa --debug
python3 main.py pac 127.0.0.1 --debug

# EAP-TLS証明書を確認
ls -la certs/

# Pythonスクリプトで直接テスト
python3 tests/test_compatibility.py
```

### デバッグのヒント

1. **詳細ログの有効化**:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

2. **パケットキャプチャ**:
```bash
# tcpdumpでPANAパケットをキャプチャ
sudo tcpdump -i lo -w pana.pcap 'udp port 5555'

# Wiresharkで解析
wireshark pana.pcap
```

3. **状態の確認**:
```python
# クライアントの状態を確認
print(f"現在の状態: {pac.state}")
print(f"セッションID: 0x{pac.session_id:08x}")
print(f"シーケンス番号: {pac.seq_number}")
```

## まとめ

pyPANAは柔軟で強力なPANAプロトコル実装です。コマンドラインツールとしても、Pythonライブラリとしても使用でき、様々なネットワーク認証シナリオに対応できます。

詳細な情報については、以下のドキュメントも参照してください：
- [README_ja.md](README_ja.md) - プロジェクトの概要
- [test_case_ja.md](test_case_ja.md) - テストケースの詳細
- [architecture_diagrams.md](architecture_diagrams.md) - アーキテクチャ図