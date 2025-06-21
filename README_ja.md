# pyPANA - RFC5191 PANAプロトコル実装

RFC5191で定義されたPANA（Protocol for carrying Authentication for Network Access）の完全なPython実装です。完全なEAP-TLS認証サポートを含み、OpenSSL 3.xに対応しています。

## PANAとは？

PANA（Protocol for carrying Authentication for Network Access）は、クライアントデバイス（PaC - PANAクライアント）とアクセスネットワーク（PAA - PANA認証エージェント）間でネットワークアクセス認証を可能にするUDPベースのプロトコルです。リンク層の変更を必要とせずにEAP（Extensible Authentication Protocol）メッセージを伝送します。

### 主要な使用例

- **ネットワークアクセス制御**: ネットワークアクセスを許可する前にデバイスを認証
- **ゲストネットワーク認証**: 802.1Xなしでセキュアなゲストアクセス
- **IoTデバイス認証**: リソース制約のあるデバイス向けの軽量認証
- **サービスプロバイダーネットワーク**: マルチテナント環境での認証

## 機能

- **RFC5191準拠**: PANAプロトコル仕様の完全実装
- **EAP-TLS認証**: 適切なキー導出を伴う完全なEAP-TLS（RFC5216）サポート
- **暗号化アルゴリズム**:
  - PRF_HMAC_SHA2_256（PRFアルゴリズム）
  - AUTH_HMAC_SHA2_256_128（完全性アルゴリズム）
  - AES128_CTR（暗号化アルゴリズム）
- **OpenSSL 3.xサポート**: OpenSSL 3.xと1.1の両方に対応
- **ステートマシン**: 適切なRFC5191ステートマシン実装
- **セッション管理**: ライフタイム管理と再認証サポート
- **メッセージ再送信**: Rビットサポートによる信頼性のあるメッセージ配信
- **包括的エラーハンドリング**: 堅牢な検証とエラー回復
- **RADIUSバックエンド**: `pyrad`によるオプションのRADIUS認証サポート

## 必要要件

- Python 3.7+
- OpenSSL 3.xまたは1.1
- Pythonパッケージ:
  - cryptography
  - pyOpenSSL
  - pyrad（オプション、RADIUSバックエンド用）

**RADIUS統合用（オプション）:**
- FreeRADIUSサーバー（または任意のRADIUSサーバー）
- RADIUSサーバーへのネットワークアクセス（UDPポート1812/1813）

## インストール

```bash
# リポジトリをクローン
git clone https://github.com/yourusername/pyPANA.git
cd pyPANA

# 依存関係をインストール
pip install -r requirements.txt
```

## クイックスタート

### 基本認証（EAP-TLSのみ）

**ターミナル1 - PAA（サーバー）:**
```bash
# デフォルト設定で実行（すべてのインターフェースのポート716にバインド）
sudo python3 pyPANA.py paa

# 特定のインターフェースとカスタムポートで実行
sudo python3 pyPANA.py paa --bind 192.168.1.100 --port 716
```

**ターミナル2 - PaC（クライアント）:**
```bash
# PAAに接続
python3 pyPANA.py pac 192.168.1.100

# カスタムポートでPAAに接続
python3 pyPANA.py pac 192.168.1.100 --port 716
```

注意: ポート716は管理者権限が必要です。テスト用には高いポート番号を使用できます。

### 例: localhostでの基本テスト

**ターミナル1（PAA）:**
```bash
sudo python3 pyPANA.py paa --debug
```

**ターミナル2（PaC）:**
```bash
python3 pyPANA.py pac 127.0.0.1 --debug
```

これにより、自動生成された自己署名証明書を使用してEAP-TLS認証が実行されます。

### コマンドラインオプション

**PAA（サーバー）オプション:**
```bash
python3 pyPANA.py paa [オプション]

オプション:
  --bind ADDRESS        特定のIPアドレスにバインド（デフォルト: 0.0.0.0）
  --port PORT          リッスンするUDPポート（デフォルト: 716）
  --debug              デバッグログを有効化
  --radius-server IP   RADIUSサーバーのIPアドレス
  --radius-port PORT   RADIUSサーバーポート（デフォルト: 1812）
  --radius-secret SECRET  RADIUS共有シークレット
  --radius-timeout SEC RADIUS要求タイムアウト（デフォルト: 5）
  --radius-retries N   RADIUS再試行回数（デフォルト: 3）
```

**PaC（クライアント）オプション:**
```bash
python3 pyPANA.py pac SERVER_IP [オプション]

オプション:
  --port PORT          PAAサーバーポート（デフォルト: 716）
  --debug              デバッグログを有効化
  --timeout SEC        接続タイムアウト（デフォルト: 10）
```

## プロトコル概要

### メッセージフロー

```
PaC（クライアント）                    PAA（サーバー）
     |                              |
     |------- PCI (Start) --------->|
     |                              |
     |<------ PAR (EAP-Req/Id) -----|
     |                              |
     |------- PAN (EAP-Resp/Id) --->|
     |                              |
     |<------ PAR (EAP-TLS) --------|
     |                              |
     |------- PAN (EAP-TLS) ------->|
     |         ...                  |
     |<------ PAR (EAP-Success) ----|
     |                              |
     |------- PAN (Complete) ------>|
     |                              |
     |        [認証済み]            |
```

### メッセージタイプ

- **PCI**: PANA-Client-Initiation - 認証プロセスを開始
- **PAR/PAN**: PANA-Auth-Request/Answer - EAPペイロードを伝送
- **PNR/PNA**: PANA-Notification-Request/Answer - キープアライブと通知
- **PRR/PRA**: PANA-Reauth-Request/Answer - セッション再認証
- **PTR/PTA**: PANA-Termination-Request/Answer - セッション終了

## 高度な使用方法

### カスタム設定

設定ファイルを作成するか、コード定数を変更してください：

```python
# セッションパラメータ
DEFAULT_SESSION_LIFETIME = 3600  # 1時間
RETRANSMIT_INTERVAL = 3.0       # 秒
MAX_RETRANSMISSIONS = 3

# 暗号化アルゴリズム
PRF_ALGORITHM = PRF_HMAC_SHA2_256
AUTH_ALGORITHM = AUTH_HMAC_SHA2_256_128
ENCR_ALGORITHM = AES128_CTR
```

### RADIUSバックエンド統合の使用

pyPANAはユーザー認証のためにRADIUSサーバーと統合できます。PANA認証エージェント（PAA）がRADIUSクライアントとして動作し、認証要求をRADIUSサーバーに転送します。

#### RADIUS統合のセットアップ

1. **FreeRADIUSのインストール（Ubuntu/Debianでの例）:**

```bash
# FreeRADIUSサーバーをインストール
sudo apt update
sudo apt install freeradius freeradius-utils

# サービスを開始
sudo systemctl start freeradius
sudo systemctl enable freeradius
```

2. **FreeRADIUSの設定:**

`/etc/freeradius/3.0/clients.conf`を編集してpyPANAをクライアントとして追加：

```
client pana_agent {
    ipaddr = 127.0.0.1
    secret = testing123
    shortname = pana-agent
    nastype = other
}
```

3. **`/etc/freeradius/3.0/users`にテストユーザーを追加:**

```
testuser    Cleartext-Password := "testpass"
            Reply-Message = "Welcome to PANA network"

alice       Cleartext-Password := "alice123"
            Reply-Message = "Alice authenticated successfully"

bob         Cleartext-Password := "bob456"
            Reply-Message = "Bob authenticated successfully"
```

4. **FreeRADIUSを再起動:**

```bash
sudo systemctl restart freeradius

# RADIUSが動作していることをテスト
radtest testuser testpass 127.0.0.1 0 testing123
```

#### RADIUSバックエンドでpyPANAを実行

**方法1: コマンドライン引数を使用:**

```bash
# RADIUSバックエンドでPAAを実行
sudo python3 pyPANA.py paa --radius-server 127.0.0.1 --radius-port 1812 --radius-secret testing123
```

**方法2: コード内での設定を使用:**

```python
from pyPANA import PANAAuthAgent

# RADIUS設定でPAAを作成
agent = PANAAuthAgent(
    bind_addr='0.0.0.0',
    port=716,
    radius_server='127.0.0.1',
    radius_port=1812,
    radius_secret='testing123'
)

agent.run()
```

#### 完全なRADIUSセットアップ例

同一マシンでpyPANAとRADIUSをセットアップする完全な例：

**ターミナル1 - FreeRADIUSセットアップ:**

```bash
# FreeRADIUSをインストールして設定
sudo apt install freeradius freeradius-utils

# PANAクライアント設定を追加
echo 'client pana_agent {
    ipaddr = 127.0.0.1
    secret = testing123
    shortname = pana-agent
    nastype = other
}' | sudo tee -a /etc/freeradius/3.0/clients.conf

# テストユーザーを追加
echo 'testuser    Cleartext-Password := "testpass"
            Reply-Message = "Welcome to PANA network"' | sudo tee -a /etc/freeradius/3.0/users

# FreeRADIUSを再起動
sudo systemctl restart freeradius

# RADIUSが動作していることを確認
radtest testuser testpass 127.0.0.1 0 testing123
```

**ターミナル2 - RADIUSでPAAを実行:**

```bash
# RADIUSバックエンドでPANA認証エージェントを実行
sudo python3 pyPANA.py paa --radius-server 127.0.0.1 --radius-port 1812 --radius-secret testing123 --debug
```

**ターミナル3 - PANAクライアントを実行:**

```bash
# PANAクライアントを実行
python3 pyPANA.py pac 127.0.0.1 --debug
```

#### RADIUSでの認証フロー

```
PaC（クライアント）         PAA（サーバー）         RADIUSサーバー
     |                    |                      |
     |-- PCI (Start) ---->|                      |
     |                    |                      |
     |<-- PAR (EAP-Req) --|                      |
     |                    |                      |
     |-- PAN (EAP-Resp) ->|-- Access-Request --->|
     |                    |                      |
     |                    |<-- Access-Accept ----|
     |                    |                      |
     |<-- PAR (Success) --|                      |
     |                    |                      |
     |-- PAN (Complete) ->|                      |
     |                    |                      |
     |   [認証済み]       |                      |
```

#### RADIUS設定オプション

RADIUS統合をカスタマイズできます：

```python
# 高度なRADIUS設定
agent = PANAAuthAgent(
    radius_server='127.0.0.1',
    radius_port=1812,
    radius_secret='testing123',
    radius_timeout=5,           # 要求タイムアウト（秒）
    radius_retries=3,           # 再試行回数
    radius_nas_identifier='pana-agent',  # NAS識別子
    radius_nas_ip='192.168.1.100'       # NAS IPアドレス
)
```

#### RADIUS統合のトラブルシューティング

1. **RADIUSサーバーが応答しない:**
```bash
# FreeRADIUSのステータスを確認
sudo systemctl status freeradius

# RADIUSログを確認
sudo tail -f /var/log/freeradius/radius.log

# RADIUSを手動でテスト
radtest testuser testpass 127.0.0.1 0 testing123
```

2. **認証失敗:**
```bash
# FreeRADIUSでデバッグモードを有効化
sudo freeradius -X

# RADIUSエラーのpyPANAデバッグログを確認
python3 pyPANA.py paa --radius-server 127.0.0.1 --debug
```

3. **一般的な問題:**
   - **間違った共有シークレット**: clients.confとpyPANAでシークレットが一致することを確認
   - **ファイアウォールによるブロック**: RADIUSはUDPポート1812/1813を使用
   - **ユーザーが見つからない**: FreeRADIUS設定のusersファイルを確認
   - **IP制限**: clients.confでクライアントIPが許可されていることを確認

#### 外部RADIUSサーバーとの統合

pyPANAはMicrosoft NPS、Cisco ISE、クラウドベースのAAAサービスなどの外部RADIUSサーバーとも連携できます：

```bash
# 外部RADIUSサーバーに接続
sudo python3 pyPANA.py paa \
  --radius-server radius.company.com \
  --radius-port 1812 \
  --radius-secret "your-shared-secret" \
  --radius-nas-identifier "pana-gateway-01"
```

### 証明書の使用

本番環境では、自己署名証明書の生成を実際の証明書に置き換えてください：

```python
# コード内で
eap_handler = EAPTLSHandler(
    is_server=True,
    cert_file='/path/to/server.crt',
    key_file='/path/to/server.key'
)
```

### 統合例

```python
from pyPANA import PANAClient

# クライアントを作成して設定
client = PANAClient('paa.example.com')

# カスタム認証ハンドリングを追加
def on_auth_success(session_key):
    print(f"認証成功！セッションキー: {session_key.hex()}")
    # 後続の通信でセッションキーを使用

# 認証を実行
client.run()
```

## アーキテクチャ

### コアコンポーネント

1. **PANAMessage**: プロトコルメッセージ構造とシリアライゼーション
2. **PANAClient (PaC)**: ステートマシン付きクライアント実装
3. **PANAAuthAgent (PAA)**: サーバー実装
4. **EAPTLSHandler**: EAP-TLS認証ハンドリング
5. **CryptoContext**: キー導出と暗号化操作
6. **SessionManager**: セッションライフサイクル管理
7. **RetransmissionManager**: 信頼性のあるメッセージ配信

### ステートマシン

実装はRFC5191ステートマシンに従います：

**PaCステート**: INITIAL → WAIT_PAN_OR_PAR → WAIT_EAP_MSG → WAIT_EAP_RESULT → OPEN

**PAAステート**: INITIAL → WAIT_EAP_MSG → WAIT_PAN_OR_PAR → WAIT_SUCC_PAN → OPEN

## セキュリティ考慮事項

1. **証明書検証**: 例では自己署名証明書を使用しています。本番環境では：
   - 信頼できるCAからの証明書を使用
   - 適切な証明書検証を有効化
   - 証明書失効チェックを実装

2. **キーストレージ**: 秘密キーとセッションキーを保護：
   - セキュアなキーストレージメカニズムを使用
   - 適切なキーローテーションを実装
   - 使用後にメモリからキーをクリア

3. **ネットワークセキュリティ**:
   - PANAはUDPを使用 - ネットワークレベルの保護を検討
   - DoS攻撃を防ぐためのレート制限を実装
   - 認証失敗を監視

## トラブルシューティング

### よくある問題

1. **Permission Denied（ポート716）**
   ```
   解決方法: sudoで実行するか、テスト用に1024より大きいポートを使用
   ```

2. **OpenSSL Not Found**
   ```
   解決方法: OpenSSL 3.xまたは1.1をインストールし、システムパスに含まれることを確認
   ```

3. **Module Import Errors**
   ```
   解決方法: 必要要件をインストール: pip install -r requirements.txt
   ```

### デバッグモード

詳細ログを有効化：
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 開発

### テストの実行

```bash
# 基本構造テスト
python test_basic.py

# 完全テストスイート（依存関係が必要）
python test_pana.py
```

### 貢献

1. リポジトリをフォーク
2. 機能ブランチを作成（`git checkout -b feature/amazing-feature`）
3. 変更をコミット（`git commit -m 'Add amazing feature'`）
4. ブランチにプッシュ（`git push origin feature/amazing-feature`）
5. プルリクエストを開く

### 新機能の追加

プロトコルを拡張するには：

1. 定数に新しいメッセージタイプ/AVPを追加
2. PANAClient/PANAAuthAgentでハンドラーを実装
3. ステートマシンの遷移を更新
4. 新機能のテストを追加

## 参考文献

- [RFC5191](https://tools.ietf.org/html/rfc5191) - Protocol for Carrying Authentication for Network Access (PANA)
- [RFC5216](https://tools.ietf.org/html/rfc5216) - The EAP-TLS Authentication Protocol
- [RFC5705](https://tools.ietf.org/html/rfc5705) - Keying Material Exporters for TLS
- [RFC3748](https://tools.ietf.org/html/rfc3748) - Extensible Authentication Protocol (EAP)

## ライセンス

このプロジェクトはMITライセンスの下でライセンスされています - 詳細はLICENSEファイルを参照してください。

## サポート

問題や質問については：
- GitHubでissueを開く
- 既存のissueで解決方法を確認
- 問題を報告する際はデバッグログを提供

## 謝辞

この実装は、RFC5191および関連する標準でIETFによって定義された仕様に従っています。