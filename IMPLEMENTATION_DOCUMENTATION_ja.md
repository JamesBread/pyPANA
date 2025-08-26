# pyPANA 実装ドキュメント

## 目次
1. [プロジェクト概要](#プロジェクト概要)
2. [アーキテクチャ概要](#アーキテクチャ概要)
3. [コアプロトコル実装](#コアプロトコル実装)
4. [セキュリティ実装](#セキュリティ実装)
5. [セッション管理](#セッション管理)
6. [エンタープライズ機能](#エンタープライズ機能)
7. [テストと検証](#テストと検証)
8. [APIリファレンス](#apiリファレンス)
9. [設定](#設定)
10. [デプロイメント](#デプロイメント)
11. [トラブルシューティング](#トラブルシューティング)
12. [貢献](#貢献)
13. [ライセンス](#ライセンス)
14. [参考文献](#参考文献)

---

## プロジェクト概要

pyPANAは、RFC 5191で定義されたネットワークアクセス認証のためのプロトコル（PANA）の包括的なPython実装です。RFC 6786のAVP暗号化拡張もサポートしています。本実装は、クライアント（PaC - PANAクライアント）とサーバー（PAA - PANA認証エージェント）の両方の機能をエンタープライズグレードの機能と共に提供します。

### 主要機能
- **完全なRFC 5191準拠**: 適切な16バイトヘッダー形式でPANAプロトコルを完全実装
- **RFC 6786 AVP暗号化**: PANAメッセージ内の機密データ暗号化を完全サポート
- **EAP-TLS認証**: PyOpenSSL経由の適切なMSK/EMSK導出でRFC 5216準拠
- **エンタープライズ統合**: 外部認証用のRADIUSバックエンドサポート
- **本番環境対応**: レート制限、監視、統計収集、エラー回復
- **モジュラーアーキテクチャ**: 25以上の専門化されたモジュールによる関心の分離
- **包括的なテスト**: 完全なRFC準拠カバレッジを持つ15個のアクティブテストファイル

### 現在の実装状況 (v2.3.1)

#### ✅ 完全実装済み
- **コアPANAプロトコル (RFC 5191)**
  - 全メッセージタイプ: PCI（フラグ=0x0000）、PAR/PAN、PTR/PTA、PNR/PNA
  - PaCとPAAの両方の完全なステートマシン
  - 全必須フィールドを含む正しい16バイトヘッダー形式
  - 適切なAVP構造と解析（16ビットフィールド）
  - AUTH AVPによるメッセージ認証（SHA1-160、20バイト）
  - セッション有効期間管理
  - PANA-Notification（Aビット）による再認証サポート

- **セキュリティ機能 (RFC 6786)**
  - 機密AVP用のAES-128-CTR暗号化
  - 双方向暗号化鍵（PANA_PAC_ENCR_KEY、PANA_PAA_ENCR_KEY）
  - 暗号化アルゴリズムネゴシエーション
  - ポリシーベースの暗号化強制
  - スライディングウィンドウによるアンチリプレイ保護

- **EAP-TLS認証**
  - 完全なPyOpenSSLベースの実装
  - RFC 5705準拠の鍵エクスポート（"client EAP encryption"ラベル）
  - 適切なMSK/EMSK導出（各64バイト）
  - 証明書検証とチェーン検証
  - 正確なEAP-TLSパケット長計算（6バイトベース）

- **エンタープライズ機能**
  - 外部認証用のRADIUSプロキシモード
  - セッション統計と監視
  - レート制限とDoS保護
  - HTTPベースの監視インターフェース
  - 包括的なロギングとデバッグ

#### ⚠️ 部分実装
- **フラグメンテーション**: 基本サポート、RFC 5191セクション5.1に従い無効化
- **OpenPANA相互運用性**: プロトコルレベル互換（v2.3.1修正適用済み）

#### ❌ 未実装
- **追加のEAPメソッド**: 現在EAP-TLSのみサポート
- **PAAディスカバリー**: マルチキャストディスカバリー未実装
- **IPモビリティ**: IPアドレス変更の限定的サポート

---

## アーキテクチャ概要

### モジュール構成

コードベースは関心の明確な分離を持つクリーンなモジュラーアーキテクチャに従っています：

```
pyPANA/
├── main.py                      # エントリーポイントとCLIインターフェース
├── コアプロトコル層
│   ├── pana_messages.py         # メッセージとAVP構造
│   ├── pana_constants.py        # プロトコル定数と列挙型
│   ├── pana_client.py           # PaC実装
│   └── pana_server.py           # PAA実装
├── セキュリティ層
│   ├── pana_crypto.py           # 暗号化操作
│   ├── pana_antireplay.py       # アンチリプレイ保護
│   ├── pana_encryption_policy.py # RFC 6786暗号化ポリシー
│   ├── pana_client_encryption.py # クライアント側暗号化
│   └── pana_server_encryption.py # サーバー側暗号化
├── 認証層
│   ├── eap_tls_factory.py       # EAP-TLS実装選択
│   ├── eap_tls_pyopenssl.py     # PyOpenSSLベースのEAP-TLS
│   ├── eap_tls.py               # フォールバックEAP-TLS実装
│   └── radius_backend.py        # RADIUS統合
├── セッション管理
│   ├── pana_session.py          # セッションライフサイクル管理
│   ├── pana_retransmission.py   # 信頼性のあるメッセージ配信
│   └── pana_error_recovery.py   # エラー処理と回復
└── エンタープライズ機能
    ├── pana_statistics.py       # 統計収集
    ├── pana_monitor.py          # HTTPベース監視
    └── pana_ratelimit.py        # レート制限
```

### 主要なデザインパターン
- **ステートマシンパターン**: RFC 5191ステートマシンの適切な実装
- **ファクトリーパターン**: EAP-TLS実装の動的選択
- **オブザーバーパターン**: セッションイベント通知
- **ストラテジーパターン**: 暗号化ポリシー選択

---

## コアプロトコル実装

### メッセージ構造 (RFC 5191)

#### PANAヘッダー形式 (16バイト)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           予約                |        メッセージ長           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           フラグ              |        メッセージタイプ       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      セッション識別子                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      シーケンス番号                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### AVP形式 (8+ バイト)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           AVPコード           |           AVPフラグ           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           AVP長               |            予約               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    ベンダーID (オプション)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    値 ...
+-+-+-+-+-+-+-+-+
```

### メッセージタイプ

| タイプ | 値 | 説明 |
|--------|-----|------|
| PANA_CLIENT_INITIATION | 1 | PCI - クライアントによるセッション開始 |
| PANA_AUTH | 2 | PAR/PAN - 認証交換 |
| PANA_TERMINATION | 3 | PTR/PTA - セッション終了 |
| PANA_NOTIFICATION | 4 | PNR/PNA - 通知とping |

### ステートマシン

#### PaC（クライアント）の状態
- `INITIAL`: 初期状態
- `WAIT_PAN_OR_PAR`: サーバー応答待ち
- `WAIT_EAP_MSG`: EAP認証処理中
- `WAIT_EAP_RESULT`: 認証結果待ち
- `OPEN`: 認証済みセッション有効
- `CLOSED`: セッション終了

#### PAA（サーバー）の状態
- `INITIAL`: 初期状態
- `WAIT_EAP_MSG`: EAP応答待ち
- `WAIT_PAN_OR_PAR`: クライアント応答待ち
- `WAIT_SUCC_PAN`: 成功確認待ち
- `WAIT_FAIL_PAN`: 失敗確認待ち
- `OPEN`: 認証済みセッション有効
- `CLOSED`: セッション終了

### プロトコルフロー

```
PaC                          PAA                          RADIUS
 |                            |                              |
 |------ PCI (flags=0x0000) ->|                              |
 |<------- PAR (R|S) ---------|                              |
 |-------- PAN (S-bit) ------>|                              |
 |<------- PAR (EAP-Req) -----|                              |
 |-------- PAN (EAP-Resp) --->|------- Access-Request ------>|
 |                            |<------ Access-Challenge ------|
 |<------- PAR (EAP-TLS) -----|                              |
 |-------- PAN (EAP-TLS) ---->|                              |
 |          ...               |            ...                |
 |<------- PAR (C-bit) -------|<------ Access-Accept ---------|
 |-------- PAN (C-bit) ------>|                              |
```

### OpenPANA相互運用性

#### 相互運用性ステータス

| 方向 | ステータス | 備考 |
|-----|---------|------|
| pyPANA PaC → pyPANA PAA | ✅ 完了 | 完全な認証動作中 |
| pyPANA PAA → pyPANA PaC | ✅ 完了 | 完全な認証動作中 |
| pyPANA PaC → OpenPANA PAA | ✅ プロトコル互換 | v2.3.1修正適用済み |
| OpenPANA PaC → pyPANA PAA | ✅ プロトコル互換 | v2.3.1修正適用済み |

#### v2.3.1での主要修正
1. **PCIメッセージフラグ**: RFC 5191 Section 7.1準拠でflags=0x0000
2. **Nonce長**: RFC 5191準拠の20バイト
3. **AUTH AVP**: SHA1-160で20バイト（OpenPANA互換）
4. **EAP-TLSパケット長**: 正確な6バイトベース計算

---

## セキュリティ実装

### 鍵導出 (RFC 5191 Section 5.3)

#### マスター鍵導出
```python
# EAP-TLSから (RFC 5216)
MSK = export_keying_material("client EAP encryption", 64)
EMSK = export_keying_material("client EAP encryption", 64, offset=64)
```

#### PANA鍵導出
```python
# 認証鍵
PANA_AUTH_KEY = prf+(MSK, "IETF PANA"|I_PAR|I_PAN|PaC_nonce|PAA_nonce|Key_ID)

# 暗号化鍵 (RFC 6786)
PANA_PAC_ENCR_KEY = prf+(MSK, "IETF PANA PaC Encr"|I_PAR|I_PAN|PaC_nonce|PAA_nonce|Key_ID)
PANA_PAA_ENCR_KEY = prf+(MSK, "IETF PANA PAA Encr"|I_PAR|I_PAN|PaC_nonce|PAA_nonce|Key_ID)
```

### サポートされるアルゴリズム

| タイプ | アルゴリズム | ID | 説明 |
|--------|--------------|-----|------|
| PRF | PRF_HMAC_SHA1 | 2 | RFC 5191必須 |
| PRF | PRF_HMAC_SHA2_256 | 5 | 強化セキュリティ |
| Integrity | AUTH_HMAC_SHA1_160 | 7 | 160ビットHMAC-SHA1 |
| Integrity | AUTH_HMAC_SHA2_256_128 | 12 | 128ビット切り捨てHMAC-SHA256 |
| Encryption | AES128_CTR | 1 | カウンターモードAES-128 |

### AVP暗号化 (RFC 6786)

#### 暗号化ポリシー
```python
# 暗号化不可 (RFC 6786 Section 6.1)
NEVER_ENCRYPT = {AVP_AUTH, AVP_NONCE, AVP_KEY_ID, AVP_ENCRYPTION_ALGORITHM}

# 暗号化可能
MAY_ENCRYPT = {AVP_EAP_PAYLOAD, AVP_SESSION_LIFETIME, AVP_TERMINATION_CAUSE}

# 暗号化必須（将来使用）
MUST_ENCRYPT = {}
```

#### 暗号化プロセス
1. ポリシーに基づき暗号化するAVPを特定
2. 暗号化データを含むEncryption-Encap AVPを作成
3. RFC 6786準拠のnonceでAES-128-CTRを使用
4. メッセージにEncryption-Algorithm AVPを追加

### TLS鍵エクスポート

#### PyOpenSSL実装
```python
def export_keying_material(self, label, length, context=None):
    """RFC 5705準拠のTLS鍵エクスポート"""
    # 実際の実装はPyOpenSSLのexport_keying_material()を使用
    return self.tls_connection.export_keying_material(
        label.encode('utf-8'),
        length,
        context
    )
```

#### MSK/EMSK導出
```python
# EAP-TLSからMSKを導出
msk = tls_handler.export_keying_material(
    "client EAP encryption", 
    64  # 64バイト
)

# EMSKは必要に応じて追加の64バイトとして導出可能
emsk = tls_handler.export_keying_material(
    "client EAP encryption",
    64,
    offset=64
)
```

### アンチリプレイ保護

- **スライディングウィンドウ**: デフォルト32パケットウィンドウ
- **シーケンス番号追跡**: セッション毎のシーケンス検証
- **タイムスタンプ検証**: オプションの時間ベース検証
- **重複検出**: リプレイ攻撃を防止

---

## セッション管理

### セッションライフサイクル

1. **初期化**: PCIメッセージでセッション開始
2. **認証**: EAP-TLS交換
3. **バインド**: セッションの確立と鍵導出
4. **維持**: 定期的な生存確認（PNR/PNA）
5. **再認証**: セッション有効期限前の更新
6. **終了**: PTR/PTAメッセージでクリーンシャットダウン

### セッションパラメータ

```python
class PANASession:
    session_id: int        # 一意のセッション識別子
    sequence_number: int   # 現在のシーケンス番号
    session_lifetime: int  # セッション有効期間（秒）
    key_id: int           # アクティブな鍵識別子
    state: str            # 現在のステートマシンの状態
```

### 再送信管理

- **自動再試行**: 3回のデフォルト再送信
- **指数バックオフ**: 3秒、6秒、12秒の間隔
- **Rビットサポート**: 再送信要求の適切なマーキング
- **タイムアウト処理**: セッション回復または終了

---

## エンタープライズ機能

### RADIUS統合

#### プロキシモード操作
```python
# RADIUS設定でPAAを作成
agent = PANAAuthAgent(
    radius_server='192.168.1.100',
    radius_port=1812,
    radius_secret='shared_secret'
)
```

#### メッセージマッピング
- PANA PAR → RADIUS Access-Request
- RADIUS Access-Challenge → PANA PAR
- RADIUS Access-Accept → PANA PAR (C-bit)
- RADIUS Access-Reject → PANA PTR

### 監視と統計

#### 収集されるメトリクス
- 総セッション数
- 認証成功/失敗
- 平均認証時間
- メッセージ統計
- エラー率

#### HTTP監視インターフェース
```python
# ポート8080でHTTPサーバーを起動
monitor = PANAMonitor(port=8080)
monitor.start()

# エンドポイント:
# GET /stats - JSON形式の統計
# GET /health - ヘルスチェックステータス
# GET /sessions - アクティブセッション
```

### レート制限

#### DoS保護設定
```python
rate_limiter = RateLimiter(
    max_requests_per_second=100,
    max_concurrent_sessions=1000,
    blacklist_duration=300
)
```

---

## テストと検証

### テストスイート概要 (v2.3.1)

テストスイートは5つのカテゴリーに整理された15個のアクティブテストで構成されています：

### テストカテゴリー

1. **コア互換性テスト（5テスト）**
   - `test_compatibility.py` - 基本的なpyPANA ↔ pyPANA互換性
   - `test_compatibility_fixed.py` - スレッディングと改善された診断機能付き
   - `test_protocol_flow.py` - RFC 5191メッセージ形式検証（PCI flags=0x0000）
   - `test_simple_auth.py` - EAP-TLSの複雑さを除いた基本認証フロー
   - `test_e2e.py` - 完全フローのエンドツーエンドテスト

2. **OpenPANA相互運用性テスト（3テスト）**
   - `test_openpana_fixed.py` - v2.3.1修正適用済みOpenPANA互換性
   - `test_pypana_paa_openpana.py` - OpenPANA PaCテスト用PAAサーバー
   - `test_pypana_complete.py` - 完全なpyPANA認証テスト

3. **暗号化テスト（3テスト）**
   - `test_auth_avp.py` - AUTH AVP計算と検証
   - `test_crypto_algorithms.py` - アルゴリズム実装検証
   - `test_avp_format.py` - AVP構造とパディング検証

4. **RFC準拠テスト（3テスト）**
   - `test_rfc_compliance_fixes.py` - RFC 5191/6786準拠性検証（新規）
   - `test_rfc6786_compliance.py` - RFC 6786暗号化準拠
   - `test_rfc_compliant_reauth.py` - 再認証フロー準拠

5. **統合テスト（1テスト）**
   - `test_pana.py` - 基本PANAプロトコル統合

### テストの実行

```bash
# すべての15個のアクティブテストを実行
python3 run_tests.py

# 拡張互換性テストを実行（v2.3.1）
python3 tests/test_compatibility_fixed.py

# RFC準拠性検証を実行
python3 tests/test_rfc_compliance_fixes.py

# プロトコルフローテストを実行（PCI flags=0x0000を検証）
python3 tests/test_protocol_flow.py

# クイック相互運用性チェック
python3 tests/test_simple_auth.py
```

### テストドキュメント

包括的なテストドキュメントが利用可能：
- `tests/TEST_DOCUMENTATION.md` - 全15テストの詳細説明
- `tests/TEST_CATEGORIZATION.md` - テスト構成と状態
- `tests/TEST_COMPATIBILITY_FIXED.md` - 拡張互換性テストの詳細
- `tests/TEST_RFC_COMPLIANCE_FIXES.md` - RFC準拠テストのドキュメント
- `tests/RUN_TESTS_DOCUMENTATION.md` - テストランナーアーキテクチャ

### テストカバレッジ
- **コアプロトコル**: メッセージタイプとステートマシンの100%カバレッジ
- **セキュリティ**: 鍵導出と暗号化の完全カバレッジ  
- **エラー処理**: エッジケースと失敗シナリオ

---

## APIリファレンス

### PANAClient (PaC)

```python
class PANAClient:
    def __init__(self, server_addr, port=716, **kwargs):
        """PANAクライアントを初期化"""
        
    def start_authentication(self):
        """認証プロセスを開始"""
        
    def handle_message(self, msg):
        """受信メッセージを処理"""
        
    def terminate_session(self):
        """セッションを終了"""
```

### PANAAuthAgent (PAA)

```python
class PANAAuthAgent:
    def __init__(self, bind_addr='0.0.0.0', port=716, **kwargs):
        """PANA認証エージェントを初期化"""
        
    def run(self):
        """PAAサーバーを起動"""
        
    def handle_client(self, addr, msg):
        """クライアントメッセージを処理"""
        
    def create_session(self, client_addr):
        """新規セッションを作成"""
```

### PANAMessage

```python
class PANAMessage:
    def __init__(self):
        """PANAメッセージを作成"""
        
    def add_avp(self, avp):
        """AVPをメッセージに追加"""
        
    def pack(self):
        """メッセージをバイトにシリアライズ"""
        
    def unpack(self, data):
        """バイトからメッセージをデシリアライズ"""
```

---

## 設定

### 設定ファイル（pana_config.py）

```python
# セッションパラメータ
DEFAULT_SESSION_LIFETIME = 3600  # 1時間
RETRANSMIT_INTERVAL = 3.0       # 秒
MAX_RETRANSMISSIONS = 3

# アルゴリズム選択
PRF_ALGORITHM = PRF_HMAC_SHA1  # OpenPANA互換
AUTH_ALGORITHM = AUTH_HMAC_SHA1_160
ENCR_ALGORITHM = AES128_CTR

# セキュリティ設定
RATE_LIMIT_ENABLED = False
MAX_REQUESTS_PER_SECOND = 100
ANTI_REPLAY_WINDOW_SIZE = 32
```

### 環境変数

```bash
export PANA_DEBUG=1
export PANA_SESSION_LIFETIME=7200
export PANA_RATE_LIMIT_ENABLED=true
export PANA_RATE_LIMIT_MAX_RPS=50
```

---

## デプロイメント

### Dockerデプロイメント

```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "main.py", "paa", "--bind", "0.0.0.0"]
```

### Systemdサービス

```ini
[Unit]
Description=PANA Authentication Agent
After=network.target

[Service]
Type=simple
User=pana
ExecStart=/usr/bin/python3 /opt/pypana/main.py paa
Restart=always

[Install]
WantedBy=multi-user.target
```

### 本番環境チェックリスト

- [x] テスト証明書を本番CA署名証明書に置き換える
- [x] セキュリティ要件に応じた暗号化ポリシー設定
- [x] レート制限を有効化し、閾値を設定
- [x] ログローテーションとアーカイブ設定
- [x] 監視とアラート設定
- [x] フェイルオーバーと回復手順のテスト
- [x] 運用手順のドキュメント化

---

## トラブルシューティング

### よくある問題

1. **AUTH AVP検証失敗**
   - 両側で一致するアルゴリズムを確認
   - I_PARとI_PANが正しく保存されていることを確認
   - シーケンス番号の同期を確認

2. **EAP-TLSハンドシェイク失敗**
   - 証明書チェーンと有効性を確認
   - PyOpenSSLのインストールを確認
   - TLS 1.2サポートを確認

3. **暗号化ネゴシエーション失敗**
   - 両側が同じアルゴリズムをサポートしていることを確認
   - 暗号化ポリシー設定を確認
   - 鍵が適切に導出されていることを確認

4. **セッションタイムアウト**
   - 再送信パラメータを調整
   - ネットワーク接続を確認
   - ファイアウォールルールを確認

### デバッグモード

```bash
# デバッグログを有効化
python3 main.py pac 192.168.1.1 --debug

# 特定のモジュールを確認
export PYTHONPATH=.
python3 -c "import logging; logging.basicConfig(level=logging.DEBUG); from pana_crypto import CryptoContext; c = CryptoContext()"
```

---

## 貢献

### 開発セットアップ

```bash
# リポジトリをクローン
git clone https://github.com/yourusername/pypana.git
cd pypana

# 仮想環境を作成
python3 -m venv venv
source venv/bin/activate

# 依存関係をインストール
pip install -r requirements.txt
pip install -r requirements-dev.txt

# テストを実行
python3 run_tests.py  # 全15個のアクティブテストを実行
```

### コードスタイル

- PEP 8準拠
- 型ヒント使用推奨
- docstring必須
- 新機能にはユニットテスト含める

### 新機能の追加

1. 機能ブランチを作成
2. テストを書く
3. 実装を書く
4. ドキュメントを更新
5. プルリクエストを提出

---

## ライセンス

このプロジェクトはMITライセンスの下でライセンスされています - 詳細はLICENSEファイルを参照してください。

---

## 参考文献

- [RFC 5191](https://tools.ietf.org/html/rfc5191) - Protocol for Carrying Authentication for Network Access (PANA)
- [RFC 6786](https://tools.ietf.org/html/rfc6786) - Encrypting the Protocol for Carrying Authentication for Network Access (PANA) Attribute-Value Pairs (AVPs)
- [RFC 5216](https://tools.ietf.org/html/rfc5216) - The EAP-TLS Authentication Protocol
- [RFC 5705](https://tools.ietf.org/html/rfc5705) - Keying Material Exporters for Transport Layer Security (TLS)
- [RFC 3748](https://tools.ietf.org/html/rfc3748) - Extensible Authentication Protocol (EAP)

---

## 既知の実装上の制限事項

### メジャーな制限
- **EAPメソッド**: 現在EAP-TLSのみサポート（EAP-TTLS、PEAP等は未実装）
- **PAAディスカバリー**: マルチキャスト探索（224.0.0.246）未実装
- **IPモビリティ**: IPアドレス変更の限定的サポート
- **メッセージフラグメンテーション**: 大規模メッセージ（>64KB）の分割未実装

### マイナーな逸脱
- **Nonce交換タイミング**: S-bitがセットされた初期PANからクライアントnonceを抽出（RFC 5191からの軽微な逸脱）
- **再送信タイマー**: RFC5191のIRT/MRT/MRDパラメータによるランダム化バックオフではなく、固定3秒間隔

これらの制限事項は基本的なプロトコル動作やセキュリティには影響しませんが、厳密なRFC準拠実装との相互運用性で問題が発生する可能性があります。