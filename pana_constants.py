#!/usr/bin/env python3
"""
PANA Protocol Constants and Enums
RFC5191 compliant constants for PANA protocol

【概要】
PANAプロトコルで使用される定数と列挙型を定義するモジュール。
RFC5191およびRFC6786で規定された値を厳密に実装しています。

【主な内容】
- メッセージタイプ定数
- フラグビット定義
- AVP（Attribute-Value Pair）コード
- アルゴリズム識別子
- EAP関連定数
- ステートマシン状態定義
- デフォルトパラメータ値
"""

# ============================================================================
# Message and AVP Format Constants
# ============================================================================

# PANA Message Header Size (RFC5191 Section 6.2)
PANA_HEADER_SIZE = 16  # bytes: Reserved(2) + Length(2) + Flags(2) + Type(2) + SessionID(4) + Sequence(4)

# AVP Header Size (RFC5191 Section 6.3)
AVP_HEADER_SIZE = 8    # bytes: Code(2) + Flags(2) + Length(2) + Reserved(2)

# AVP Value Alignment
AVP_ALIGNMENT = 4      # AVP values must be padded to 4-byte boundary

# Maximum sizes
MAX_AVP_LENGTH = 65535  # Maximum value for 16-bit length field
MAX_MESSAGE_LENGTH = 65535  # Maximum value for 16-bit message length field

# Field sizes in bytes
UINT16_SIZE = 2        # Size of 16-bit fields
UINT32_SIZE = 4        # Size of 32-bit fields

# ============================================================================
# RFC5191 PANA Message Types (single byte)
# PANAメッセージタイプ（1バイト）
# 各値はRFC5191 Section 7およびSection 10.2.1で定義
PANA_CLIENT_INITIATION = 1  # PCI: クライアント開始メッセージ
PANA_AUTH = 2              # PAR/PAN: 認証要求/応答メッセージ
PANA_TERMINATION = 3       # PTR/PTA: 終了要求/応答メッセージ
PANA_NOTIFICATION = 4      # PNR/PNA: 通知要求/応答メッセージ

# PANA Flags (RFC5191 Section 6.2)
# PANAメッセージヘッダーのフラグビット（16ビット中の上位6ビット）
FLAG_REQUEST = 0x8000      # R flag - Request: 要求メッセージであることを示す
FLAG_START = 0x4000        # S flag - Start: 認証フェーズの開始を示す
FLAG_COMPLETE = 0x2000     # C flag - Complete Auth: 認証フェーズの完了を示す
FLAG_REAUTH = 0x1000       # A flag - re-Authentication: 再認証を示す（PNR/PNA用のみ、RFC 5191 Section 6.2）
# Note: FLAG_AUTH removed - A-flag is ONLY for re-authentication PNR/PNA messages
FLAG_PING = 0x0800         # P flag - Ping request: ライブネスチェック要求を示す
FLAG_IP_RECONFIG = 0x0400  # I flag - IP Reconfiguration: IPアドレス再設定を示す

# AVP Codes (IANA準拠)
# AVP（Attribute-Value Pair）コード定義
# IANA PANA Parameters準拠 (https://www.iana.org/assignments/pana-parameters/)
AVP_AUTH = 1                     # 認証データ（HMAC）を含むAVP
AVP_EAP_PAYLOAD = 2              # EAPメッセージを含むAVP
AVP_INTEGRITY_ALGORITHM = 3      # 完全性保護アルゴリズムを指定するAVP
AVP_KEY_ID = 4                   # 鍵識別子を含むAVP
AVP_NONCE = 5                    # ノンス（ランダム値）を含むAVP
AVP_PRF_ALGORITHM = 6            # 擬似乱数関数アルゴリズムを指定するAVP
AVP_RESULT_CODE = 7              # 結果コードを含むAVP
AVP_SESSION_LIFETIME = 8         # セッション有効期間を含むAVP（RFC5191）
AVP_TERMINATION_CAUSE = 9        # 終了理由を含むAVP
AVP_PAC_INFORMATION = 10         # PaC Information（RFC6345）- 未使用
AVP_RELAYED_MESSAGE = 11         # Relayed-Message（RFC6345）- 未使用
AVP_ENCRYPTION_ENCAP = 12        # RFC 6786 - 暗号化カプセル化AVP
AVP_ENCRYPTION_ALGORITHM = 13    # RFC 6786 - 暗号化アルゴリズム指定AVP

# Algorithm IDs (IANA PANA Parameters準拠)
# アルゴリズム識別子
# https://www.iana.org/assignments/pana-parameters/
# RFC5191およびRFC6786で定義された暗号アルゴリズムID

# PRFアルゴリズム (IKEv2 Transform ID準拠)
PRF_HMAC_SHA1 = 2            # IKEv2 PRF_HMAC_SHA1
PRF_HMAC_SHA2_256 = 5        # IKEv2 PRF_HMAC_SHA2_256

# 認証アルゴリズム (IKEv2 Transform ID準拠)
AUTH_HMAC_SHA1_160 = 7       # IKEv2 AUTH_HMAC_SHA1_96 (実際は160bit使用)
AUTH_HMAC_SHA2_256_128 = 12  # IKEv2 AUTH_HMAC_SHA2_256_128

# 暗号化アルゴリズム (PANA Encryption-Algorithm AVP Values)
AES128_CTR = 1               # RFC 6786: AES-128-CTR mode (IANA: 1)

# EAP Codes
# EAPメッセージコード（RFC3748で定義）
EAP_REQUEST = 1    # EAP要求メッセージ
EAP_RESPONSE = 2   # EAP応答メッセージ
EAP_SUCCESS = 3    # EAP認証成功メッセージ
EAP_FAILURE = 4    # EAP認証失敗メッセージ

# EAP Types
# EAPメソッドタイプ
EAP_TYPE_IDENTITY = 1  # Identity（ユーザー識別情報）
EAP_TYPE_TLS = 13      # EAP-TLS（RFC5216）- 証明書ベース認証

# EAP-TLS Flags
# EAP-TLSメッセージフラグ（RFC5216）
EAP_TLS_FLAG_LENGTH = 0x80  # Lフラグ: 全体長フィールドが含まれることを示す
EAP_TLS_FLAG_MORE = 0x40    # Mフラグ: さらにフラグメントが続くことを示す
EAP_TLS_FLAG_START = 0x20   # Sフラグ: TLSハンドシェイクの開始を示す

# Retransmission parameters
# 再送信パラメータ
RETRANSMIT_INTERVAL = 3.0  # 再送信間隔（秒）
MAX_RETRANSMISSIONS = 3    # 最大再送信回数

# Session parameters
# セッションパラメータ
DEFAULT_SESSION_LIFETIME = 3600  # デフォルトセッション有効期間（1時間）
SESSION_CLEANUP_INTERVAL = 60    # 期限切れセッションのチェック間隔（1分）
AUTHENTICATED_SESSION_CLEANUP_DELAY = 300  # 認証済みセッションのクリーンアップ遅延（5分、テスト用）

# PANA State Machine States (RFC5191 Section 4)
# PANAステートマシンの状態定義
# PaC States (クライアント側の状態)
PAC_STATE_INITIAL = 'INITIAL'
PAC_STATE_WAIT_PAN_OR_PAR = 'WAIT_PAN_OR_PAR'
PAC_STATE_WAIT_EAP_MSG = 'WAIT_EAP_MSG'
PAC_STATE_WAIT_EAP_RESULT = 'WAIT_EAP_RESULT'
PAC_STATE_WAIT_EAP_RESULT_CLOSE = 'WAIT_EAP_RESULT_CLOSE'
PAC_STATE_OPEN = 'OPEN'
PAC_STATE_WAIT_PRA = 'WAIT_PRA'
PAC_STATE_SESS_TERM = 'SESS_TERM'
PAC_STATE_CLOSED = 'CLOSED'

# PAA States (認証エージェント側の状態)
PAA_STATE_INITIAL = 'INITIAL'
PAA_STATE_WAIT_EAP_MSG = 'WAIT_EAP_MSG'
PAA_STATE_WAIT_PAN_OR_PAR = 'WAIT_PAN_OR_PAR'
PAA_STATE_WAIT_SUCC_PAN = 'WAIT_SUCC_PAN'
PAA_STATE_WAIT_FAIL_PAN = 'WAIT_FAIL_PAN'
PAA_STATE_OPEN = 'OPEN'
PAA_STATE_WAIT_PRA = 'WAIT_PRA'
PAA_STATE_SESS_TERM = 'SESS_TERM'
PAA_STATE_CLOSED = 'CLOSED'

# TLS Key Export Label (RFC5216)
# TLS鍵エクスポート用ラベル（MSK/EMSK導出用）
TLS_EXPORT_LABEL = b"EXPORTER_EAP_TLS_Key_Material"  # 鍵材料エクスポート用ラベル
TLS_EXPORT_CONTEXT = b""                             # コンテキスト（空）

# Default cipher suites for EAP-TLS
# EAP-TLS用デフォルト暗号スイート
# 楕円曲線暗号とAES-128を使用する安全な暗号スイート
DEFAULT_CIPHERS = (
    'ECDHE-ECDSA-AES128-SHA256:'    # 楕円曲線DH + ECDSA + AES128 + SHA256
    'ECDHE-ECDSA-AES128-CCM:'       # 楕円曲線DH + ECDSA + AES128-CCM
    'ECDHE-ECDSA-AES128-CCM8'       # 楕円曲線DH + ECDSA + AES128-CCM8
)

# Result codes
# 結果コード（RFC5191 Section 8.7）
PANA_SUCCESS = 0                      # 認証および承認の両方が成功
PANA_AUTHENTICATION_REJECTED = 1      # 認証が失敗
PANA_AUTHORIZATION_REJECTED = 2       # 認証は成功したが承認が失敗

# Legacy aliases for backward compatibility (DEPRECATED - will be removed)
RESULT_CODE_SUCCESS = PANA_SUCCESS   # Use PANA_SUCCESS instead
RESULT_CODE_FAILURE = PANA_AUTHENTICATION_REJECTED  # Use PANA_AUTHENTICATION_REJECTED instead