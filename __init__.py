#!/usr/bin/env python3
"""
pyPANA - RFC5191 PANAプロトコル実装
pyPANA - RFC5191 PANA Protocol Implementation

【概要】
RFC5191で規定されたネットワークアクセス認証のためのプロトコル（PANA）の
完全な実装です。RFC5216に基づくEAP-TLSサポートも含まれています。

A complete implementation of the Protocol for carrying Authentication for Network Access (PANA)
as specified in RFC5191, with EAP-TLS support according to RFC5216.

【主要クラス / Main classes】
- PANAClient: PANAクライアント（PaC）実装
- PANAAuthAgent: PANA認証エージェント（PAA）実装
- PANAMessage: PANAメッセージ構造
- AVP: 属性値ペア（Attribute-Value Pair）構造
- CryptoContext: PANA用暗号化操作
- EAPTLSHandler: EAP-TLS認証ハンドラー

【使用例 / Usage】
    from pana_client import PANAClient
    from pana_server import PANAAuthAgent
    
    # クライアントとして実行 / Run as client
    client = PANAClient('192.168.1.1')
    client.run()
    
    # サーバーとして実行 / Run as server  
    server = PANAAuthAgent()
    server.run()
"""

from .pana_constants import *
from .pana_messages import PANAMessage, AVP
from .pana_crypto import CryptoContext
from .pana_session import PANASession, SessionManager
from .pana_retransmission import RetransmissionManager
from .eap_tls import EAPTLSHandler
from .pana_client import PANAClient
from .pana_server import PANAAuthAgent

__version__ = "1.0.0"
__author__ = "pyPANA Contributors"
__description__ = "RFC5191 PANA Protocol Implementation with EAP-TLS support"

__all__ = [
    # Main classes
    'PANAClient',
    'PANAAuthAgent',
    
    # Protocol structures
    'PANAMessage',
    'AVP',
    
    # Crypto and security
    'CryptoContext',
    'EAPTLSHandler',
    
    # Session management
    'PANASession',
    'SessionManager',
    
    # Utilities
    'RetransmissionManager',
    
    # Constants
    # Message types
    'PANA_CLIENT_INITIATION',
    'PANA_AUTH',
    'PANA_TERMINATION',
    'PANA_NOTIFICATION',
    
    # Flags
    'FLAG_REQUEST',
    'FLAG_START',
    'FLAG_COMPLETE',
    'FLAG_REAUTH',  # RFC 5191: A-flag is only for re-authentication PNR/PNA
    'FLAG_PING',
    'FLAG_IP_RECONFIG',
    
    # AVP codes
    'AVP_AUTH',
    'AVP_EAP_PAYLOAD',
    'AVP_INTEGRITY_ALGORITHM',
    'AVP_KEY_ID',
    'AVP_NONCE',
    'AVP_PRF_ALGORITHM',
    'AVP_RESULT_CODE',
    'AVP_TERMINATION_CAUSE',
    'AVP_PAC_INFORMATION',
    'AVP_RELAYED_MESSAGE',
    'AVP_SESSION_LIFETIME',
    'AVP_ENCRYPTION_ENCAP',
    'AVP_ENCRYPTION_ALGORITHM',
    
    # Algorithm IDs
    'PRF_HMAC_SHA1',
    'PRF_HMAC_SHA2_256',
    'AUTH_HMAC_SHA1_160',
    'AUTH_HMAC_SHA2_256_128',
    'AES128_CTR',
    
    # States
    'PAC_STATE_INITIAL',
    'PAC_STATE_WAIT_PAN_OR_PAR',
    'PAC_STATE_WAIT_EAP_MSG',
    'PAC_STATE_WAIT_EAP_RESULT',
    'PAC_STATE_WAIT_EAP_RESULT_CLOSE',
    'PAC_STATE_OPEN',
    'PAC_STATE_WAIT_PRA',
    'PAC_STATE_SESS_TERM',
    'PAC_STATE_CLOSED',
    
    'PAA_STATE_INITIAL',
    'PAA_STATE_WAIT_EAP_MSG',
    'PAA_STATE_WAIT_PAN_OR_PAR',
    'PAA_STATE_WAIT_SUCC_PAN',
    'PAA_STATE_WAIT_FAIL_PAN',
    'PAA_STATE_OPEN',
    'PAA_STATE_WAIT_PRA',
    'PAA_STATE_SESS_TERM',
    'PAA_STATE_CLOSED',
]