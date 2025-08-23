#!/usr/bin/env python3
"""
EAP-TLS Factory - Returns the best available EAP-TLS implementation

【概要】
EAP-TLS認証ハンドラを生成するファクトリーモジュール。
利用可能な最良のEAP-TLS実装を自動選択し、
適切なハンドラインスタンスを生成します。

【主な機能】
- 複数のEAP-TLS実装からの最適な選択
- PyOpenSSL実装の優先選択（MSKエクスポート対応）
- 標準実装へのフォールバック
- 証明書とキーファイルの管理
"""

import logging

logger = logging.getLogger(__name__)


def create_eap_tls_handler(is_server=False, cert_file=None, key_file=None, ca_cert=None):
    """
    利用可能な最良のEAP-TLSハンドラを作成
    
    【説明】
    現在のシステムで利用可能なEAP-TLS実装を検出し、
    最適なハンドラを選択して生成します。優先順位は以下の通り：
    1. PyOpenSSL実装（MSKエクスポート機能付き）
    2. 標準実装（フォールバック用）
    
    【ファクトリーパターン】
    このファクトリーは具体的な実装クラスを隠蔽し、
    呼び出し元は実装の詳細を意識することなく
    適切なEAP-TLSハンドラを使用できます。
    
    Args:
        is_server: サーバーモードの場合True、クライアントモードの場合False
        cert_file: 証明書ファイルのパス
        key_file: 秘密鍵ファイルのパス  
        ca_cert: CA証明書ファイルのパス
    
    Returns:
        EAP-TLS handler instance: 選択されたEAP-TLSハンドラのインスタンス
    """
    # PyOpenSSL実装を最初に試行（MSKエクスポート機能のため優先）
    try:
        from eap_tls_pyopenssl import EAPTLSWithPyOpenSSL
        logger.info("Using PyOpenSSL-based EAP-TLS implementation")
        # PyOpenSSL実装を使用（RFC 5216準拠のMSKエクスポートが可能）
        return EAPTLSWithPyOpenSSL(
            is_server=is_server,
            cert_file=cert_file,
            key_file=key_file,
            ca_cert=ca_cert
        )
    except ImportError:
        # PyOpenSSLライブラリが利用できない場合
        logger.debug("PyOpenSSL implementation not available")
    except Exception as e:
        # PyOpenSSL実装の初期化でエラーが発生した場合
        logger.warning(f"Failed to initialize PyOpenSSL implementation: {e}")
    
    # 標準実装にフォールバック
    from eap_tls import EAPTLSHandler
    logger.info("Using standard EAP-TLS implementation (limited MSK export)")
    # 標準EAP-TLS実装を使用（MSKエクスポート機能は制限的）
    return EAPTLSHandler(
        is_server=is_server,
        cert_file=cert_file,
        key_file=key_file,
        ca_file=ca_cert
    )