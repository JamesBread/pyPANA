#!/usr/bin/env python3
"""
PANA Client Encryption Helper Functions
RFC 6786 encryption support for PANA client

【概要】
PANAクライアント（PaC）側の暗号化ヘルパー関数。
RFC 6786に準拠した暗号化ネゴシエーションとメッセージ処理を提供。

【主な機能】
- 暗号化アルゴリズムの提案
- サーバーからのアルゴリズム応答の処理
- メッセージの暗号化/復号
- 暗号化状態の管理とリセット
"""

import logging
from pana_constants import (
    AVP_ENCRYPTION_ALGORITHM,
    AVP_KEY_ID,
    AVP_NONCE,
    AES128_CTR
)
from pana_messages import PANAMessage, AVP
from pana_encryption_policy import EncryptionPolicy, EncryptionContext


class ClientEncryptionHelper:
    """クライアント側の暗号化操作を支援するヘルパークラス
    
    【クラス説明】
    PANAクライアントにおける暗号化関連の処理を担当。
    暗号化ネゴシエーション、メッセージの暗号化/復号を管理する。
    """
    
    def __init__(self, encryption_policy=None):
        """
        暗号化ヘルパーを初期化
        
        Args:
            encryption_policy: EncryptionPolicyインスタンス、Noneの場合デフォルトを使用
        """
        self.policy = encryption_policy or self._create_default_policy()
        self.encryption_context = EncryptionContext(self.policy)  # 暗号化コンテキスト
        self.logger = logging.getLogger('ClientEncryption')
        
    def _create_default_policy(self):
        """
        デフォルトのクライアント暗号化ポリシーを作成
        
        Returns:
            EncryptionPolicy: デフォルト設定のポリシー
        """
        policy = EncryptionPolicy()
        policy.encryption_enabled = True
        policy.enforce_encryption = False  # クライアントは柔軟に対応
        return policy
    
    def propose_encryption_algorithm(self, message):
        """
        メッセージに暗号化アルゴリズムの提案を追加
        
        Args:
            message: アルゴリズムAVPを追加するPANAMessage
            
        Returns:
            int: 提案したアルゴリズムID、暗号化が無効な場合None
        """
        if not self.policy.encryption_enabled:
            return None
            
        # 優先アルゴリズムを提案
        algorithm = self.policy.default_algorithm
        message.add_encryption_algorithm_avp(algorithm)
        
        self.logger.info(f"Proposing encryption algorithm: {algorithm}")
        return algorithm
    
    def handle_server_algorithm(self, message):
        """
        サーバーからの暗号化アルゴリズムを処理
        
        サーバーが選択したアルゴリズムを検証し、
        サポートされている場合はネゴシエーションを完了する。
        
        Args:
            message: サーバーのアルゴリズムを含むPANAMessage
            
        Returns:
            bool: アルゴリズムが受け入れられた場合True、それ以外False
        """
        server_algorithm = message.get_encryption_algorithm()
        
        if server_algorithm is None:
            self.logger.info("Server did not propose encryption")
            return False
            
        # 検証とネゴシエーション
        if self.policy.validate_algorithm(server_algorithm):
            result = self.encryption_context.negotiate_encryption(server_algorithm)
            if result:
                self.logger.info(f"Accepted server encryption algorithm: {server_algorithm}")
            else:
                self.logger.warning(f"Failed to negotiate algorithm: {server_algorithm}")
            return result
        else:
            self.logger.warning(f"Server proposed unsupported algorithm: {server_algorithm}")
            return False
    
    def prepare_message_with_encryption(self, message, crypto_context):
        """
        アクティブな場合、メッセージに暗号化を適用して準備
        
        ポリシーに従ってセンシティブなAVPを暗号化する。
        
        Args:
            message: 準備するPANAMessage
            crypto_context: 鍵を含むCryptoContext
            
        Returns:
            bool: 暗号化が適用された場合True
        """
        if not self.encryption_context.is_encryption_active():
            return False
            
        # メッセージに暗号化コンテキストを設定
        message.encryption_context = self.encryption_context
        
        # センシティブなAVPに暗号化を適用
        result = message.apply_encryption(crypto_context)
        
        if result:
            self.logger.debug("Applied encryption to message")
        
        return result
    
    def process_encrypted_message(self, message, crypto_context):
        """
        潜在的に暗号化された受信メッセージを処理
        
        Encryption-Encap AVPを探し、暗号化されたAVPを復号する。
        
        Args:
            message: 受信したPANAMessage
            crypto_context: 鍵を含むCryptoContext
            
        Returns:
            list: 復号されたAVPのリスト（暗号化がない場合は空）
        """
        if not self.encryption_context.is_encryption_active():
            return []
            
        # 暗号化されたAVPを復号
        decrypted_avps = message.decrypt_avps(crypto_context)
        
        if decrypted_avps:
            self.logger.debug(f"Decrypted {len(decrypted_avps)} AVPs from message")
            
        return decrypted_avps
    
    def should_encrypt_avp(self, avp_code):
        """
        AVPを暗号化すべきかチェック
        
        Args:
            avp_code: チェックするAVPコード
            
        Returns:
            bool: AVPを暗号化すべき場合True
        """
        if not self.encryption_context.is_encryption_active():
            return False
            
        return self.policy.is_avp_encryption_recommended(avp_code)
    
    def get_encryption_status(self):
        """
        現在の暗号化ステータスを取得
        
        Returns:
            dict: ステータス情報の辞書
                - enabled: 暗号化が有効か
                - active: 暗号化がアクティブか
                - algorithm: ネゴシエートされたアルゴリズム
                - enforce: 暗号化を強制するか
        """
        return {
            'enabled': self.policy.encryption_enabled,
            'active': self.encryption_context.is_encryption_active(),
            'algorithm': self.encryption_context.get_negotiated_algorithm(),
            'enforce': self.policy.enforce_encryption
        }
    
    def reset_encryption(self):
        """
        新しいセッションのために暗号化状態をリセット
        
        暗号化コンテキストを新しく作成し、ネゴシエーション状態を初期化する。
        """
        self.encryption_context = EncryptionContext(self.policy)
        self.logger.info("Reset encryption state")