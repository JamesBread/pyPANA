#!/usr/bin/env python3
"""
PANA Server Encryption Helper Functions
RFC 6786 encryption support for PANA server (PAA)

【概要】
PANAサーバー（PAA）側での暗号化処理をサポートするヘルパークラスを提供します。
RFC 6786で定義されたPANA暗号化拡張の実装において、サーバー固有の処理を担当します。

【主な機能】
1. クライアントからの暗号化アルゴリズム提案の処理
2. サーバー側の暗号化ポリシーの適用
3. メッセージの暗号化・復号化処理
4. セッション単位の暗号化状態管理
5. 暗号化統計情報の収集とログ出力
"""

import logging
from pana_constants import (
    AVP_ENCRYPTION_ALGORITHM,
    AVP_KEY_ID,
    AVP_NONCE,
    AVP_AUTH,
    AES128_CTR
)
from pana_messages import PANAMessage, AVP
from pana_encryption_policy import EncryptionPolicy, EncryptionContext


class ServerEncryptionHelper:
    """Helper class for server-side encryption operations
    
    【クラス説明】
    PANAサーバー（PAA）側での暗号化処理を支援するヘルパークラスです。
    クライアントとの暗号化ネゴシエーション、ポリシー適用、メッセージの暗号化/復号化など、
    サーバー固有の暗号化機能を提供します。
    """
    
    def __init__(self, encryption_policy=None):
        """Initialize encryption helper
        
        【メソッド説明】
        暗号化ヘルパーを初期化します。
        
        Args:
            encryption_policy: EncryptionPolicy instance or None for default
                              暗号化ポリシーインスタンス（Noneの場合はデフォルトポリシーを使用）
        """
        self.policy = encryption_policy or self._create_default_policy()
        self.logger = logging.getLogger('ServerEncryption')
        
    def _create_default_policy(self):
        """Create default server encryption policy
        
        【メソッド説明】
        デフォルトのサーバー暗号化ポリシーを作成します。
        デフォルトでは暗号化は有効ですが、強制はしない柔軟な設定となっています。
        
        Returns:
            EncryptionPolicy: デフォルトの暗号化ポリシー
        """
        policy = EncryptionPolicy()
        policy.encryption_enabled = True     # 暗号化を有効化
        policy.enforce_encryption = False    # 暗号化を強制しない（柔軟な設定）
        return policy
    
    def handle_client_algorithm(self, message, session):
        """Handle encryption algorithm from client
        
        【メソッド説明】
        クライアントから提案された暗号化アルゴリズムを処理します。
        アルゴリズムの妥当性を検証し、セッションでのネゴシエーションを行います。
        
        Args:
            message: PANAMessage containing client's algorithm
                    クライアントのアルゴリズムを含むPANAメッセージ
            session: PANASession to update
                    更新対象のPANAセッション
            
        Returns:
            int: Negotiated algorithm ID or None
                ネゴシエートされたアルゴリズムID、またはNone
        """
        # クライアントが提案した暗号化アルゴリズムを取得
        client_algorithm = message.get_encryption_algorithm()
        
        if client_algorithm is None:
            # クライアントが暗号化を提案していない場合
            self.logger.info("Client did not propose encryption")
            return None
            
        # セッションの暗号化コンテキストでアルゴリズムを検証
        if session.encryption_context.policy.validate_algorithm(client_algorithm):
            # アルゴリズムが有効な場合、ネゴシエーションを実行
            result = session.negotiate_encryption(client_algorithm)
            if result:
                self.logger.info(f"Accepted client encryption algorithm: {client_algorithm}")
                return client_algorithm
            else:
                self.logger.warning(f"Failed to negotiate algorithm: {client_algorithm}")
        else:
            # サポートされていないアルゴリズムの場合
            self.logger.warning(f"Client proposed unsupported algorithm: {client_algorithm}")
            
        return None
    
    def add_encryption_response(self, message, session):
        """Add encryption algorithm response to message
        
        【メソッド説明】
        ネゴシエートされた暗号化アルゴリズムをメッセージに追加します。
        暗号化がアクティブな場合のみ、アルゴリズムAVPを追加します。
        
        Args:
            message: PANAMessage to add algorithm to
                    アルゴリズムを追加する対象のPANAメッセージ
            session: PANASession with negotiated algorithm
                    ネゴシエート済みアルゴリズムを持つPANAセッション
        """
        if session.is_encryption_active():
            # セッションの暗号化アルゴリズムを取得してメッセージに追加
            algorithm = session.get_encryption_algorithm()
            message.add_encryption_algorithm_avp(algorithm)
            self.logger.info(f"Added encryption algorithm to response: {algorithm}")
    
    def prepare_message_with_encryption(self, message, session):
        """Prepare message with encryption if active
        
        【メソッド説明】
        暗号化がアクティブな場合、メッセージに暗号化を適用します。
        センシティブなAVPを識別し、適切に暗号化処理を行います。
        
        Args:
            message: PANAMessage to prepare
                    準備対象のPANAメッセージ
            session: PANASession with crypto context
                    暗号化コンテキストを持つPANAセッション
            
        Returns:
            bool: True if encryption was applied
                 暗号化が適用された場合True
        """
        if not session.is_encryption_active():
            # 暗号化が無効な場合は何もしない
            return False
            
        # メッセージに暗号化コンテキストを設定
        message.encryption_context = session.encryption_context
        
        # センシティブなAVPに暗号化を適用
        result = message.apply_encryption(session.crypto_ctx)
        
        if result:
            self.logger.debug(f"Applied encryption to message for session {session.session_id:08x}")
        
        return result
    
    def process_encrypted_message(self, message, session):
        """Process received message with potential encryption
        
        【メソッド説明】
        受信したメッセージに含まれる暗号化されたAVPを処理します。
        暗号化がアクティブな場合、暗号化されたAVPを復号化します。
        
        Args:
            message: Received PANAMessage
                    受信したPANAメッセージ
            session: PANASession with crypto context
                    暗号化コンテキストを持つPANAセッション
            
        Returns:
            list: Decrypted AVPs (empty if no encryption)
                 復号化されたAVPのリスト（暗号化なしの場合は空リスト）
        """
        if not session.is_encryption_active():
            # 暗号化が無効な場合は空リストを返す
            return []
            
        # 暗号化されたAVPを復号化
        decrypted_avps = message.decrypt_avps(session.crypto_ctx)
        
        if decrypted_avps:
            self.logger.debug(f"Decrypted {len(decrypted_avps)} AVPs from client message")
            
        return decrypted_avps
    
    def should_encrypt_avp(self, avp_code, session):
        """Check if an AVP should be encrypted for a session
        
        【メソッド説明】
        指定されたAVPコードが暗号化されるべきかを判定します。
        セッションの暗号化状態とポリシーに基づいて判断します。
        
        Args:
            avp_code: AVP code to check
                     チェック対象のAVPコード
            session: PANASession to check
                    チェック対象のPANAセッション
            
        Returns:
            bool: True if AVP should be encrypted
                 AVPが暗号化されるべき場合True
        """
        if not session.is_encryption_active():
            # 暗号化が無効な場合は暗号化不要
            return False
            
        # ポリシーに基づいて暗号化推奨かどうかを判定
        return session.encryption_context.policy.is_avp_encryption_recommended(avp_code)
    
    def enforce_encryption_policy(self, session):
        """Check if encryption policy is satisfied
        
        【メソッド説明】
        セッションが暗号化ポリシーを満たしているかをチェックします。
        暗号化が必須の場合、暗号化されていないセッションは拒否されます。
        
        Args:
            session: PANASession to check
                    チェック対象のPANAセッション
            
        Returns:
            bool: True if policy satisfied, False if session should be rejected
                 ポリシーが満たされている場合True、セッションを拒否すべき場合False
        """
        if self.policy.enforce_encryption and not session.is_encryption_active():
            # 暗号化が必須だが有効でない場合、セッションを拒否
            self.logger.warning(f"Session {session.session_id:08x} rejected: encryption required but not negotiated")
            return False
            
        return True
    
    def get_session_encryption_status(self, session):
        """Get encryption status for a session
        
        【メソッド説明】
        指定されたセッションの暗号化ステータス情報を取得します。
        セッションID、暗号化の有効状態、使用アルゴリズム、ポリシー強制状態を含みます。
        
        Args:
            session: PANASession to check
                    チェック対象のPANAセッション
            
        Returns:
            dict: Status information
                 以下の情報を含むステータス辞書:
                 - session_id: セッションID
                 - encryption_active: 暗号化が有効かどうか
                 - algorithm: 使用中の暗号化アルゴリズム
                 - policy_enforced: ポリシーが強制されているか
        """
        return {
            'session_id': session.session_id,
            'encryption_active': session.is_encryption_active(),
            'algorithm': session.get_encryption_algorithm(),
            'policy_enforced': self.policy.enforce_encryption
        }
    
    def log_encryption_stats(self, session_manager):
        """Log encryption statistics for all sessions
        
        【メソッド説明】
        すべてのセッションの暗号化統計情報をログに出力します。
        暗号化されているセッション数と総セッション数を表示し、
        ポリシー違反がある場合は警告を出力します。
        
        Args:
            session_manager: SessionManager instance
                           セッション管理を行うSessionManagerインスタンス
        """
        # 総セッション数を取得
        total_sessions = len(session_manager.sessions)
        # 暗号化が有効なセッション数をカウント
        encrypted_sessions = sum(1 for s in session_manager.sessions.values() 
                               if s.is_encryption_active())
        
        # 暗号化統計をログ出力
        self.logger.info(f"Encryption stats: {encrypted_sessions}/{total_sessions} sessions encrypted")
        
        # 暗号化が必須だが全セッションが暗号化されていない場合、警告を出力
        if self.policy.enforce_encryption and encrypted_sessions < total_sessions:
            self.logger.warning(f"{total_sessions - encrypted_sessions} sessions without required encryption")