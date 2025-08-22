#!/usr/bin/env python3
"""
RFC 6786 Encryption Policy Configuration
Defines which AVPs require encryption and encryption policies

【概要】
RFC 6786に準拠したPANAメッセージ暗号化のためのポリシー設定モジュール。
どのAVPを暗号化するか、どの暗号アルゴリズムを使用するかを管理する。

【主な機能】
- AVP暗号化ポリシーの定義（必須/推奨）
- サポートする暗号アルゴリズムの管理
- 暗号化ネゴシエーションロジック
- セッション単位の暗号化コンテキスト管理
"""

from pana_constants import (
    AVP_KEY_ID,
    AVP_NONCE,
    AVP_AUTH,
    AVP_ENCRYPTION_ENCAP,
    AVP_ENCRYPTION_ALGORITHM,
    AVP_SESSION_LIFETIME,
    AVP_TERMINATION_CAUSE,
    AVP_EAP_PAYLOAD,
    AVP_RESULT_CODE,
    AVP_INTEGRITY_ALGORITHM,
    AVP_PRF_ALGORITHM,
    AVP_PAC_INFORMATION,
    AVP_RELAYED_MESSAGE,
    AES128_CTR
)


class EncryptionPolicy:
    """暗号化ポリシーを定義するクラス
    
    【クラス説明】
    PANA AVPの暗号化ポリシーを定義し、どのAVPを暗号化すべきか、
    どのアルゴリズムを使用するかを管理する。
    """
    
    def __init__(self):
        """デフォルトの暗号化ポリシーを初期化
        
        RFC 6786 Section 6.1準拠の暗号化ポリシーテーブル実装
        Enc列の値:
        - 'N': MUST NOT be encrypted (暗号化禁止)
        - 'Y': MUST be encrypted (暗号化必須)
        - 'X': MAY be encrypted (暗号化任意)
        """
        # RFC 6786 Section 6.1 - AVPs that MUST NOT be encrypted ('N')
        self.never_encrypt_avps = {
            # RFC 5191 AVPs
            AVP_AUTH,                   # RFC 6786: 'N' - 認証データ
            AVP_INTEGRITY_ALGORITHM,    # RFC 6786: 'N' - 完全性アルゴリズム
            AVP_KEY_ID,                 # RFC 6786: 'N' - 鍵識別子
            AVP_NONCE,                  # RFC 6786: 'N' - ノンス
            AVP_PRF_ALGORITHM,          # RFC 6786: 'N' - PRFアルゴリズム
            AVP_RESULT_CODE,            # RFC 6786: 'N' - 結果コード
            # RFC 6345 AVPs
            AVP_PAC_INFORMATION,        # RFC 6786: 'N' - PaC情報
            AVP_RELAYED_MESSAGE,        # RFC 6786: 'N' - リレーメッセージ
            # RFC 6786 AVPs
            AVP_ENCRYPTION_ALGORITHM,   # RFC 6786: 'N' - 暗号化アルゴリズム
            AVP_ENCRYPTION_ENCAP,       # RFC 6786: 'N' - 暗号化カプセル
        }
        
        # RFC 6786 - AVPs that MUST be encrypted ('Y')
        # 現在のRFC 6786では'Y'に指定されたAVPは存在しない
        # 将来の拡張用に空のセットとして定義
        self.mandatory_encrypt_avps = set()
        
        # RFC 6786 - AVPs that MAY be encrypted ('X')
        self.optional_encrypt_avps = {
            # RFC 5191 AVPs
            AVP_EAP_PAYLOAD,         # RFC 6786: 'X' - EAPペイロード
            AVP_SESSION_LIFETIME,    # RFC 6786: 'X' - セッション有効期間
            AVP_TERMINATION_CAUSE,   # RFC 6786: 'X' - 終了理由
        }
        
        # サポートする暗号アルゴリズム（優先順位順）
        self.supported_algorithms = [
            AES128_CTR,      # AES-128 カウンターモード
        ]
        
        # デフォルトアルゴリズム
        self.default_algorithm = AES128_CTR
        
        # 暗号化が有効かどうか
        self.encryption_enabled = False
        
        # 必須暗号化を強制するかどうか
        self.enforce_encryption = False
    
    def get_avp_encryption_requirement(self, avp_code):
        """
        AVPの暗号化要件を取得 (RFC 6786 Section 6.1準拠)
        
        Args:
            avp_code: チェックするAVPコード
            
        Returns:
            str: 'N' (MUST NOT), 'Y' (MUST), 'X' (MAY), or None (未定義)
        """
        if avp_code in self.never_encrypt_avps:
            return 'N'
        elif avp_code in self.mandatory_encrypt_avps:
            return 'Y'
        elif avp_code in self.optional_encrypt_avps:
            return 'X'
        else:
            # RFC 6786: 仕様で明示されていないAVPはMAY扱い
            return 'X'
    
    def is_avp_encryption_required(self, avp_code):
        """
        AVPが必ず暗号化されるべきかチェック
        
        Args:
            avp_code: チェックするAVPコード
            
        Returns:
            bool: 暗号化が必須の場合True
        """
        if not self.encryption_enabled:
            return False
        
        requirement = self.get_avp_encryption_requirement(avp_code)
        return requirement == 'Y'
    
    def is_avp_encryption_recommended(self, avp_code):
        """
        AVPが暗号化されるべきかチェック
        
        Args:
            avp_code: チェックするAVPコード
            
        Returns:
            bool: 暗号化が推奨される場合True ('Y' or 'X')
        """
        if not self.encryption_enabled:
            return False
        
        requirement = self.get_avp_encryption_requirement(avp_code)
        # 'Y' (MUST) または 'X' (MAY) の場合は暗号化推奨
        return requirement in ('Y', 'X')
    
    def get_avps_to_encrypt(self, avp_list):
        """
        暗号化すべきAVPをフィルタリング
        
        AVPリストを暗号化対象と平文に分割する。
        
        Args:
            avp_list: AVPインスタンスのリスト
            
        Returns:
            tuple: (暗号化対象AVPリスト, 平文AVPリスト)
        """
        if not self.encryption_enabled:
            return [], avp_list
            
        avps_to_encrypt = []  # 暗号化対象
        avps_plaintext = []   # 平文のまま
        
        for avp in avp_list:
            if self.is_avp_encryption_recommended(avp.code):
                avps_to_encrypt.append(avp)
            else:
                avps_plaintext.append(avp)
        
        return avps_to_encrypt, avps_plaintext
    
    def validate_encryption_policy(self, avp_list, encrypted_avps):
        """
        暗号化ポリシーの妥当性を検証
        
        Args:
            avp_list: すべてのAVPのリスト
            encrypted_avps: 暗号化されたAVPのコードリスト
            
        Returns:
            tuple: (valid: bool, errors: list of error messages)
        """
        errors = []
        
        # 暗号化が有効な場合のチェック
        if self.encryption_enabled:
            # 必須暗号化AVPが平文で送信されていないかチェック
            for avp in avp_list:
                if avp.code in self.mandatory_encrypt_avps and avp.code not in encrypted_avps:
                    errors.append(f"Mandatory encryption AVP {avp.code} sent in plaintext")
            
            # 暗号化禁止AVPが暗号化されていないかチェック
            for avp_code in encrypted_avps:
                if avp_code in self.never_encrypt_avps:
                    errors.append(f"Never-encrypt AVP {avp_code} was encrypted")
        
        # 暗号化が強制されている場合
        if self.enforce_encryption and self.encryption_enabled:
            # オプション暗号化AVPもすべて暗号化されているかチェック
            for avp in avp_list:
                if (avp.code in self.optional_encrypt_avps and 
                    avp.code not in encrypted_avps and
                    avp.code not in self.never_encrypt_avps):
                    errors.append(f"Optional AVP {avp.code} must be encrypted when enforce_encryption is True")
        
        return len(errors) == 0, errors
    
    def validate_algorithm(self, algorithm_id):
        """
        暗号アルゴリズムがサポートされているか検証
        
        Args:
            algorithm_id: アルゴリズム識別子
            
        Returns:
            bool: アルゴリズムがサポートされている場合True
        """
        return algorithm_id in self.supported_algorithms
    
    def select_algorithm(self, peer_algorithms):
        """
        ピアがサポートするアルゴリズムから最適なものを選択
        
        自身の優先順位に従って、最初にマッチしたアルゴリズムを選択する。
        
        Args:
            peer_algorithms: ピアがサポートするアルゴリズムのリスト
            
        Returns:
            int: 選択されたアルゴリズムID、またはマッチしない場合None
        """
        for algo in self.supported_algorithms:
            if algo in peer_algorithms:
                return algo
        return None


class EncryptionContext:
    """セッションの暗号化状態を管理するクラス
    
    【クラス説明】
    PANAセッションごとの暗号化状態を管理し、
    ネゴシエーション結果や現在の暗号化設定を保持する。
    """
    
    def __init__(self, policy=None):
        """
        暗号化コンテキストを初期化
        
        Args:
            policy: EncryptionPolicyインスタンス（Noneの場合デフォルトを作成）
        """
        self.policy = policy or EncryptionPolicy()
        self.negotiated_algorithm = None  # ネゴシエートされたアルゴリズム
        self.encryption_active = False    # 暗号化がアクティブか
        
    def negotiate_encryption(self, peer_algorithm):
        """
        ピアと暗号化をネゴシエート
        
        Args:
            peer_algorithm: ピアが提案したアルゴリズム
            
        Returns:
            bool: ネゴシエーションが成功した場合True
        """
        if not self.policy.encryption_enabled:
            return False
            
        # 提案されたアルゴリズムがサポートされているか確認
        if self.policy.validate_algorithm(peer_algorithm):
            self.negotiated_algorithm = peer_algorithm
            self.encryption_active = True
            return True
            
        return False
    
    def is_encryption_active(self):
        """
        このセッションで暗号化がアクティブか確認
        
        Returns:
            bool: 暗号化がアクティブな場合True
        """
        return self.encryption_active and self.negotiated_algorithm is not None
    
    def get_negotiated_algorithm(self):
        """
        ネゴシエートされた暗号アルゴリズムを取得
        
        Returns:
            int: アルゴリズムID、またはNone
        """
        return self.negotiated_algorithm