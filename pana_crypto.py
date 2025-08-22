#!/usr/bin/env python3
"""
PANA Cryptographic Context Implementation
RFC5191 compliant cryptographic operations

【概要】
このモジュールはPANAプロトコルの暗号化処理を実装します。
RFC5191およびRFC6786に準拠した鍵導出、認証、暗号化機能を提供します。

【主な機能】
- 鍵導出（MSK/EMSKからPANA鍵を生成）
- メッセージ認証（HMAC-SHA256）
- データ暗号化（AES-128-CTR）
- AVP暗号化（RFC6786準拠）
- nonce生成
"""

import os
import struct
import hashlib
import hmac
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from pana_constants import (
    PRF_HMAC_SHA1, PRF_HMAC_SHA2_256, 
    AUTH_HMAC_SHA1_160, AUTH_HMAC_SHA2_256_128, 
    AES128_CTR
)


class CryptoContext:
    """Cryptographic context for PANA session
    
    【クラス説明】
    PANAセッションの暗号化コンテキストを管理するクラス。
    各セッション固有の暗号化パラメータと鍵を保持します。
    
    【保持する情報】
    - 暗号化アルゴリズム（PRF、認証、暗号化）
    - マスター鍵（MSK/EMSK）
    - 導出鍵（PANA_AUTH_KEY、PANA_ENCR_KEY）
    - nonce値（PAA/PaC）
    - セッション識別情報（session_id、key_id）
    """
    def __init__(self):
        """
        暗号化コンテキストの初期化
        
        【初期値】
        - PRFアルゴリズム: HMAC-SHA2-256
        - 認証アルゴリズム: HMAC-SHA2-256-128（128ビットに切り詰め）
        - 暗号化アルゴリズム: AES-128-CTR
        """
        self.prf_algorithm = PRF_HMAC_SHA1           # RFC 5191 mandatory PRF algorithm
        self.auth_algorithm = AUTH_HMAC_SHA1_160     # RFC 5191 mandatory integrity algorithm
        self.encr_algorithm = AES128_CTR             # 暗号化アルゴリズム
        self.msk = None  # Master Session Key from EAP（EAPから取得）
        self.emsk = None  # Extended Master Session Key（拡張マスター鍵）
        self.pana_auth_key = None  # PANA認証鍵（導出鍵）
        self.pana_encr_key = None  # PANA暗号化鍵（導出鍵）- 旧実装用
        self.pana_pac_encr_key = None  # PaC→PAA暗号化鍵
        self.pana_paa_encr_key = None  # PAA→PaC暗号化鍵
        self.nonce_paa = None      # PAAが生成したnonce
        self.nonce_pac = None      # PaCが生成したnonce
        self.key_id = None         # 鍵識別子（4バイト）
        self.session_id = None     # セッションID（32ビット）
        self.i_par = None  # 初期PANA-Auth-Request（Sビット付き）のバイト列
        self.i_pan = None  # 初期PANA-Auth-Answer（Sビット付き）のバイト列
        self.logger = logging.getLogger('CryptoContext')
        
    def derive_keys(self, msk, emsk=None):
        """RFC5191 Section 5.3に準拠したPANA鍵導出
        
        【説明】
        EAP認証で取得したMSK（Master Session Key）からPANA用の鍵を導出します。
        RFC5191のセクション5.3に定義された方法に従います。
        
        引数:
            msk: Master Session Key（EAPから取得）
            emsk: Extended Master Session Key（オプション）
        
        【鍵導出式】
        PANA_AUTH_KEY = prf+(MSK, "IETF PANA"|I_PAR|I_PAN|PaC_nonce|PAA_nonce|Key_ID)
        
        【生成される鍵】
        - PANA_AUTH_KEY: メッセージ認証用の32バイト鍵
        - PANA_ENCR_KEY: データ暗号化用の16バイト鍵（AES-128用）
        """
        self.msk = msk
        self.emsk = emsk
        
        # Key_IDの生成（PAAのみ。PaCはPAAから受信する）
        if not self.key_id:
            self.key_id = os.urandom(4)  # 4バイトのランダム値
        
        # PRF入力データの構築（Session_IDを除外、I_PAR/I_PANを追加）
        # PANA_AUTH_KEY = prf+(MSK, "IETF PANA"|I_PAR|I_PAN|PaC_nonce|PAA_nonce|Key_ID)
        prf_input = (b"IETF PANA" + 
                     (self.i_par or b'') + 
                     (self.i_pan or b'') +
                     (self.nonce_pac or b'') + 
                     (self.nonce_paa or b'') + 
                     self.key_id)
        
        # デバッグログ：鍵導出パラメータ
        self.logger.info(f"Key derivation parameters:")
        self.logger.info(f"  i_par length: {len(self.i_par) if self.i_par else 0}")
        self.logger.info(f"  i_pan length: {len(self.i_pan) if self.i_pan else 0}")
        self.logger.info(f"  nonce_pac: {(self.nonce_pac or b'').hex()}")
        self.logger.info(f"  nonce_paa: {(self.nonce_paa or b'').hex()}")
        self.logger.info(f"  key_id: {self.key_id.hex()}")
        self.logger.info(f"  MSK length: {len(msk)}")
        self.logger.info(f"  MSK: {msk.hex()}")
        
        # IKEv2形式のPRF+実装
        self.pana_auth_key = self._prf_plus(
            msk, 
            prf_input,
            32,  # 出力長（SHA256ベースの場合）
            self.prf_algorithm
        )
        self.logger.info(f"  PANA_AUTH_KEY: {self.pana_auth_key.hex()[:32]}...")
        
        # RFC6786準拠の暗号化鍵導出
        # PANA_PAC_ENCR_KEY = prf+(MSK, "IETF PANA PaC Encr"|I_PAR|I_PAN|
        #                          PaC_nonce|PAA_nonce|Key_ID)
        pac_encr_input = (b"IETF PANA PaC Encr" + 
                          (self.i_par or b'') + 
                          (self.i_pan or b'') +
                          (self.nonce_pac or b'') + 
                          (self.nonce_paa or b'') + 
                          self.key_id)
        self.pana_pac_encr_key = self._prf_plus(msk, pac_encr_input, 16, self.prf_algorithm)
        
        # PANA_PAA_ENCR_KEY = prf+(MSK, "IETF PANA PAA Encr"|I_PAR|I_PAN|
        #                          PaC_nonce|PAA_nonce|Key_ID)
        paa_encr_input = (b"IETF PANA PAA Encr" + 
                          (self.i_par or b'') + 
                          (self.i_pan or b'') +
                          (self.nonce_pac or b'') + 
                          (self.nonce_paa or b'') + 
                          self.key_id)
        self.pana_paa_encr_key = self._prf_plus(msk, paa_encr_input, 16, self.prf_algorithm)
        
        # Backward compatibility: set pana_encr_key to pac key for old tests
        self.pana_encr_key = self.pana_pac_encr_key
        
    def compute_auth(self, message_data):
        """Compute AUTH AVP value
        
        【説明】
        PANAメッセージのAUTH AVP値を計算します。
        設定されたアルゴリズムに応じて適切なHMACを使用します。
        
        引数:
            message_data: AUTH AVPを除いたメッセージ全体のバイト列
            
        戻り値:
            認証タグ（HMAC値）
            
        例外:
            ValueError: 認証鍵が設定されていない場合、
                       またはサポートされていないアルゴリズムの場合
        """
        if not self.pana_auth_key:
            raise ValueError("No authentication key available")
            
        if self.auth_algorithm == AUTH_HMAC_SHA1_160:
            h = hmac.new(self.pana_auth_key, message_data, hashlib.sha1)
            return h.digest()  # 160ビット（20バイト）全体を使用
        elif self.auth_algorithm == AUTH_HMAC_SHA2_256_128:
            h = hmac.new(self.pana_auth_key, message_data, hashlib.sha256)
            return h.digest()[:16]  # 128ビット（16バイト）に切り詰め
        else:
            raise ValueError(f"Unsupported auth algorithm: {self.auth_algorithm}")
    
    def verify_auth(self, message_data, auth_value):
        """Verify AUTH AVP value
        
        【説明】
        受信したPANAメッセージのAUTH AVP値を検証します。
        タイミング攻撃を防ぐため、hmac.compare_digestを使用して
        定時間での比較を行います。
        
        引数:
            message_data: AUTH AVPを除いたメッセージ全体のバイト列
            auth_value: 受信したAUTH AVPの値
            
        戻り値:
            True: 認証成功（HMAC値が一致）
            False: 認証失敗（HMAC値が不一致）
        """
        computed = self.compute_auth(message_data)
        result = hmac.compare_digest(computed, auth_value)  # タイミング攻撃対策
        
        # デバッグログ：認証検証結果
        self.logger.info(f"AUTH verification:")
        self.logger.info(f"  computed: {computed.hex()}")
        self.logger.info(f"  received: {auth_value.hex()}")
        self.logger.info(f"  result: {result}")
        
        return result
    
    def encrypt(self, plaintext):
        """Encrypt data using AES-128-CTR
        
        【非推奨】このメソッドは廃止予定です。
        encrypt_for_pac() または encrypt_for_paa() を使用してください。
        
        【説明】
        AES-128-CTRモードを使用してデータを暗号化します。
        CTR（Counter）モードは、ストリーム暗号のように動作し、
        任意長のデータを暗号化できます。
        
        引数:
            plaintext: 暗号化する平文データ（バイト列）
            
        戻り値:
            IV（16バイト）+ 暗号文のバイト列
            
        例外:
            ValueError: 暗号化鍵が設定されていない場合
        """
        # 互換性のため、PaC暗号鍵を使用
        if not self.pana_pac_encr_key:
            raise ValueError("No encryption key available")
            
        # ランダムなIV（初期化ベクトル）を生成
        iv = os.urandom(16)  # 16バイト（128ビット）
        
        # AES-128-CTR暗号化器を作成
        cipher = Cipher(
            algorithms.AES(self.pana_pac_encr_key[:16]),  # AES-128用に最初の16バイトを使用
            modes.CTR(iv),  # CTRモード
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return iv + ciphertext  # IVを暗号文の先頭に付加
    
    def decrypt(self, ciphertext):
        """Decrypt data using AES-128-CTR
        
        【非推奨】このメソッドは廃止予定です。
        decrypt_from_pac() または decrypt_from_paa() を使用してください。
        
        【説明】
        AES-128-CTRモードを使用してデータを復号します。
        暗号文の先頭16バイトはIVとして扱われます。
        
        引数:
            ciphertext: IV（16バイト）+ 暗号文のバイト列
            
        戻り値:
            復号された平文データ（バイト列）
            
        例外:
            ValueError: 暗号化鍵が設定されていない場合、
                       または暗号文が16バイト未満の場合
        """
        # 互換性のため、PaC暗号鍵を使用
        if not self.pana_pac_encr_key:
            raise ValueError("No encryption key available")
            
        if len(ciphertext) < 16:
            raise ValueError("Invalid ciphertext length")
            
        # IVと実際の暗号文を分離
        iv = ciphertext[:16]              # 最初の16バイトがIV
        actual_ciphertext = ciphertext[16:]  # 残りが暗号文
        
        # AES-128-CTR復号器を作成
        cipher = Cipher(
            algorithms.AES(self.pana_pac_encr_key[:16]),
            modes.CTR(iv),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def encrypt_multiple_avps(self, avp_data_list):
        """
        複数のAVPデータを一括暗号化
        
        Args:
            avp_data_list: 暗号化するAVPデータのリスト
            
        Returns:
            bytes: 暗号化されたデータ
        """
        # すべてのAVPデータを結合
        combined_data = b''.join(avp_data_list)
        
        # 最大サイズチェック（64KB - オーバーヘッド）
        if len(combined_data) > 65000:
            raise ValueError(f"Combined AVP data too large: {len(combined_data)} bytes")
        
        return self.encrypt(combined_data)
        
    def generate_nonce(self):
        """Generate random nonce
        
        【説明】
        暗号学的に安全な20バイトのランダム値（nonce）を生成します。
        nonceは鍵導出時のエントロピー源として使用され、
        セッションごとに一意である必要があります。
        
        RFC 5191 Section 8.5: Maximum nonce length should be 20 octets
        (full PRF key length for HMAC-SHA1)
        
        戻り値:
            20バイトのランダムバイト列
        """
        return os.urandom(20)  # RFC 5191準拠: 20バイト（HMAC-SHA1のフル長）
    
    def encrypt_avp(self, avp):
        """Encrypt a single AVP according to RFC 6786
        
        【説明】
        RFC 6786に準拠して単一のAVPを暗号化します。
        AVP全体（ヘッダを含む）が暗号化され、Encryption-Encap AVPに
        格納するためのデータが生成されます。
        
        Args:
            avp: AVP instance to encrypt
            
        Returns:
            bytes: IV + encrypted AVP data
            
        引数:
            avp: 暗号化するAVPインスタンス
            
        戻り値:
            IV（16バイト）+ 暗号化されたAVPデータ
            
        例外:
            ValueError: 暗号化鍵が設定されていない場合
        """
        if not self.pana_encr_key:
            raise ValueError("No encryption key available")
        
        # AVPをバイナリ形式にパック（ヘッダ + 値 + パディング）
        avp_data = avp.pack()
        
        # ランダムなIVを生成
        iv = os.urandom(16)
        
        # パックされたAVPデータを暗号化
        cipher = Cipher(
            algorithms.AES(self.pana_encr_key[:16]),
            modes.CTR(iv),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        encrypted_avp = encryptor.update(avp_data) + encryptor.finalize()
        
        # IV + 暗号化されたAVPデータを返す
        return iv + encrypted_avp
    
    def decrypt_avp(self, encrypted_data):
        """Decrypt AVP data according to RFC 6786
        
        【説明】
        RFC 6786に準拠して暗号化されたAVPデータを復号します。
        Encryption-Encap AVPから取り出したデータを元のAVPに復元します。
        
        Args:
            encrypted_data: IV + encrypted AVP data
            
        Returns:
            AVP: Decrypted AVP instance
            
        引数:
            encrypted_data: IV（16バイト）+ 暗号化されたAVPデータ
            
        戻り値:
            復号されたAVPインスタンス
            
        例外:
            ValueError: 暗号化鍵が設定されていない場合、
                       またはデータ長が不正な場合
        """
        if not self.pana_encr_key:
            raise ValueError("No encryption key available")
        
        if len(encrypted_data) < 16:
            raise ValueError("Invalid encrypted AVP data length")
        
        # IVと暗号化されたAVPを分離
        iv = encrypted_data[:16]
        encrypted_avp = encrypted_data[16:]
        
        # AVPデータを復号
        cipher = Cipher(
            algorithms.AES(self.pana_encr_key[:16]),
            modes.CTR(iv),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        avp_data = decryptor.update(encrypted_avp) + decryptor.finalize()
        
        # AVPをアンパック（バイト列からAVPオブジェクトに変換）
        from pana_messages import AVP
        avp = AVP()
        avp.unpack(avp_data)
        
        return avp
    
    def _prf_plus(self, key, seed, output_len, prf_alg):
        """IKEv2 PRF+ 実装（RFC4306/RFC5996準拠）
        
        【説明】
        IKEv2で定義されたPRF+関数を実装します。
        PRF+(K,S) = T1 | T2 | T3 | T4 | ...
        T1 = prf(K, S | 0x01)
        T2 = prf(K, T1 | S | 0x02)
        T3 = prf(K, T2 | S | 0x03)
        ...
        
        引数:
            key: PRFキー
            seed: シード値
            output_len: 出力長（バイト）
            prf_alg: PRFアルゴリズム識別子
            
        戻り値:
            指定された長さの導出鍵
        """
        result = b''
        t = b''
        counter = 1
        
        # PRFアルゴリズムに応じたHMAC関数を選択
        if prf_alg == PRF_HMAC_SHA1:
            prf_func = lambda k, m: hmac.new(k, m, hashlib.sha1).digest()
        elif prf_alg == PRF_HMAC_SHA2_256:
            prf_func = lambda k, m: hmac.new(k, m, hashlib.sha256).digest()
        else:
            raise ValueError(f"Unsupported PRF algorithm: {prf_alg}")
        
        while len(result) < output_len:
            t = prf_func(key, t + seed + counter.to_bytes(1, 'big'))
            result += t
            counter += 1
            
        return result[:output_len]
    
    def build_aes_ctr_nonce(self, sequence_number):
        """Build RFC6786 compliant AES-CTR nonce
        
        【説明】
        RFC6786 Section 4.1準拠のnonceを構築します。
        nonce = Key-Id (4 bytes) | Session-ID (4 bytes) | Sequence Number (4 bytes)
        Total: 12 bytes in Network Byte Order
        
        引数:
            sequence_number: 32-bit sequence number
            
        戻り値:
            bytes: 12-byte nonce for AES-CTR
        """
        if not self.key_id or not isinstance(self.key_id, bytes) or len(self.key_id) != 4:
            raise ValueError("Invalid key_id: must be 4 bytes")
        if self.session_id is None:
            raise ValueError("Session ID not set")
            
        # Key-Id(4) | Session ID(4) | Sequence Number(4) = 12 octets
        return self.key_id + struct.pack('!II', self.session_id, sequence_number)
    
    def encrypt_for_paa(self, plaintext, sequence_number):
        """PaC→PAA方向の暗号化（RFC6786準拠）
        
        【説明】
        RFC6786 Section 4.1に準拠したAES-128-CTR暗号化を行います。
        nonceはKey-Id(4) | Session ID(4) | Sequence Number(4)の12オクテット。
        
        引数:
            plaintext: 暗号化する平文データ
            sequence_number: メッセージのシーケンス番号
            
        戻り値:
            暗号化されたデータ
        """
        if not self.pana_pac_encr_key:
            raise ValueError("No PaC encryption key available")
            
        # RFC6786準拠のnonce構築
        nonce = self.build_aes_ctr_nonce(sequence_number)
        
        # AES-CTR with formatted nonce (NIST SP800-38C Appendix A)
        # RFC 6786 Section 4.1: n=12, q=3
        # The formatting function prefix (0x02) is handled internally by the CTR mode
        # We provide the 16-byte initial counter value: nonce(12) + counter(4)
        initial_counter = nonce + b'\x00\x00\x00\x01'  # Start with counter=1
        cipher = Cipher(
            algorithms.AES(self.pana_pac_encr_key),
            modes.CTR(initial_counter),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()
    
    def decrypt_from_paa(self, ciphertext, sequence_number):
        """PAA→PaC方向の復号（RFC6786準拠）
        
        【説明】
        RFC6786 Section 4.1に準拠したAES-128-CTR復号を行います。
        
        引数:
            ciphertext: 暗号化されたデータ
            sequence_number: メッセージのシーケンス番号
            
        戻り値:
            復号された平文データ
        """
        if not self.pana_paa_encr_key:
            raise ValueError("No PAA encryption key available")
            
        # RFC6786準拠のnonce構築
        nonce = self.build_aes_ctr_nonce(sequence_number)
        
        # RFC 6786 Section 4.1: Counter starts at 1
        initial_counter = nonce + b'\x00\x00\x00\x01'
        cipher = Cipher(
            algorithms.AES(self.pana_paa_encr_key),
            modes.CTR(initial_counter),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def encrypt_for_pac(self, plaintext, sequence_number):
        """PAA→PaC方向の暗号化（RFC6786準拠）
        
        引数:
            plaintext: 暗号化する平文データ
            sequence_number: メッセージのシーケンス番号
            
        戻り値:
            暗号化されたデータ
        """
        return self.decrypt_from_paa(plaintext, sequence_number)  # CTRモードでは暗号化と復号は同じ
    
    def decrypt_from_pac(self, ciphertext, sequence_number):
        """PaC→PAA方向の復号（RFC6786準拠）
        
        引数:
            ciphertext: 暗号化されたデータ
            sequence_number: メッセージのシーケンス番号
            
        戻り値:
            復号された平文データ
        """
        return self.encrypt_for_paa(ciphertext, sequence_number)  # CTRモードでは暗号化と復号は同じ