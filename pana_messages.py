#!/usr/bin/env python3
"""
PANA Message Structure Implementation
RFC5191 compliant PANA message and AVP structures
Extended with RFC6786 encryption support

【概要】
このモジュールはPANAプロトコルのメッセージ構造とAVP (Attribute-Value Pair)の
実装を提供します。RFC5191およびRFC6786に準拠しています。

【主な機能】
- PANAメッセージのシリアライズ/デシリアライズ
- AVPのエンコード/デコード
- RFC6786準拠のAVP暗号化サポート
- メッセージフラグの管理
"""

import struct
from pana_constants import *
from pana_encryption_policy import EncryptionPolicy, EncryptionContext


class PANAMessage:
    """PANA Message Format (RFC5191 compliant with RFC6786 encryption)
    
    【クラス説明】
    PANAプロトコルのメッセージフォーマットを表現するクラス。
    RFC5191セクション6.2に定義されたフォーマットに準拠しています。
    
    【メッセージヘッダ構造】（16バイト） - RFC 5191 Section 6.2
    
    From RFC 5191 Section 6.2:
    
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Reserved            |        Message Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             Flags             |         Message Type          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Session Identifier                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  AVPs ...
    +-+-+-+-+-+-+-+-+
    
    - Reserved: 16 bits (MUST be set to zero)
    - Message Length: 16 bits (total length including header)
    - Flags: 16 bits (R,S,C,A,P,I flags)
    - Message Type: 16 bits
    - Session Identifier: 32 bits
    - Sequence Number: 32 bits
    """
    def __init__(self, encryption_context=None):
        # RFC5191 Section 6.2: Correct 16-byte header format
        self.reserved = 0     # 16ビット (must be 0)
        self.msg_length = 0   # 16ビット (total message length including header)
        self.flags = 0        # 16ビット (R,S,C,A,P,I flags)
        self.msg_type = 0     # 16ビット (メッセージタイプ)
        self.session_id = 0   # 32ビット (セッション識別子)
        self.seq_number = 0   # 32ビット (シーケンス番号)
        self.avps = []        # AVPのリスト
        
        # RFC 6786 暗号化サポート
        self.encryption_context = encryption_context
        
        # フラグメンテーションサポート
        self.raw_data = None  # フラグメントデータ用
        
    def pack(self):
        """
        メッセージをバイト列にパック（シリアライズ）
        
        【説明】
        PANAメッセージオブジェクトをネットワーク送信用の
        バイト列に変換します。
        
        戻り値:
            メッセージヘッダ（16バイト）とAVPを含むバイト列
        """
        # RFC 5191: PANA Header is 16 bytes with Message Length field
        # Calculate AVP data first to determine total message length
        if hasattr(self, 'raw_data') and self.raw_data:
            avp_data = self.raw_data
        else:
            avp_data = b''
            for avp in self.avps:
                avp_data += avp.pack()
        
        # Calculate total message length (header + AVPs)
        self.msg_length = PANA_HEADER_SIZE + len(avp_data)
        
        # Pack header according to RFC 5191 Section 6.2
        header = struct.pack('!HHHH II',
                           self.reserved,      # Reserved (16 bits, must be 0)
                           self.msg_length,    # Message Length (16 bits)
                           self.flags,         # Flags (16 bits)
                           self.msg_type,      # Message Type (16 bits)
                           self.session_id,    # Session ID (32 bits)
                           self.seq_number)    # Sequence Number (32 bits)
        
        return header + avp_data
    
    def unpack(self, data):
        """
        バイト列からメッセージをアンパック（デシリアライズ）
        
        【説明】
        ネットワークから受信したバイト列をPANAメッセージ
        オブジェクトに変換します。
        
        引数:
            data: 受信したバイト列
        
        例外:
            ValueError: メッセージ長が不正またはメッセージタイプが無効
        """
        if len(data) < PANA_HEADER_SIZE:
            raise ValueError(f"Invalid PANA message length: must be at least {PANA_HEADER_SIZE} bytes")

        # Unpack the 16-byte header according to RFC 5191
        (self.reserved, self.msg_length, self.flags, self.msg_type,
         self.session_id, self.seq_number) = struct.unpack('!HHHH II', data[:PANA_HEADER_SIZE])
        
        # RFC 5191 Section 6.2: Reserved field MUST be set to zero
        if self.reserved != 0:
            raise ValueError(f"Reserved field not zero: {self.reserved} (RFC 5191 Section 6.2 violation)")
        
        # Validate message length
        if self.msg_length < PANA_HEADER_SIZE:
            raise ValueError(f"Invalid message length: {self.msg_length} (must be >= {PANA_HEADER_SIZE})")
        if len(data) < self.msg_length:
            raise ValueError(f"Incomplete message: expected {self.msg_length} bytes, got {len(data)}")
        
        # Validate message type
        valid_msg_types = [PANA_CLIENT_INITIATION, PANA_AUTH, PANA_TERMINATION, 
                          PANA_NOTIFICATION]
        if self.msg_type not in valid_msg_types:
            raise ValueError(f"Invalid PANA message type: {self.msg_type}")
        
        # RFC 5191 Section 6.2: Use Message Length field to determine message boundary
        # Parse AVPs only up to the message length, not the entire data buffer
        offset = PANA_HEADER_SIZE
        message_end = min(self.msg_length, len(data))  # Respect message length boundary
        while offset < message_end:
            if offset + AVP_HEADER_SIZE > message_end:
                raise ValueError("Incomplete AVP header within message boundary")
                
            avp = AVP()
            try:
                avp_len = avp.unpack(data[offset:])
                self.avps.append(avp)
                offset += avp_len
            except Exception as e:
                raise ValueError(f"Failed to parse AVP at offset {offset}: {e}")
            
        return self.msg_length  # Return actual message length, not data buffer size

    def is_request(self):
        """
        メッセージが要求（Request）かどうかをチェック
        
        戻り値:
            True: 要求メッセージ (Rフラグがセット)
            False: 応答メッセージ (Rフラグがクリア)
        """
        return bool(self.flags & FLAG_REQUEST)
    
    def set_request(self, is_req=True):
        """
        要求フラグ（Rフラグ）を設定またはクリア
        
        引数:
            is_req: Trueの場合は要求、Falseの場合は応答
        """
        if is_req:
            self.flags |= FLAG_REQUEST
        else:
            self.flags &= ~FLAG_REQUEST
            
    def add_avp(self, avp):
        """
        AVPをメッセージに追加
        
        引数:
            avp: 追加するAVPオブジェクト
        """
        self.avps.append(avp)
    
    def add_encryption_algorithm_avp(self, algorithm_id):
        """
        RFC 6786 Encryption-Algorithm AVPを追加
        
        【説明】
        暗号化アルゴリズムを指定するAVPを追加します。
        このAVPは暗号化ネゴシエーションで使用されます。
        
        引数:
            algorithm_id: 暗号化アルゴリズム識別子（例: 1 = AES128_CTR）
        """
        algo_data = struct.pack('!I', algorithm_id)
        algo_avp = AVP(AVP_ENCRYPTION_ALGORITHM, 0, algo_data)
        self.add_avp(algo_avp)
    
    def get_encryption_algorithm(self):
        """Get encryption algorithm from message
        
        暗号化アルゴリズムをメッセージから取得
        
        【説明】
        メッセージ内のEncryption-Algorithm AVPから
        暗号化アルゴリズムの識別子を取得します。
        
        Returns:
            int: アルゴリズムID（例: 1=AES128_CTR）、存在しない場合はNone
        """
        algo_avp = self.get_avp(AVP_ENCRYPTION_ALGORITHM)
        if algo_avp and len(algo_avp.value) >= UINT32_SIZE:
            return struct.unpack('!I', algo_avp.value[:UINT32_SIZE])[0]
        return None
    
    def apply_encryption(self, crypto_context):
        """Apply encryption to sensitive AVPs according to RFC 6786
        
        RFC 6786に従って機密AVPを暗号化
        
        【説明】
        暗号化ポリシーに基づいて、機密性の高いAVPを選択し、
        それらをEncryption-Encap AVPにまとめて暗号化します。
        
        Args:
            crypto_context: 暗号化鍵を持つCryptoContext
            
        Returns:
            bool: 暗号化が適用された場合True、されなかった場合False
        """
        if not self.encryption_context or not self.encryption_context.is_encryption_active():
            return False
        
        # Get policy and filter AVPs
        policy = self.encryption_context.policy
        avps_to_encrypt, avps_plaintext = policy.get_avps_to_encrypt(self.avps)
        
        if not avps_to_encrypt:
            return False
        
        # Create encrypted AVP set
        enc_set = EncryptedAVPSet(crypto_context)
        for avp in avps_to_encrypt:
            enc_set.add_avp(avp)
        
        # Create Encryption-Encap AVP
        encap_avp = enc_set.create_encryption_encap_avp()
        
        # Replace AVPs with encrypted version
        self.avps = avps_plaintext
        self.add_avp(encap_avp)
        
        # Add algorithm AVP if not present
        if not self.get_avp(AVP_ENCRYPTION_ALGORITHM):
            self.add_encryption_algorithm_avp(self.encryption_context.negotiated_algorithm)
        
        return True
    
    def decrypt_avps(self, crypto_context):
        """Decrypt any Encryption-Encap AVPs in the message
        
        メッセージ内のEncryption-Encap AVPを復号
        
        【説明】
        メッセージに含まれる暗号化されたAVPを復号します。
        RFC 6786では1つのメッセージに1つのEncryption-Encap AVP
        のみが許可されています。
        
        Args:
            crypto_context: 復号鍵を持つCryptoContext
            
        Returns:
            list: 復号されたAVPのリスト
        """
        decrypted_avps = []
        
        # Find all Encryption-Encap AVPs
        encap_avps = self.get_avps(AVP_ENCRYPTION_ENCAP)
        
        # RFC 6786 Section 5: There SHALL be only one Encryption-Encap AVP in a PANA message
        if len(encap_avps) > 1:
            raise ValueError(f"Multiple Encryption-Encap AVPs found ({len(encap_avps)}), RFC 6786 Section 5 allows only one")
        
        for encap_avp in encap_avps:
            enc_set = EncryptedAVPSet(crypto_context)
            try:
                avps = enc_set.decrypt_encryption_encap_avp(encap_avp)
                decrypted_avps.extend(avps)
            except Exception:
                # Log decryption failure but continue
                pass
        
        return decrypted_avps
        
    def get_avp(self, code):
        """Get the first AVP with the specified code
        
        指定されたコードを持つ最初のAVPを取得
        
        Args:
            code: AVPコード（例: AVP_AUTH, AVP_EAP_PAYLOAD）
            
        Returns:
            AVP: 見つかったAVP、存在しない場合はNone
        """
        for avp in self.avps:
            if avp.code == code:
                return avp
        return None
        
    def get_avps(self, code):
        """Get all AVPs with the specified code
        
        指定されたコードを持つすべてのAVPを取得
        
        Args:
            code: AVPコード
            
        Returns:
            list: 該当するAVPのリスト（空の場合もある）
        """
        return [avp for avp in self.avps if avp.code == code]


class AVP:
    """Attribute Value Pair
    
    【クラス説明】
    PANAプロトコルのAVP (Attribute-Value Pair) を表現するクラス。
    AVPはPANAメッセージ内の属性情報を運ぶための基本単位です。
    
    【AVPフォーマット】 - RFC 5191 Section 6.3
    
    From RFC 5191 Section 6.3:
    
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           AVP Code            |           AVP Flags           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          AVP Length           |            Reserved           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Vendor-Id (opt)                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Value ...
    +-+-+-+-+-+-+-+-+
    
    - AVP Code: 16 bits
    - AVP Flags: 16 bits
    - AVP Length: 16 bits (length of Value field only, not including header)
    - Reserved: 16 bits (MUST be set to zero)
    - Vendor-Id: 32 bits (optional, only present if V flag is set)
    - Value: variable length (padded to 4-byte boundary)
    """
    def __init__(self, code=0, flags=0, value=b'', vendor_id=None):
        self.code = code    # AVPコード (例: 1=AUTH, 2=EAP-Payload)
        self.flags = flags  # フラグ (V-bit for vendor-specific)
        self.value = value  # AVPの値 (バイト列)
        self.vendor_id = vendor_id  # RFC 5191 Section 6.3: Optional Vendor-Id field
        
    def pack(self):
        """
        AVPをバイト列にパック
        
        【説明】
        AVPオブジェクトをネットワーク送信用のバイト列に変換します。
        値は4バイト境界にパディングされます。
        
        戻り値:
            AVPヘッダ（8または12バイト）とパディングされた値を含むバイト列
        """
        # RFC 5191 Section 6.3: "The AVP Length field indicates the number of octets 
        # in the Value field. The length of the AVP Code, AVP Length, AVP Flags, 
        # Reserved and Vendor-Id fields are not counted in the AVP Length value."
        length = len(self.value)  # Value length only, NOT including header
        
        # Pad to 4-byte boundary
        padding = (AVP_ALIGNMENT - (len(self.value) % AVP_ALIGNMENT)) % AVP_ALIGNMENT
        
        # Set V-bit if vendor_id is present
        flags = self.flags
        if self.vendor_id is not None:
            flags |= 0x8000  # Set V-bit (bit 15)
        
        # RFC 5191 Section 6.3: AVP header is Code(2) + Flags(2) + Length(2) + Reserved(2)
        header = struct.pack('!HHHH', self.code, flags, length, 0)  # 0 for Reserved field
        
        # Add optional Vendor-Id field if V-bit is set
        if self.vendor_id is not None:
            header += struct.pack('!I', self.vendor_id)
        
        return header + self.value + (b'\x00' * padding)
    
    def unpack(self, data):
        """
        バイト列からAVPをアンパック
        
        【説明】
        ネットワークから受信したバイト列をAVPオブジェクトに
        変換します。パディングは自動的に削除されます。
        
        引数:
            data: AVPを含むバイト列
            
        戻り値:
            処理したAVPの全体長（パディング含む）
        """
        if len(data) < AVP_HEADER_SIZE:
            raise ValueError("Invalid AVP length")
            
        # RFC 5191 Section 6.3: AVP header is Code(2) + Flags(2) + Length(2) + Reserved(2)
        self.code, self.flags, length, reserved = struct.unpack('!HHHH', data[:AVP_HEADER_SIZE])
        
        # RFC 5191 Section 6.3: Reserved field MUST be set to zero
        if reserved != 0:
            raise ValueError(f"AVP Reserved field not zero: {reserved} (RFC 5191 Section 6.3 violation)")
        
        # Check for V-bit (vendor-specific AVP)
        header_size = AVP_HEADER_SIZE
        if self.flags & 0x8000:  # V-bit is set
            if len(data) < AVP_HEADER_SIZE + 4:
                raise ValueError("Invalid vendor-specific AVP length")
            self.vendor_id = struct.unpack('!I', data[AVP_HEADER_SIZE:AVP_HEADER_SIZE + 4])[0]
            header_size += 4  # Add Vendor-Id field size
        else:
            self.vendor_id = None
        
        # RFC 5191 Section 6.3: "The AVP Length field indicates the number of octets 
        # in the Value field" - it does NOT include header size
        value_length = length  # Length field contains value length only
        
        # Validate that we have enough data for the value
        if header_size + value_length > len(data):
            raise ValueError(f"Insufficient data for AVP value (need {header_size + value_length}, have {len(data)})")
            
        self.value = data[header_size:header_size + value_length]
        
        # Account for padding - total length includes header + value + padding
        padding = (AVP_ALIGNMENT - (value_length % AVP_ALIGNMENT)) % AVP_ALIGNMENT
        total_length = header_size + value_length + padding
        return total_length
        
    def __repr__(self):
        """String representation for debugging
        
        デバッグ用の文字列表現を返す
        """
        if self.vendor_id is not None:
            return f"AVP(code={self.code}, flags={self.flags}, vendor_id={self.vendor_id}, value_len={len(self.value)})"
        return f"AVP(code={self.code}, flags={self.flags}, value_len={len(self.value)})"


def create_avp_uint32(code, value):
    """
    32ビット無符号整数値を持つAVPを作成
    
    【説明】
    整数値をネットワークバイトオーダー（ビッグエンディアン）で
    エンコードしたAVPを作成するユーティリティ関数。
    
    引数:
        code: AVPコード
        value: 32ビット無符号整数値
        
    戻り値:
        作成されたAVPオブジェクト
    """
    return AVP(code, 0, struct.pack('!I', value))


class EncryptedAVPSet:
    """Helper class for RFC 6786 encrypted AVP handling
    
    【クラス説明】
    RFC 6786で定義された暗号化AVPの処理を支援するヘルパークラス。
    複数のAVPをまとめて暗号化し、Encryption-Encap AVPに格納します。
    
    【主な機能】
    - AVPの暗号化/復号
    - Encryption-Encap AVPの作成/解析
    - 暗号化メタデータの管理
    """
    
    def __init__(self, crypto_context):
        """
        暗号化コンテキストで初期化
        
        引数:
            crypto_context: 暗号化鍵を持つCryptoContextインスタンス
        """
        self.crypto_ctx = crypto_context
        self.avps_to_encrypt = []
        self.avp_order = []  # AVPの順序を保持
    
    def add_avp(self, avp):
        """Add an AVP to be encrypted
        
        暗号化対象のAVPを追加
        
        【説明】
        暗号化するAVPをセットに追加します。
        AVPの順序は保持され、復号時に同じ順序で復元されます。
        
        Args:
            avp: 暗号化するAVPインスタンス
        """
        self.avps_to_encrypt.append(avp)
        self.avp_order.append(avp.code)  # 順序を記録
    
    def add_avps(self, avp_list):
        """Add multiple AVPs to be encrypted at once
        
        複数のAVPを一度に暗号化対象として追加
        
        Args:
            avp_list: 暗号化するAVPインスタンスのリスト
        """
        for avp in avp_list:
            self.add_avp(avp)
    
    def create_encryption_encap_avp(self):
        """Create Encryption-Encap AVP containing all encrypted AVPs
        
        すべての暗号化AVPを含むEncryption-Encap AVPを作成
        
        【説明】
        追加されたすべてのAVPを1つのデータブロックにまとめ、
        暗号化してEncryption-Encap AVPに格納します。
        最大サイズは64KB（AVPヘッダを除く）です。
        
        Returns:
            AVP: 暗号化されたコンテンツを含むEncryption-Encap AVP
            
        Raises:
            ValueError: 暗号化するAVPがない、またはデータが大きすぎる場合
        """
        if not self.avps_to_encrypt:
            raise ValueError("No AVPs to encrypt")
        
        # Pack all AVPs into a single data block
        avp_data = b''
        for avp in self.avps_to_encrypt:
            avp_data += avp.pack()
        
        # Check maximum size (64KB - AVP header)
        max_data_size = MAX_AVP_LENGTH - AVP_HEADER_SIZE  # Max AVP length minus header
        if len(avp_data) > max_data_size:
            raise ValueError(f"Combined AVP data too large: {len(avp_data)} > {max_data_size}")
        
        # Encrypt the combined AVP data
        encrypted_data = self.crypto_ctx.encrypt(avp_data)
        
        # Check encrypted size
        if len(encrypted_data) > max_data_size:
            raise ValueError(f"Encrypted data too large: {len(encrypted_data)} > {max_data_size}")
        
        # Create Encryption-Encap AVP
        return AVP(AVP_ENCRYPTION_ENCAP, 0, encrypted_data)
    
    def decrypt_encryption_encap_avp(self, encap_avp):
        """Decrypt AVPs from Encryption-Encap AVP
        
        Encryption-Encap AVPからAVPを復号
        
        【説明】
        暗号化されたデータブロックを復号し、
        元のAVPのリストを復元します。
        
        Args:
            encap_avp: 暗号化されたAVPを含むEncryption-Encap AVP
            
        Returns:
            list: 復号されたAVPインスタンスのリスト
        """
        if encap_avp.code != AVP_ENCRYPTION_ENCAP:
            raise ValueError("Not an Encryption-Encap AVP")
        
        # Decrypt the data
        decrypted_data = self.crypto_ctx.decrypt(encap_avp.value)
        
        # Unpack AVPs from decrypted data
        avps = []
        avp_codes = []
        offset = 0
        
        while offset < len(decrypted_data):
            if len(decrypted_data) - offset < AVP_HEADER_SIZE:
                break  # Not enough data for AVP header
            
            # Read AVP header - RFC 5191: Code(2) + Flags(2) + Length(2) + Reserved(2)
            code, flags, length, reserved = struct.unpack('!HHHH', decrypted_data[offset:offset+AVP_HEADER_SIZE])
            
            # RFC 5191 Section 6.3: Validate reserved field
            if reserved != 0:
                raise ValueError(f"AVP Reserved field not zero in encrypted data: {reserved}")
            
            # RFC 5191: Length is value length only
            value_length = length
            padding = (AVP_ALIGNMENT - (value_length % AVP_ALIGNMENT)) % AVP_ALIGNMENT
            
            if offset + AVP_HEADER_SIZE + value_length > len(decrypted_data):
                raise ValueError("Invalid AVP length in decrypted data")
            
            avp = AVP()
            avp.code = code
            avp.flags = flags
            avp.value = decrypted_data[offset+AVP_HEADER_SIZE:offset+AVP_HEADER_SIZE+value_length]
            
            avps.append(avp)
            avp_codes.append(code)
            offset += AVP_HEADER_SIZE + value_length + padding  # header + value + padding
        
        return avps


def extract_avp_uint32(avp):
    """Extract a 32-bit unsigned integer value from an AVP
    
    AVPから32ビット無符号整数値を抽出
    
    Args:
        avp: 値を抽出するAVP
        
    Returns:
        int: 抽出された整数値、またはNone（AVPがNullまたは不正な長さの場合）
    """
    if avp and len(avp.value) == UINT32_SIZE:
        return struct.unpack('!I', avp.value)[0]
    return None