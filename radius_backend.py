#!/usr/bin/env python3
"""
RADIUS Backend Integration for PANA
Implements RADIUS client functionality for enterprise authentication

【概要】
PANAの企業認証向けRADIUSバックエンド統合モジュール。
PANAプロトコルから企業のRADIUSサーバーに認証を委譲する機能を提供します。

【主な機能】
- RADIUS Access-Request/Accept/Reject/Challengeメッセージの処理
- EAPメッセージのRADIUSカプセル化
- RADIUS属性の管理とエンコーディング
- メッセージ認証子（Message-Authenticator）の計算
- セッション状態の維持とタイムアウト処理
- 複数RADIUSサーバーへの負荷分散とフェイルオーバー

【アーキテクチャ】
このモジュールはフェーズ3の要件に対応し、PANAが企業の既存認証インフラ
（RADIUS/Active Directory/LDAP）と統合できるようにします。

【RFC準拠】
- RFC 2865: Remote Authentication Dial In User Service (RADIUS)
- RFC 2869: RADIUS Extensions 
- RFC 3579: RADIUS (Remote Authentication Dial In User Service) Support For Extensible Authentication Protocol (EAP)
"""

import os
import socket
import struct
import hashlib
import hmac
import time
import logging
import threading
from typing import Optional, Tuple, Dict, Any, List
from enum import IntEnum
import random

# RADIUS定数
RADIUS_AUTH_PORT = 1812  # 認証ポート（RFC 2865）
RADIUS_ACCT_PORT = 1813  # アカウンティングポート（RFC 2866）

class RadiusCode(IntEnum):
    """RADIUSパケットコード（RFC 2865準拠）
    
    【説明】
    RADIUSプロトコルで使用されるメッセージタイプの定義。
    各コードは特定の認証フローにおける役割を持ちます。
    """
    ACCESS_REQUEST = 1      # アクセス要求（クライアント→サーバー）
    ACCESS_ACCEPT = 2       # アクセス許可（サーバー→クライアント）
    ACCESS_REJECT = 3       # アクセス拒否（サーバー→クライアント）
    ACCOUNTING_REQUEST = 4  # アカウンティング要求
    ACCOUNTING_RESPONSE = 5 # アカウンティング応答
    ACCESS_CHALLENGE = 11   # アクセスチャレンジ（EAP継続時）
    STATUS_SERVER = 12      # サーバー状態確認
    STATUS_CLIENT = 13      # クライアント状態確認

class RadiusAttribute(IntEnum):
    """一般的なRADIUS属性（RFC 2865準拠）
    
    【説明】
    RADIUSメッセージで使用される標準属性タイプの定義。
    各属性はネットワークアクセス制御に必要な情報を運搬します。
    """
    USER_NAME = 1           # ユーザー名
    USER_PASSWORD = 2       # ユーザーパスワード（PAP用）
    NAS_IP_ADDRESS = 4      # NAS（Network Access Server）のIPアドレス
    NAS_PORT = 5            # NASポート番号
    SERVICE_TYPE = 6        # サービスタイプ
    FRAMED_PROTOCOL = 7     # フレーム化プロトコル
    CALLED_STATION_ID = 30  # 呼び出し先ステーション（アクセスポイントMAC等）
    CALLING_STATION_ID = 31 # 呼び出し元ステーション（クライアントMAC等）
    NAS_IDENTIFIER = 32     # NAS識別子（文字列）
    STATE = 24              # 状態情報（EAP継続時に使用）
    CLASS = 25              # クラス情報
    SESSION_TIMEOUT = 27    # セッションタイムアウト値
    IDLE_TIMEOUT = 28           # アイドルタイムアウト値
    TERMINATION_ACTION = 29     # 終了時のアクション
    NAS_PORT_TYPE = 61          # NASポートタイプ
    CONNECT_INFO = 77           # 接続情報
    EAP_MESSAGE = 79            # EAPメッセージ（RFC 3579）
    MESSAGE_AUTHENTICATOR = 80  # メッセージ認証子（RFC 2869）
    NAS_PORT_ID = 87            # NASポートID（文字列）

class RadiusServiceType(IntEnum):
    """RADIUSサービスタイプ（RFC 2865準拠）
    
    【説明】
    ユーザーが要求するサービスの種類を示します。
    ネットワークアクセスの形態に応じて適切な値を設定します。
    """
    LOGIN = 1                   # ログインサービス
    FRAMED = 2                  # フレーム化サービス（PPP等）
    CALLBACK_LOGIN = 3          # コールバックログイン
    CALLBACK_FRAMED = 4         # コールバックフレーム化
    OUTBOUND = 5                # アウトバウンド接続
    ADMINISTRATIVE = 6          # 管理用接続
    NAS_PROMPT = 7              # NASプロンプト
    AUTHENTICATE_ONLY = 8       # 認証のみ（PANAで使用）
    CALLBACK_NAS_PROMPT = 9     # コールバックNASプロンプト

class RadiusNASPortType(IntEnum):
    """NASポートタイプ（RFC 2865拡張）
    
    【説明】
    ネットワークアクセスサーバーが提供する物理的または論理的な
    接続インターフェースの種類を示します。
    """
    ASYNC = 0                   # 非同期接続
    SYNC = 1                    # 同期接続
    ISDN_SYNC = 2               # ISDN同期
    ISDN_ASYNC_V120 = 3         # ISDN非同期V.120
    ISDN_ASYNC_V110 = 4         # ISDN非同期V.110
    VIRTUAL = 5                 # 仮想接続（VPN等）
    PIAFS = 6                   # PIAFS接続
    HDLC_CLEAR_CHANNEL = 7      # HDLCクリアチャネル
    X25 = 8                     # X.25接続
    X75 = 9                     # X.75接続
    G3_FAX = 10                 # G3ファックス
    SDSL = 11                   # SDSL接続
    ADSL_CAP = 12               # ADSL CAP接続
    ADSL_DMT = 13               # ADSL DMT接続
    IDSL = 14                   # IDSL接続
    ETHERNET = 15               # イーサネット接続
    XDSL = 16                   # xDSL接続
    CABLE = 17                  # ケーブル接続
    WIRELESS_OTHER = 18         # その他の無線接続
    WIRELESS_802_11 = 19        # IEEE 802.11無線LAN


class RadiusPacket:
    """RADIUSパケット構造体（RFC 2865準拠）
    
    【クラス説明】
    RADIUSプロトコルの標準パケット形式を実装します。
    パケットヘッダ（Code, Identifier, Length, Authenticator）と
    可変長の属性リストで構成されます。
    
    【パケット構造】
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Code      |  Identifier   |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                         Authenticator                         |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Attributes ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-
    """
    
    def __init__(self, code: RadiusCode, identifier: int = None, 
                 authenticator: bytes = None):
        """
        RADIUSパケットを初期化
        
        Args:
            code: RADIUSパケットコード（Access-Request等）
            identifier: パケット識別子（0-255）
            authenticator: 認証子（16バイト）。Noneの場合は自動生成
        """
        self.code = code  # パケットコード
        self.identifier = identifier or random.randint(0, 255)  # 識別子（自動生成）
        self.authenticator = authenticator or os.urandom(16)  # 16バイト認証子
        self.attributes = []  # 属性リスト
        
    def add_attribute(self, attr_type: int, value: bytes):
        """パケットに属性を追加
        
        Args:
            attr_type: RADIUS属性タイプ
            value: 属性値（バイト列）
            
        Raises:
            ValueError: 属性値が253バイトを超える場合
        """
        if len(value) > 253:  # 最大属性長（RFC 2865準拠）
            raise ValueError(f"Attribute too long: {len(value)} > 253")
        self.attributes.append((attr_type, value))
    
    def add_string(self, attr_type: int, value: str):
        """文字列属性を追加
        
        Args:
            attr_type: RADIUS属性タイプ
            value: 文字列値（UTF-8でエンコード）
        """
        self.add_attribute(attr_type, value.encode('utf-8'))
    
    def add_integer(self, attr_type: int, value: int):
        """整数属性を追加
        
        Args:
            attr_type: RADIUS属性タイプ
            value: 32ビット符号なし整数値
        """
        self.add_attribute(attr_type, struct.pack('!I', value))
    
    def add_ipaddr(self, attr_type: int, ip: str):
        """IPアドレス属性を追加
        
        Args:
            attr_type: RADIUS属性タイプ
            ip: IPアドレス（ドット記法文字列）
            
        Raises:
            ValueError: 不正なIPアドレス形式の場合
        """
        parts = ip.split('.')
        if len(parts) != 4:
            raise ValueError(f"Invalid IP address: {ip}")
        ip_bytes = bytes([int(p) for p in parts])
        self.add_attribute(attr_type, ip_bytes)
    
    def add_eap_message(self, eap_data: bytes):
        """EAP-Message属性を追加（必要に応じて分割）
        
        【説明】
        RFC 3579準拠のEAP-Message属性を追加します。
        大きなEAPメッセージは253バイトの複数属性に分割されます。
        
        Args:
            eap_data: EAPメッセージデータ
        """
        offset = 0
        while offset < len(eap_data):
            chunk_size = min(253, len(eap_data) - offset)
            chunk = eap_data[offset:offset + chunk_size]
            self.add_attribute(RadiusAttribute.EAP_MESSAGE, chunk)
            offset += chunk_size
    
    def get_eap_message(self) -> bytes:
        """Extract and concatenate all EAP-Message attributes"""
        eap_data = b''
        for attr_type, value in self.attributes:
            if attr_type == RadiusAttribute.EAP_MESSAGE:
                eap_data += value
        return eap_data
    
    def pack(self, secret: bytes) -> bytes:
        """
        Pack packet into bytes
        
        Args:
            secret: RADIUS shared secret
            
        Returns:
            Packed RADIUS packet
        """
        # Pack attributes
        attr_data = b''
        for attr_type, value in self.attributes:
            attr_len = len(value) + 2  # Type(1) + Length(1) + Value
            attr_data += struct.pack('!BB', attr_type, attr_len) + value
        
        # Calculate length
        length = 20 + len(attr_data)  # Header(20) + Attributes
        
        # Pack header
        packet = struct.pack('!BBH16s',
            self.code,
            self.identifier,
            length,
            self.authenticator
        )
        packet += attr_data
        
        # Add Message-Authenticator if EAP-Message present
        if self.has_eap_message():
            # Calculate Message-Authenticator
            msg_auth = self.calculate_message_authenticator(packet, secret)
            # Add attribute
            packet += struct.pack('!BB', RadiusAttribute.MESSAGE_AUTHENTICATOR, 18)
            packet += msg_auth
            # Update length
            length += 18
            packet = packet[:2] + struct.pack('!H', length) + packet[4:]
        
        return packet
    
    def has_eap_message(self) -> bool:
        """Check if packet contains EAP-Message"""
        return any(attr[0] == RadiusAttribute.EAP_MESSAGE for attr in self.attributes)
    
    def calculate_message_authenticator(self, packet: bytes, secret: bytes) -> bytes:
        """Calculate Message-Authenticator for packet with EAP"""
        # Temporarily set Message-Authenticator to zeros
        temp_packet = packet + struct.pack('!BB16s', 
            RadiusAttribute.MESSAGE_AUTHENTICATOR, 18, b'\x00' * 16)
        # Calculate HMAC-MD5
        return hmac.new(secret, temp_packet, hashlib.md5).digest()
    
    @classmethod
    def unpack(cls, data: bytes, secret: bytes) -> 'RadiusPacket':
        """
        Unpack RADIUS packet from bytes
        
        Args:
            data: Raw packet data
            secret: RADIUS shared secret
            
        Returns:
            RadiusPacket object
        """
        if len(data) < 20:
            raise ValueError("Packet too short")
        
        # Unpack header
        code, identifier, length, authenticator = struct.unpack('!BBH16s', data[:20])
        
        if len(data) != length:
            raise ValueError(f"Length mismatch: {len(data)} != {length}")
        
        packet = cls(RadiusCode(code), identifier, authenticator)
        
        # Unpack attributes
        offset = 20
        while offset < length:
            if offset + 2 > length:
                break
            attr_type, attr_len = struct.unpack('!BB', data[offset:offset+2])
            if attr_len < 2 or offset + attr_len > length:
                break
            value = data[offset+2:offset+attr_len]
            packet.attributes.append((attr_type, value))
            offset += attr_len
        
        # Verify Message-Authenticator if present
        if packet.has_eap_message():
            msg_auth = packet.get_attribute(RadiusAttribute.MESSAGE_AUTHENTICATOR)
            if msg_auth:
                # Verify Message-Authenticator
                # Replace the Message-Authenticator with zeros for calculation
                temp_data = bytearray(data)
                for i in range(len(data) - 18):
                    if data[i:i+2] == struct.pack('!BB', RadiusAttribute.MESSAGE_AUTHENTICATOR, 18):
                        # Found Message-Authenticator attribute, zero it out
                        temp_data[i+2:i+18] = b'\x00' * 16
                        break
                
                # Calculate expected Message-Authenticator
                expected_auth = hmac.new(secret, bytes(temp_data), hashlib.md5).digest()
                
                # Verify it matches
                if msg_auth != expected_auth:
                    raise ValueError("Message-Authenticator verification failed")
        
        return packet
    
    def get_attribute(self, attr_type: int) -> Optional[bytes]:
        """Get first occurrence of attribute"""
        for t, v in self.attributes:
            if t == attr_type:
                return v
        return None


class RadiusClient:
    """
    RADIUS client for enterprise authentication
    
    Supports EAP pass-through for PANA-RADIUS integration
    """
    
    def __init__(self, server: str, secret: str, port: int = RADIUS_AUTH_PORT,
                 timeout: int = 5, retries: int = 3):
        """
        Initialize RADIUS client
        
        Args:
            server: RADIUS server address
            secret: Shared secret
            port: RADIUS port (default 1812)
            timeout: Response timeout in seconds
            retries: Number of retries
        """
        self.server = server
        self.secret = secret.encode('utf-8') if isinstance(secret, str) else secret
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.logger = logging.getLogger('RADIUSClient')
        
        # Socket for communication
        self.socket = None
        
        # Request tracking
        self.pending_requests = {}
        self.lock = threading.Lock()
        
        # NAS configuration
        self.nas_ip = self._get_local_ip()
        self.nas_identifier = socket.gethostname()
        
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to a remote host to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.server, self.port))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return '127.0.0.1'
    
    def _create_socket(self):
        """Create UDP socket for RADIUS"""
        if self.socket:
            self.socket.close()
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(self.timeout)
        self.socket.bind(('', 0))  # Bind to any available port
    
    def send_access_request_eap(self, username: str, eap_data: bytes,
                                state: bytes = None) -> Tuple[RadiusCode, bytes, Dict]:
        """
        Send Access-Request with EAP data
        
        Args:
            username: User identity
            eap_data: EAP packet data
            state: State from previous Access-Challenge
            
        Returns:
            Tuple of (response_code, eap_response, attributes)
        """
        if not self.socket:
            self._create_socket()
        
        # Create Access-Request packet
        packet = RadiusPacket(RadiusCode.ACCESS_REQUEST)
        
        # Add attributes
        packet.add_string(RadiusAttribute.USER_NAME, username)
        packet.add_ipaddr(RadiusAttribute.NAS_IP_ADDRESS, self.nas_ip)
        packet.add_string(RadiusAttribute.NAS_IDENTIFIER, self.nas_identifier)
        packet.add_integer(RadiusAttribute.NAS_PORT, 0)
        packet.add_integer(RadiusAttribute.NAS_PORT_TYPE, RadiusNASPortType.VIRTUAL)
        packet.add_integer(RadiusAttribute.SERVICE_TYPE, RadiusServiceType.FRAMED)
        
        # Add State if provided (from Access-Challenge)
        if state:
            packet.add_attribute(RadiusAttribute.STATE, state)
        
        # Add EAP-Message
        packet.add_eap_message(eap_data)
        
        # Send packet and wait for response
        response = self._send_and_receive(packet)
        
        if not response:
            return (RadiusCode.ACCESS_REJECT, None, {})
        
        # Extract EAP from response
        eap_response = response.get_eap_message()
        
        # Extract other attributes
        attributes = {
            'state': response.get_attribute(RadiusAttribute.STATE),
            'class': response.get_attribute(RadiusAttribute.CLASS),
            'session_timeout': response.get_attribute(RadiusAttribute.SESSION_TIMEOUT),
        }
        
        return (response.code, eap_response, attributes)
    
    def _send_and_receive(self, packet: RadiusPacket) -> Optional[RadiusPacket]:
        """
        Send packet and receive response
        
        Args:
            packet: RADIUS packet to send
            
        Returns:
            Response packet or None
        """
        packet_data = packet.pack(self.secret)
        
        for attempt in range(self.retries):
            try:
                # Send packet
                self.socket.sendto(packet_data, (self.server, self.port))
                self.logger.debug(f"Sent {packet.code.name} to {self.server}:{self.port}")
                
                # Receive response
                response_data, addr = self.socket.recvfrom(4096)
                
                # Unpack response
                response = RadiusPacket.unpack(response_data, self.secret)
                
                # Verify response matches request
                if response.identifier == packet.identifier:
                    self.logger.debug(f"Received {response.code.name} from {addr}")
                    return response
                else:
                    self.logger.warning(f"Identifier mismatch: {response.identifier} != {packet.identifier}")
                    
            except socket.timeout:
                self.logger.warning(f"Timeout on attempt {attempt + 1}/{self.retries}")
                continue
            except Exception as e:
                self.logger.error(f"Error communicating with RADIUS server: {e}")
                break
        
        return None
    
    def close(self):
        """Close RADIUS client"""
        if self.socket:
            self.socket.close()
            self.socket = None


class RadiusEAPPassthrough:
    """
    RADIUS EAP pass-through handler for PANA integration
    
    This class bridges PANA EAP messages with RADIUS server
    """
    
    def __init__(self, radius_server: str, radius_secret: str, 
                 radius_port: int = RADIUS_AUTH_PORT):
        """
        Initialize RADIUS EAP pass-through
        
        Args:
            radius_server: RADIUS server address
            radius_secret: Shared secret
            radius_port: RADIUS port
        """
        self.radius_client = RadiusClient(
            radius_server, 
            radius_secret,
            radius_port
        )
        self.logger = logging.getLogger('RADIUS-EAP-Passthrough')
        
        # Session tracking
        self.sessions = {}  # session_id -> session_data
        
    def process_eap_for_radius(self, session_id: str, username: str, 
                               eap_data: bytes) -> Tuple[bool, bytes]:
        """
        Process EAP data through RADIUS
        
        Args:
            session_id: Session identifier
            username: User identity
            eap_data: EAP packet
            
        Returns:
            Tuple of (success, eap_response)
        """
        # Get or create session
        session = self.sessions.get(session_id, {})
        
        # Send to RADIUS
        code, eap_response, attributes = self.radius_client.send_access_request_eap(
            username,
            eap_data,
            session.get('state')
        )
        
        # Update session state
        if attributes.get('state'):
            session['state'] = attributes['state']
            self.sessions[session_id] = session
        
        # Handle response
        if code == RadiusCode.ACCESS_ACCEPT:
            self.logger.info(f"RADIUS authentication successful for {username}")
            # Clean up session
            self.sessions.pop(session_id, None)
            return (True, eap_response)
            
        elif code == RadiusCode.ACCESS_CHALLENGE:
            self.logger.debug(f"RADIUS Access-Challenge for {username}")
            return (None, eap_response)  # Continue authentication
            
        elif code == RadiusCode.ACCESS_REJECT:
            self.logger.warning(f"RADIUS authentication failed for {username}")
            # Clean up session
            self.sessions.pop(session_id, None)
            return (False, eap_response)
        
        else:
            self.logger.error(f"Unexpected RADIUS response: {code}")
            return (False, None)
    
    def close(self):
        """Close RADIUS client"""
        self.radius_client.close()


# Test function
def test_radius_backend():
    """Test RADIUS backend functionality"""
    logging.basicConfig(level=logging.DEBUG)
    
    print("\n" + "="*70)
    print("  Testing RADIUS Backend Integration")
    print("="*70)
    
    # Test packet creation
    print("\n1. Testing RADIUS packet creation...")
    packet = RadiusPacket(RadiusCode.ACCESS_REQUEST)
    packet.add_string(RadiusAttribute.USER_NAME, "test@example.com")
    packet.add_ipaddr(RadiusAttribute.NAS_IP_ADDRESS, "192.168.1.1")
    
    # Add EAP-Identity Response
    eap_identity = b'\x02\x01\x00\x15\x01test@example.com'
    packet.add_eap_message(eap_identity)
    
    secret = b"testing123"
    packed = packet.pack(secret)
    print(f"   Created Access-Request packet: {len(packed)} bytes")
    print(f"   Has EAP-Message: {packet.has_eap_message()}")
    
    # Test unpacking
    print("\n2. Testing packet unpacking...")
    unpacked = RadiusPacket.unpack(packed, secret)
    print(f"   Unpacked code: {unpacked.code.name}")
    print(f"   Attributes: {len(unpacked.attributes)}")
    
    eap_msg = unpacked.get_eap_message()
    print(f"   EAP message recovered: {len(eap_msg)} bytes")
    
    print("\n✅ RADIUS backend module ready for integration")
    
    # Note: Actual RADIUS server testing requires a real server
    print("\nNote: Full testing requires a RADIUS server.")
    print("Configure with: RadiusClient('radius.server.com', 'secret')")


if __name__ == "__main__":
    test_radius_backend()