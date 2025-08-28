#!/usr/bin/env python3
"""
PANA Client (PaC) Implementation
RFC5191 compliant PANA Client

【概要】
このモジュールはPANA (Protocol for carrying Authentication for Network Access) の
クライアント側実装です。RFC5191およびRFC6786（暗号化拡張）に準拠しています。

【主な機能】
- PANA-Client-Initiation (PCI) メッセージの送信
- EAP-TLS認証の処理
- 暗号鍵の導出と管理
- メッセージの再送信管理
- セッションライフサイクル管理
- RFC6786準拠のAVP暗号化サポート
"""

import os
import socket
import struct
import threading
import time
import select
import logging
import secrets

from pana_constants import *
from pana_messages import PANAMessage, AVP, create_avp_uint32, extract_avp_uint32
from pana_crypto import CryptoContext
from pana_retransmission import RetransmissionManager
from eap_tls_factory import create_eap_tls_handler
from pana_error_recovery import ErrorRecovery, ErrorContext, ErrorType, RecoveryAction, create_error_context
from pana_client_encryption import ClientEncryptionHelper
from pana_encryption_policy import EncryptionPolicy
from pana_antireplay import AntiReplay
# RFC 5191 Section 5.1: PANA does not provide fragmentation - disabled
# from pana_fragmentation import MessageFragmenter
from pana_statistics import PANAStatistics
from pana_monitor import PANAMonitor


class PANAClient:
    """PANA Client (PaC) Implementation - RFC5191 Compliant with RFC6786 Encryption
    
    【クラス説明】
    PANAプロトコルのクライアント（PaC: PANA Client）を実装するメインクラス。
    ネットワークアクセス認証のためのステートマシンと通信処理を管理します。
    
    【状態遷移】
    INITIAL -> WAIT_PAN_OR_PAR -> WAIT_EAP_MSG -> OPEN
    各状態の詳細はRFC5191のセクション4.1を参照。
    """
    def __init__(self, server_addr, server_port=716, encryption_policy=None, prefer_sha2=False):
        """
        PANAクライアントの初期化
        
        引数:
            server_addr: PAAサーバーのIPアドレス
            server_port: PAAサーバーのポート番号（デフォルト: 716）
            encryption_policy: RFC6786暗号化ポリシー（オプション）
            prefer_sha2: SHA2アルゴリズム優先フラグ（v2.3.2新機能）
                        True: SHA2-256を優先（PRF_HMAC_SHA2_256, AUTH_HMAC_SHA2_256_128）
                              AUTH AVPは16バイト（128ビットに切り詰め）
                              より強力な暗号アルゴリズムでセキュリティ向上
                        False: SHA1を優先（デフォルト、OpenPANA互換）
                               PRF_HMAC_SHA1, AUTH_HMAC_SHA1_160
                               AUTH AVPは20バイト（160ビット）
                               RFC 5191必須アルゴリズムで最大互換性
        
        注意: PAAサーバーと同じprefer_sha2設定を使用する必要があります。
             異なる設定の場合、互換性のためSHA1が選択されます。
        """
        # サーバー接続情報の設定
        self.server_addr = server_addr
        self.server_port = server_port
        # SHA2アルゴリズム優先フラグ（v2.3.2で追加）
        # True: SHA2-256/AUTH_HMAC_SHA2_256_128を優先（より安全）
        # False: SHA1/AUTH_HMAC_SHA1_160を優先（デフォルト、OpenPANA互換）  
        self.prefer_sha2 = prefer_sha2
        
        # ロギング設定（早期に設定）
        self.logger = logging.getLogger('PANA-Client')
        
        # 適切なローカルIPアドレスを決定
        local_ip = self._determine_local_ip()
        
        # UDPソケットの作成と任意のポートへのバインド
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((local_ip, 0))  # 適切なローカルIPにバインド
        local_addr, local_port = self.socket.getsockname()
        
        self.logger.info(f"Client socket bound to {local_addr}:{local_port}")
        
        # セッション管理変数の初期化
        self.session_id = 0  # RFC 5191 Section 7.1: Must be 0 in PCI, PAA will assign actual session ID
        # RFC 5191 Section 5.2: Random initial sequence number (except PCI which must be 0)
        self.seq_number = 0  # Will be set to random after PCI
        self.seq_number_initialized = False  # Track if we've set random ISN
        
        # 各種ハンドラとマネージャーの初期化
        self.crypto_ctx = CryptoContext()  # 暗号化コンテキスト
        self.eap_handler = create_eap_tls_handler(is_server=False)  # EAP-TLSハンドラ（クライアントモード）
        self.retransmit_mgr = RetransmissionManager(self.socket)  # 再送信管理
        
        # 実行状態とセッション管理
        self.running = True  # 実行フラグ
        self.session_lifetime = DEFAULT_SESSION_LIFETIME  # セッション有効期間（デフォルト3600秒）
        self.session_start_time = None  # セッション開始時刻
        self.state = PAC_STATE_INITIAL  # 初期状態（RFC5191ステートマシン）
        
        # RFC 6786 暗号化サポートの初期化
        self.encryption_helper = ClientEncryptionHelper(encryption_policy)
        
        # リプレイ攻撃対策の初期化
        self.anti_replay = AntiReplay(window_size=32)
        
        # エラーリカバリマネージャー
        self.error_recovery = ErrorRecovery(
            retransmit_manager=self.retransmit_mgr
        )
        
        # フラグメンテーションサポート
        # RFC 5191 Section 5.1: PANA does not provide fragmentation
        # self.fragmenter = MessageFragmenter()
        
        # 統計情報収集の初期化
        self.statistics = PANAStatistics()
        self.monitor = PANAMonitor(self.statistics)
        self.monitor.start()
        
        # このセッションの統計オブジェクト
        self.session_stats = None
        
        # IPアドレス変更検出用
        self.current_ip = None
        self.ip_monitor_thread = None
        
    def generate_nonce(self):
        """
        ランダムなnonceを生成
        
        【説明】
        暗号化処理で使用する16バイトのランダム値（nonce）を生成します。
        nonceは暗号鍵導出時のエントロピー源として使用されます。
        
        戻り値:
            16バイトのランダムバイト列
        """
        return self.crypto_ctx.generate_nonce()
    
    def _prepare_and_send_message(self, msg):
        """
        メッセージの準備（暗号化含む）と送信
        
        【説明】
        PANAメッセージに必要な暗号化処理とAUTH AVPの追加を行い、
        ネットワークに送信します。送信したメッセージは再送信キューにも追加されます。
        大きなメッセージは自動的にフラグメント化されます。
        
        引数:
            msg: 送信するPANAMessageオブジェクト
        
        処理フロー:
            1. RFC 6786暗号化が有効な場合、メッセージを暗号化
            2. AUTH AVPが必要かつ未追加の場合、HMAC認証タグを計算して追加
            3. メッセージサイズをチェックし、必要に応じてフラグメント化
            4. メッセージをパック（バイト列化）して送信
            5. 再送信管理キューに追加
        """
        # RFC 6786: 暗号化が有効な場合、機密性の高いAVPを暗号化
        if self.encryption_helper.encryption_context.is_encryption_active():
            self.encryption_helper.prepare_message_with_encryption(msg, self.crypto_ctx)
        
        # RFC 5191: 鍵が利用可能な場合は常にAUTH AVPを追加
        if self.crypto_ctx.pana_auth_key and not msg.get_avp(AVP_AUTH):
            msg_without_auth = msg.pack()  # AUTH AVPなしでメッセージをパック
            auth_value = self.crypto_ctx.compute_auth(msg_without_auth)  # HMAC-SHA256で認証タグ計算
            msg.add_avp(AVP(AVP_AUTH, 0, auth_value))  # AUTH AVPを追加
        
        # RFC 5191 Section 5.1: PANA does not provide fragmentation
        # Send message directly without fragmentation
        message_data = msg.pack()  # 最終的なバイト列に変換
        self.socket.sendto(message_data, (self.server_addr, self.server_port))  # UDP送信
        
        # 統計情報: パケット送信
        self.statistics.record_packet(self.session_id, 'sent', len(message_data), msg.msg_type)
        
        # 再送信キューに追加
        self.retransmit_mgr.add_message(self.seq_number, message_data, (self.server_addr, self.server_port))
                
        self.seq_number += 1  # シーケンス番号をインクリメント
    
    def send_pci(self):
        """
        PANA-Client-Initiation (PCI) メッセージの送信
        
        【説明】
        PANA認証セッションを開始するための最初のメッセージを送信します。
        このメッセージには、クライアントがサポートする暗号化アルゴリズムと
        ランダムなnonce値が含まれます。
        
        【RFC5191準拠】
        - メッセージタイプ: PANA_CLIENT_INITIATION (1)
        - フラグ: REQUEST (R) | START (S)
        - 必須AVP: PRF-Algorithm, Integrity-Algorithm, Nonce
        - オプションAVP: Encryption-Algorithm (RFC6786)
        
        【前提条件】
        - 状態がINITIAL状態であること
        """
        # 状態チェック：INITIAL状態でない場合はエラー
        if self.state != PAC_STATE_INITIAL:
            self.logger.error(f"Invalid state for PCI: {self.state}")
            return
        
        # Additional safety check: don't send PCI if already authenticated
        if self.state == PAC_STATE_OPEN:
            self.logger.warning("Already authenticated, skipping PCI")
            return
        
        # Resume retransmission manager if it was paused
        if hasattr(self.retransmit_mgr, 'resume'):
            self.retransmit_mgr.resume()
            self.logger.debug("Resumed retransmission manager for new authentication")
            
        # PCIメッセージの作成
        msg = PANAMessage()
        msg.flags = 0  # RFC 5191 Section 7.1: PCI has no flags set (not R or S)
        # メッセージヘッダの設定
        msg.msg_type = PANA_CLIENT_INITIATION  # メッセージタイプをPCIに設定
        msg.session_id = 0  # RFC 5191 Section 7.1: Must be 0 in PCI
        msg.seq_number = 0  # RFC 5191 Section 7.1: Must be 0 in PCI
        
        # RFC5191準拠: PCIは最小限のメッセージ（ヘッダーのみ）
        # OpenPANA互換性のため、PCIにはAVPを含めない
        # Nonceは最初のPANメッセージで送信する
        
        # RFC6786: 暗号化も同様にクライアントは提案せず、サーバーの候補を待つ
        
        # メッセージの送信
        message_data = msg.pack()  # バイト列に変換
        self.socket.sendto(message_data, (self.server_addr, self.server_port))  # UDP送信
        self.retransmit_mgr.add_message(self.seq_number, message_data, (self.server_addr, self.server_port))  # 再送信キューに追加
        self.seq_number += 1  # シーケンス番号をインクリメント
        
        # 状態遷移：INITIAL -> WAIT_PAN_OR_PAR
        self.state = PAC_STATE_WAIT_PAN_OR_PAR
        self.logger.info(f"State transition: {PAC_STATE_INITIAL} -> {PAC_STATE_WAIT_PAN_OR_PAR}")
        
        # 統計情報: セッション開始
        self.session_stats = self.statistics.start_session(self.session_id)
        self.session_stats.start_authentication()
        
    def handle_auth_msg(self, msg):
        """
        PANA-Authメッセージの処理
        
        【説明】
        PAAから受信したPANA-Auth-Request (PAR) またはPANA-Auth-Answer (PAN) を処理します。
        メッセージの内容に応じて、EAP認証の進行、認証結果の確認、
        暗号鍵の導出などを行います。
        
        引数:
            msg: 受信したPANAMessageオブジェクト
        
        【主な処理フロー】
        1. RFC 6786暗号化されたAVPの復号
        2. 状態の検証
        3. 再送信キューからの削除（応答メッセージの場合）
        4. AVPの抽出と処理
        5. EAPペイロードの処理
        6. 認証結果の確認と鍵導出
        """
        self.logger.info(f"handle_auth_msg: Received {'request' if msg.is_request() else 'answer'} in state {self.state}")
        
        # RFC 6786: 暗号化されたAVPの処理
        # 暗号化が有効な場合、Encryption-Encap AVPを探して復号
        if self.encryption_helper.encryption_context.is_encryption_active():
            decrypted_avps = self.encryption_helper.process_encrypted_message(msg, self.crypto_ctx)
            # 復号されたAVPをメッセージに追加して処理を継続
            for avp in decrypted_avps:
                msg.avps.append(avp)
        
        # 状態の検証：許可された状態でない場合はエラー
        if self.state not in [PAC_STATE_WAIT_PAN_OR_PAR, PAC_STATE_WAIT_EAP_MSG, 
                             PAC_STATE_WAIT_EAP_RESULT, PAC_STATE_OPEN]:
            self.logger.error(f"Received AUTH message in invalid state: {self.state}")
            return
            
        # 応答メッセージの場合、対応する要求を再送信キューから削除
        if not msg.is_request() and self.seq_number > 0:
            self.retransmit_mgr.remove_message(self.seq_number - 1)
        
        # RFC 6786: Check encryption policy if encryption is active
        encrypted_avp_codes = []
        if self.encryption_helper.encryption_context and self.encryption_helper.encryption_context.is_encryption_active():
            # Check if there's an Encryption-Encap AVP
            encap_avp = msg.get_avp(AVP_ENCRYPTION_ENCAP)
            if encap_avp:
                encrypted_avp_codes = [AVP_ENCRYPTION_ENCAP]
                # Decrypt and get the AVP codes that were encrypted
                decrypted_avps = msg.decrypt_avps(self.crypto_ctx)
                for avp in decrypted_avps:
                    encrypted_avp_codes.append(avp.code)
                    msg.avps.append(avp)
            
            # Validate encryption policy
            if self.encryption_helper.encryption_policy:
                valid, errors = self.encryption_helper.encryption_policy.validate_encryption_policy(
                    msg.avps, encrypted_avp_codes
                )
                if not valid:
                    self.logger.error(f"Encryption policy violation: {errors}")
                    # RFC 6786: Silently discard messages violating policy
                    return
            
        # RFC5191: AUTH AVP is mandatory after key establishment (except for PCI and initial exchanges)
        # Don't enforce on initial exchanges (S-bit set) as keys aren't established yet
        if (self.crypto_ctx.pana_auth_key and 
            msg.msg_type != PANA_CLIENT_INITIATION and
            not (msg.flags & FLAG_START)):  # Don't enforce on S-bit messages
            auth_avp = msg.get_avp(AVP_AUTH)
            if not auth_avp:
                self.logger.warning(f"Missing mandatory AUTH AVP after key establishment")
                return  # Silently discard message
            
        # AVPの抽出と解析
        # 受信メッセージから必要な情報を抽出
        eap_payload = None      # EAPペイロード（認証データ）
        nonce_paa = None        # PAAからのnonce値
        session_lifetime = None # セッション有効期間（秒）
        result_code = None      # 認証結果コード
        auth_avp = None         # 認証タグ（HMAC）
        key_id = None           # 鍵ID
        prf_algorithms = []     # PRFアルゴリズム候補
        integrity_algorithms = []  # 完全性アルゴリズム候補
        
        self.logger.info(f"Message has {len(msg.avps)} AVPs")
        for avp in msg.avps:
            self.logger.info(f"AVP: code={avp.code}, length={len(avp.value)}")
            if avp.code == AVP_EAP_PAYLOAD:
                eap_payload = avp.value  # EAPメッセージを抽出
            elif avp.code == AVP_NONCE:
                nonce_paa = avp.value    # PAAのnonceを保存
            elif avp.code == AVP_SESSION_LIFETIME:
                session_lifetime = extract_avp_uint32(avp)  # 32ビット整数として解析
            elif avp.code == AVP_RESULT_CODE:
                result_code = extract_avp_uint32(avp)  # 結果コードを解析
            elif avp.code == AVP_AUTH:
                auth_avp = avp.value     # HMAC値を保存
            elif avp.code == AVP_KEY_ID:
                key_id = avp.value       # 鍵IDを保存
            elif avp.code == AVP_PRF_ALGORITHM:
                prf_algorithms.append(extract_avp_uint32(avp))  # PRFアルゴリズム候補
            elif avp.code == AVP_INTEGRITY_ALGORITHM:
                integrity_algorithms.append(extract_avp_uint32(avp))  # 完全性アルゴリズム候補
                
        # Store PAA nonce if this is first auth request
        if nonce_paa and not self.crypto_ctx.nonce_paa:
            self.crypto_ctx.nonce_paa = nonce_paa
            
        # 初期PAR受信時：PAAから提示されたアルゴリズム候補から選択
        if msg.is_request() and (msg.flags & FLAG_START):
            # Store I_PAR for key derivation (RFC 5191 Section 5.3)
            self.crypto_ctx.i_par = msg.pack()
            self.logger.debug(f"Stored I_PAR ({len(self.crypto_ctx.i_par)} bytes) for key derivation")
            
            # RFC 5191 Section 4.1: PAA assigns session ID in initial PAR
            if self.session_id == 0 and msg.session_id != 0:
                self.session_id = msg.session_id
                self.logger.info(f"Session ID assigned by PAA: 0x{self.session_id:08x}")
                
                # Remove PCI (seq=0) from retransmission queue since PAA responded
                self.retransmit_mgr.remove_message(0)
                self.logger.debug("Removed PCI from retransmission queue")
            
            # RFC 5191 Section 5.2: Initialize random sequence number after PCI
            if not self.seq_number_initialized:
                self.seq_number = secrets.randbelow(2**32)
                self.seq_number_initialized = True
                self.logger.info(f"Initialized random sequence number: {self.seq_number}")
            # 最適なアルゴリズムを選択
            # prefer_sha2フラグに基づいてPRFアルゴリズムを選択
            if prf_algorithms:
                if self.prefer_sha2:
                    # SHA2を優先（v2.3.2: より安全だがOpenPANAと互換性なし）
                    # PRF_HMAC_SHA2_256 (ID:5) > PRF_HMAC_SHA1 (ID:2)
                    if PRF_HMAC_SHA2_256 in prf_algorithms:
                        self.selected_prf = PRF_HMAC_SHA2_256
                        self.crypto_ctx.prf_algorithm = PRF_HMAC_SHA2_256
                    elif PRF_HMAC_SHA1 in prf_algorithms:
                        self.selected_prf = PRF_HMAC_SHA1
                        self.crypto_ctx.prf_algorithm = PRF_HMAC_SHA1
                    else:
                        self.selected_prf = prf_algorithms[0]  # 最初の候補を選択
                        self.crypto_ctx.prf_algorithm = prf_algorithms[0]
                else:
                    # SHA1を優先（デフォルト: RFC 5191 mandatory, OpenPANA互換）  
                    # PRF_HMAC_SHA1 (ID:2) > PRF_HMAC_SHA2_256 (ID:5)
                    if PRF_HMAC_SHA1 in prf_algorithms:
                        self.selected_prf = PRF_HMAC_SHA1
                        self.crypto_ctx.prf_algorithm = PRF_HMAC_SHA1
                    elif PRF_HMAC_SHA2_256 in prf_algorithms:
                        self.selected_prf = PRF_HMAC_SHA2_256
                        self.crypto_ctx.prf_algorithm = PRF_HMAC_SHA2_256
                    else:
                        self.selected_prf = prf_algorithms[0]  # 最初の候補を選択
                        self.crypto_ctx.prf_algorithm = prf_algorithms[0]
                # 選択結果をログ出力（prefer_sha2設定も表示）
                self.logger.info(f"Selected PRF algorithm: {self.selected_prf} (prefer_sha2={self.prefer_sha2})")
                
            # Integrityアルゴリズムの選択（AUTH AVP計算用）
            if integrity_algorithms:
                if self.prefer_sha2:
                    # SHA2を優先（v2.3.2: AUTH AVP 16バイト、より安全）
                    # AUTH_HMAC_SHA2_256_128 (ID:12) > AUTH_HMAC_SHA1_160 (ID:7)
                    if AUTH_HMAC_SHA2_256_128 in integrity_algorithms:
                        self.selected_integrity = AUTH_HMAC_SHA2_256_128
                        self.crypto_ctx.auth_algorithm = AUTH_HMAC_SHA2_256_128
                    elif AUTH_HMAC_SHA1_160 in integrity_algorithms:
                        self.selected_integrity = AUTH_HMAC_SHA1_160
                        self.crypto_ctx.auth_algorithm = AUTH_HMAC_SHA1_160
                    else:
                        self.selected_integrity = integrity_algorithms[0]  # 最初の候補を選択
                        self.crypto_ctx.auth_algorithm = integrity_algorithms[0]
                else:
                    # SHA1を優先（デフォルト: AUTH AVP 20バイト、OpenPANA互換）
                    # AUTH_HMAC_SHA1_160 (ID:7) > AUTH_HMAC_SHA2_256_128 (ID:12)
                    if AUTH_HMAC_SHA1_160 in integrity_algorithms:
                        self.selected_integrity = AUTH_HMAC_SHA1_160
                        self.crypto_ctx.auth_algorithm = AUTH_HMAC_SHA1_160
                    elif AUTH_HMAC_SHA2_256_128 in integrity_algorithms:
                        self.selected_integrity = AUTH_HMAC_SHA2_256_128
                        self.crypto_ctx.auth_algorithm = AUTH_HMAC_SHA2_256_128
                    else:
                        self.selected_integrity = integrity_algorithms[0]  # 最初の候補を選択
                        self.crypto_ctx.auth_algorithm = integrity_algorithms[0]
                # 選択結果をログ出力（AUTH AVPサイズも影響）
                auth_avp_size = 16 if self.selected_integrity == AUTH_HMAC_SHA2_256_128 else 20
                self.logger.info(f"Selected integrity algorithm: {self.selected_integrity} "
                               f"(prefer_sha2={self.prefer_sha2}, AUTH AVP: {auth_avp_size} bytes)")
            
        # Update session lifetime if provided
        if session_lifetime:
            self.session_lifetime = session_lifetime
            self.logger.info(f"Session lifetime set to {session_lifetime} seconds")
            
        # Store Key-ID if present
        if key_id:
            self.crypto_ctx.key_id = key_id
            
        # Pass session_id to crypto context for key derivation
        self.crypto_ctx.session_id = msg.session_id
        
        # Debug log extracted AVPs
        self.logger.info(f"Extracted AVPs: eap_payload={'present' if eap_payload else 'none'}, "
                         f"nonce_paa={'present' if nonce_paa else 'none'}, "
                         f"session_lifetime={session_lifetime}, result_code={result_code}")
        
        # RFC 6786: Handle server's encryption algorithm
        if msg.is_request():  # Only process algorithm from requests
            self.encryption_helper.handle_server_algorithm(msg)
            
        # Verify AUTH AVP if present and we have keys
        if auth_avp and self.crypto_ctx.pana_auth_key:
            # Reconstruct message without AUTH AVP for verification
            msg_copy = PANAMessage()
            msg_copy.reserved = msg.reserved
            msg_copy.flags = msg.flags
            msg_copy.msg_type = msg.msg_type
            msg_copy.session_id = msg.session_id
            msg_copy.seq_number = msg.seq_number
            
            for avp in msg.avps:
                if avp.code != AVP_AUTH:
                    msg_copy.add_avp(avp)
                    
            if not self.crypto_ctx.verify_auth(msg_copy.pack(), auth_avp):
                self.logger.error("AUTH AVP verification failed")
                return
                
        # Handle based on message flags and content
        if msg.flags & FLAG_COMPLETE:
            # This is the final auth message with result
            if result_code == RESULT_CODE_SUCCESS:
                self.logger.info("PANA authentication successful")
                self.session_start_time = time.time()
                prev_state = self.state
                self.state = PAC_STATE_OPEN
                self.logger.info(f"State transition: {prev_state} -> {PAC_STATE_OPEN}")
                
                # Clear all pending retransmissions after successful authentication
                self.retransmit_mgr.clear_messages_for_address((self.server_addr, self.server_port))
                self.logger.debug("Cleared all pending retransmissions after authentication")
                
                # Pause retransmission manager to reduce CPU usage during idle authenticated state
                if hasattr(self.retransmit_mgr, 'pause'):
                    self.retransmit_mgr.pause()
                    self.logger.debug("Paused retransmission manager after authentication")
                
                # 統計情報: 認証成功
                self.statistics.record_auth_result(self.session_id, 'success')
                
                # IPアドレス監視を開始
                self.current_ip = self._get_current_ip()
                if self.current_ip:
                    self.ip_monitor_thread = threading.Thread(target=self._monitor_ip_change)
                    self.ip_monitor_thread.daemon = True
                    self.ip_monitor_thread.start()
                    self.logger.info(f"IP address monitoring started. Current IP: {self.current_ip}")
                
                # Process EAP-Success message if present to get MSK
                if eap_payload and len(eap_payload) >= 4:
                    # Process the EAP message (which should be EAP-Success)
                    self.eap_handler.process_eap_message(eap_payload)
                    
                    # Now derive keys from EAP MSK
                    msk = self.eap_handler.get_msk()
                    emsk = self.eap_handler.get_emsk()
                    if msk:
                        self.crypto_ctx.session_id = msg.session_id
                        self.crypto_ctx.derive_keys(msk, emsk)
                        self.logger.info("Derived PANA keys from EAP MSK")
                
                # Send final answer if this was a request
                if msg.is_request():
                    self.logger.info("Sending final PANA-Auth-Answer")
                    answer = PANAMessage()
                    answer.flags = FLAG_COMPLETE  # RFC 5191: No A-flag here, it's only for re-auth PNR/PNA
                    answer.msg_type = PANA_AUTH
                    answer.session_id = msg.session_id
                    answer.seq_number = msg.seq_number  # RFC 5191 Section 5.2: Answer uses request's seq number
                    
                    # Add Key-ID AVP if present
                    if key_id:
                        answer.add_avp(AVP(AVP_KEY_ID, 0, key_id))
                    
                    # Add AUTH AVP
                    msg_without_auth = answer.pack()
                    auth_value = self.crypto_ctx.compute_auth(msg_without_auth)
                    answer.add_avp(AVP(AVP_AUTH, 0, auth_value))
                    
                    message_data = answer.pack()
                    self.logger.info(f"Sending final answer: seq={self.seq_number}, size={len(message_data)}")
                    self.socket.sendto(message_data, (self.server_addr, self.server_port))
                    self.seq_number += 1
                else:
                    self.logger.info("Final message was not a request, not sending answer")
                    
                # Start session lifetime monitoring
                self._start_session_monitoring()
            else:
                self.logger.error(f"Authentication failed with result code: {result_code}")
                
        elif eap_payload:
            self.logger.debug(f"Processing EAP payload of {len(eap_payload)} bytes")
            
            # Update state for EAP processing
            if self.state == PAC_STATE_WAIT_PAN_OR_PAR:
                self.state = PAC_STATE_WAIT_EAP_MSG
                self.logger.info(f"State transition: {PAC_STATE_WAIT_PAN_OR_PAR} -> {PAC_STATE_WAIT_EAP_MSG}")
            
            # Process EAP message
            eap_response = self.eap_handler.process_eap_message(eap_payload)
            self.logger.debug(f"EAP response: {eap_response.hex() if eap_response else 'None'}")
            
            if eap_response:
                # Send PANA-Auth with EAP response
                answer = PANAMessage()
                # Set S-bit if this is response to initial PAR with S-bit
                if msg.flags & FLAG_START:
                    answer.flags = FLAG_START  # Answer with S-bit
                else:
                    answer.flags = 0  # Answer, no special flags
                answer.msg_type = PANA_AUTH
                answer.session_id = msg.session_id
                answer.seq_number = msg.seq_number  # RFC 5191 Section 5.2: Answer uses request's seq number
                
                # Add EAP payload
                answer.add_avp(AVP(AVP_EAP_PAYLOAD, 0, eap_response))
                
                # RFC 5191: Add client nonce to first non-initial PAN (no S-bit)
                # This happens after initial exchange when we have PAA nonce
                if not (msg.flags & FLAG_START) and self.crypto_ctx.nonce_paa and not hasattr(self, '_sent_client_nonce'):
                    answer.add_avp(AVP(AVP_NONCE, 0, self.crypto_ctx.nonce_pac))
                    self._sent_client_nonce = True
                    self.logger.debug(f"Added client nonce to first non-initial PAN: {self.crypto_ctx.nonce_pac.hex()}")
                
                # 初期PANの場合、Nonceと選択したアルゴリズムを送信
                if msg.flags & FLAG_START:
                    # RFC 5191 Section 4.1: Nonce MUST NOT be in initial messages with S-bit
                    # Nonce will be sent in first non-initial PAN after receiving PAA nonce
                    # Generate nonce now but don't send it yet
                    if not self.crypto_ctx.nonce_pac:
                        self.crypto_ctx.nonce_pac = self.generate_nonce()
                        self.logger.debug(f"Generated client nonce for later use: {self.crypto_ctx.nonce_pac.hex()}")
                
                # 選択したアルゴリズムを送信
                if hasattr(self, 'selected_prf'):
                    answer.add_avp(create_avp_uint32(AVP_PRF_ALGORITHM, self.selected_prf))
                if hasattr(self, 'selected_integrity'):
                    answer.add_avp(create_avp_uint32(AVP_INTEGRITY_ALGORITHM, self.selected_integrity))
                
                # Don't derive keys here - wait for FLAG_COMPLETE with key_id from PAA
                
                message_data = answer.pack()
                
                # Store I_PAN if this is initial PAN with S-bit (RFC 5191 Section 5.3)
                if answer.flags & FLAG_START and not self.crypto_ctx.i_pan:
                    self.crypto_ctx.i_pan = message_data
                    self.logger.debug(f"Stored I_PAN ({len(self.crypto_ctx.i_pan)} bytes) for key derivation")
                
                self.logger.debug(f"Sending PAN with seq_number {self.seq_number}, flags {answer.flags:04x}, {len(message_data)} bytes")
                self.socket.sendto(message_data, (self.server_addr, self.server_port))
                if answer.is_request():
                    self.retransmit_mgr.add_message(self.seq_number, message_data, (self.server_addr, self.server_port))
                self.seq_number += 1
            else:
                self.logger.warning("No EAP response generated")
        elif msg.is_request() and (msg.flags & FLAG_START):
            # RFC 5191: Respond to initial PAR with S-bit even without EAP
            self.logger.info("Received initial PAR with S-bit (no EAP) - sending initial PAN with S-bit")
            
            # Send initial PAN with S-bit and selected algorithms
            answer = PANAMessage()
            answer.flags = FLAG_START  # Answer with S-bit
            answer.msg_type = PANA_AUTH
            answer.session_id = msg.session_id
            answer.seq_number = msg.seq_number  # RFC 5191 Section 5.2: Answer uses request's seq number
            
            # Generate client nonce now but don't send it yet (RFC 5191)
            if not self.crypto_ctx.nonce_pac:
                self.crypto_ctx.nonce_pac = self.generate_nonce()
                self.logger.debug(f"Generated client nonce for later use: {self.crypto_ctx.nonce_pac.hex()}")
            
            # Add selected algorithms
            if hasattr(self, 'selected_prf'):
                answer.add_avp(create_avp_uint32(AVP_PRF_ALGORITHM, self.selected_prf))
            if hasattr(self, 'selected_integrity'):
                answer.add_avp(create_avp_uint32(AVP_INTEGRITY_ALGORITHM, self.selected_integrity))
            
            # Store I_PAN if this is initial PAN with S-bit (RFC 5191 Section 5.3)
            message_data = answer.pack()
            if not self.crypto_ctx.i_pan:
                self.crypto_ctx.i_pan = message_data
                self.logger.debug(f"Stored I_PAN ({len(self.crypto_ctx.i_pan)} bytes) for key derivation")
            
            # Send the initial PAN
            self.logger.debug(f"Sending initial PAN with S-bit, seq={answer.seq_number}")
            self.socket.sendto(message_data, (self.server_addr, self.server_port))
            self.seq_number += 1
        else:
            self.logger.info("No action required for this message")
                
    def _start_session_monitoring(self):
        """
        セッション有効期限の監視を開始
        
        【説明】
        セッションの有効期限をバックグラウンドスレッドで監視し、
        期限切れが近づいたら再認証を要求し、期限切れの場合は
        セッション終了を送信します。
        
        【監視ロジック】
        - 残り時間が0以下: セッション終了
        - 残り時間が5分以下: 再認証要求
        - それ以外: 1分ごとにチェック
        """
        def monitor_session():
            while self.running and self.session_start_time:
                elapsed = time.time() - self.session_start_time
                remaining = self.session_lifetime - elapsed
                
                if remaining <= 0:
                    self.logger.info("Session expired, sending termination request")
                    self.send_termination_request()
                    break
                elif remaining <= 300:  # 5 minutes before expiry
                    self.logger.info(f"Session expiring in {remaining} seconds, requesting re-authentication")
                    self.send_reauth_request()
                    break
                    
                time.sleep(60)  # Check every minute
                
        monitor_thread = threading.Thread(target=monitor_session)
        monitor_thread.daemon = True
        monitor_thread.start()
        
    def send_ping_request(self):
        """
        Pingメッセージ（Keep-Alive）の送信
        
        【説明】
        PANA-Notification-RequestメッセージにPingフラグを設定して送信します。
        これにより、セッションがアクティブであることをPAAに通知し、
        ネットワークの接続性を確認します。
        
        【RFC5191準拠】
        - メッセージタイプ: PANA_NOTIFICATION (4)
        - フラグ: REQUEST (R) | PING (P)
        - AUTH AVPを含む（鍵が利用可能な場合）
        """
        msg = PANAMessage()
        msg.flags = FLAG_REQUEST | FLAG_PING
        msg.msg_type = PANA_NOTIFICATION
        msg.session_id = self.session_id
        msg.seq_number = self.seq_number
        
        # Add AUTH AVP if keys available
        if self.crypto_ctx.pana_auth_key:
            # RFC 5191: No A-flag needed when adding AUTH AVP
            msg_without_auth = msg.pack()
            auth_value = self.crypto_ctx.compute_auth(msg_without_auth)
            msg.add_avp(AVP(AVP_AUTH, 0, auth_value))
        
        message_data = msg.pack()
        self.socket.sendto(message_data, (self.server_addr, self.server_port))
        self.retransmit_mgr.add_message(self.seq_number, message_data, (self.server_addr, self.server_port))
        self.seq_number += 1
    
    def send_reauth_request(self):
        """Send re-authentication request using PANA-Notification with 'A' flag (RFC 5191 Section 4.3)"""
        msg = PANAMessage()
        msg.flags = FLAG_REQUEST | FLAG_REAUTH  # Set R and A flags
        msg.msg_type = PANA_NOTIFICATION
        msg.session_id = self.session_id
        msg.seq_number = self.seq_number
        
        # Add AUTH AVP
        msg_without_auth = msg.pack()
        auth_value = self.crypto_ctx.compute_auth(msg_without_auth)
        msg.add_avp(AVP(AVP_AUTH, 0, auth_value))
        
        message_data = msg.pack()
        self.socket.sendto(message_data, (self.server_addr, self.server_port))
        self.retransmit_mgr.add_message(self.seq_number, message_data, (self.server_addr, self.server_port))
        self.seq_number += 1
        
    def handle_notification_msg(self, msg):
        """Handle PANA-Notification message (including Ping and Re-authentication per RFC 5191)"""
        # Handle re-authentication response (RFC 5191 Section 4.3)
        if msg.flags & FLAG_REAUTH:
            if not msg.is_request():
                self.retransmit_mgr.remove_message(self.seq_number - 1)
                # Update session lifetime
                lifetime_avp = msg.get_avp(AVP_SESSION_LIFETIME)
                if lifetime_avp:
                    self.session_lifetime = extract_avp_uint32(lifetime_avp)
                    self.session_start_time = time.time()
                    self.logger.info(f"Session re-authenticated, new lifetime: {self.session_lifetime}")
                    self._start_session_monitoring()
            return
            
        if msg.flags & FLAG_PING:
            # This is a Ping request or response
            if msg.is_request():
                # Respond to Ping request
                answer = PANAMessage()
                answer.flags = FLAG_PING  # Answer with Ping flag
                answer.msg_type = PANA_NOTIFICATION
                answer.session_id = msg.session_id
                answer.seq_number = msg.seq_number  # RFC 5191 Section 5.2: Answer uses request's seq number
                
                if self.crypto_ctx.pana_auth_key:
                    # RFC 5191: No A-flag needed when adding AUTH AVP
                    msg_without_auth = answer.pack()
                    auth_value = self.crypto_ctx.compute_auth(msg_without_auth)
                    answer.add_avp(AVP(AVP_AUTH, 0, auth_value))
                    
                self.socket.sendto(answer.pack(), (self.server_addr, self.server_port))
                self.seq_number += 1
            else:
                # Ping response received, remove from retransmission
                self.retransmit_mgr.remove_message(self.seq_number - 1)
                self.logger.debug("Ping response received")
        
    def send_termination_request(self):
        """
        セッション終了要求の送信
        
        【説明】
        PANA-Termination-Requestメッセージを送信して、PANAセッションを
        正常に終了させます。終了理由として"Logout"を設定します。
        
        【含まれるAVP】
        - Termination-Cause: 終了理由（1 = Logout）
        - AUTH: 認証タグ（鍵が利用可能な場合）
        """
        msg = PANAMessage()
        msg.flags = FLAG_REQUEST
        msg.msg_type = PANA_TERMINATION
        msg.session_id = self.session_id
        msg.seq_number = self.seq_number
        
        # Add Termination-Cause AVP
        msg.add_avp(create_avp_uint32(AVP_TERMINATION_CAUSE, 1))  # Logout
        
        # Add AUTH AVP if keys available
        if self.crypto_ctx.pana_auth_key:
            # RFC 5191: No A-flag needed when adding AUTH AVP
            msg_without_auth = msg.pack()
            auth_value = self.crypto_ctx.compute_auth(msg_without_auth)
            msg.add_avp(AVP(AVP_AUTH, 0, auth_value))
        
        message_data = msg.pack()
        self.socket.sendto(message_data, (self.server_addr, self.server_port))
        self.retransmit_mgr.add_message(self.seq_number, message_data, (self.server_addr, self.server_port))
        self.seq_number += 1
        
    def run(self):
        """
        PANAクライアントのメイン実行ループ
        
        【説明】
        PANAクライアントのメイン処理を実行します。
        1. PANA-Client-Initiationを送信してセッションを開始
        2. PAAからのメッセージを待機し、適切に処理
        3. セッションが終了するまでループを継続
        
        【エラー処理】
        - ネットワークエラーはログに記録して継続
        - パースエラーはスキップ
        - KeyboardInterruptで正常終了
        """
        self.logger.info("Starting PANA Client...")
        
        try:
            # Send PANA-Client-Initiation
            self.send_pci()
        except Exception as e:
            self.logger.error(f"Failed to send PCI: {e}")
            return
        
        # Main loop
        while self.running:
            try:
                # Use select for timeout handling
                ready = select.select([self.socket], [], [], 1.0)
                if not ready[0]:
                    continue
                    
                data, addr = self.socket.recvfrom(65536)  # 最大フラグメントサイズ対応
                self.logger.info(f"Received {len(data)} bytes from {addr}")
                if not data:
                    continue
                    
                msg = PANAMessage()
                try:
                    msg.unpack(data)
                    self.logger.debug(f"Successfully parsed message: type={msg.msg_type}, flags=0x{msg.flags:04x}, seq={msg.seq_number}")
                except ValueError as e:
                    self.logger.error(f"Failed to parse PANA message: {e}")
                    self.logger.debug(f"Raw data: {data.hex()}")
                    continue
                
                # RFC 5191 Section 5.1: PANA does not provide fragmentation
                # Messages are not fragmented at PANA level
                
                # リプレイ攻撃のチェック（応答メッセージのみ）
                if not msg.is_request():
                    if not self.anti_replay.check_and_update(msg.seq_number):
                        self.logger.warning(f"Replay attack detected! Dropping message with seq={msg.seq_number}")
                        continue
                
                # RFC 5191: No fragmentation cleanup needed
                
                self.logger.info(f"Received message: type={msg.msg_type}, flags=0x{msg.flags:04x}, seq={msg.seq_number}")
                
                # 統計情報: パケット受信
                self.statistics.record_packet(self.session_id, 'received', len(data), msg.msg_type)
                
                if msg.msg_type == PANA_AUTH:
                    self.handle_auth_msg(msg)
                elif msg.msg_type == PANA_NOTIFICATION:
                    self.handle_notification_msg(msg)
                elif msg.msg_type == PANA_TERMINATION:
                    if msg.is_request():
                        # Server initiated termination
                        # Send termination answer
                        answer = PANAMessage()
                        answer.flags = 0  # Answer
                        answer.msg_type = PANA_TERMINATION
                        answer.session_id = msg.session_id
                        answer.seq_number = msg.seq_number  # RFC 5191 Section 5.2: Answer uses request's seq number
                        
                        if self.crypto_ctx.pana_auth_key:
                            # RFC 5191: No A-flag needed when adding AUTH AVP
                            msg_without_auth = answer.pack()
                            auth_value = self.crypto_ctx.compute_auth(msg_without_auth)
                            answer.add_avp(AVP(AVP_AUTH, 0, auth_value))
                            
                        self.socket.sendto(answer.pack(), addr)
                        self.running = False
                    else:
                        # Our termination request was acknowledged
                        self.retransmit_mgr.remove_message(self.seq_number - 1)
                        self.running = False
                    
            except socket.error as e:
                # ソケットエラーのハンドリング
                context = create_error_context(
                    ErrorType.SOCKET_ERROR,
                    e,
                    session_id=self.session_id,
                    addr=(self.server_addr, self.server_port)
                )
                action = self.error_recovery.handle_error(context)
                
                if action == RecoveryAction.RETRY:
                    continue
                elif action == RecoveryAction.ESCALATE:
                    self.logger.critical(f"Critical socket error: {e}")
                    break
                    
            except Exception as e:
                # その他のエラー
                self.logger.error(f"Error: {e}", exc_info=True)
                
                # プロトコルエラーとして扱う
                context = create_error_context(
                    ErrorType.PROTOCOL_ERROR,
                    e,
                    session_id=self.session_id,
                    additional_info={'location': 'main_loop'}
                )
                self.error_recovery.handle_error(context)
                
        self.cleanup()
        self.logger.info("PANA Client terminated")
        
    def cleanup(self):
        """
        リソースのクリーンアップ
        
        【説明】
        PANAクライアントが使用したすべてのリソースを適切に解放します。
        - 再送信マネージャーの停止
        - EAPハンドラのクリーンアップ
        - ソケットのクローズ
        """
        self.retransmit_mgr.stop()
        if self.eap_handler:
            self.eap_handler.cleanup()
        self.socket.close()
        self.monitor.stop()
        self.statistics.stop()
    
    def _determine_local_ip(self):
        """
        サーバーと通信するための適切なローカルIPアドレスを決定
        
        Returns:
            str: ローカルIPアドレス（決定できない場合は''で全インターフェース）
        """
        try:
            # サーバーへの接続を試みて、使用されるローカルIPを取得
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_socket.connect((self.server_addr, self.server_port))
            ip_address = test_socket.getsockname()[0]
            test_socket.close()
            self.logger.debug(f"Determined local IP for server {self.server_addr}: {ip_address}")
            return ip_address
        except Exception as e:
            self.logger.warning(f"Could not determine specific local IP, using all interfaces: {e}")
            return ''  # フォールバック: 全インターフェースにバインド
    
    def _get_current_ip(self):
        """
        現在のIPアドレスを取得
        
        Returns:
            str: 現在のIPアドレス
        """
        try:
            # サーバーへの接続を試みて、使用されるローカルIPを取得
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_socket.connect((self.server_addr, self.server_port))
            ip_address = test_socket.getsockname()[0]
            test_socket.close()
            return ip_address
        except Exception as e:
            self.logger.error(f"Failed to get current IP: {e}")
            return None
    
    def _monitor_ip_change(self):
        """
        IPアドレス変更を監視
        
        【説明】
        定期的に現在のIPアドレスをチェックし、
        変更が検出されたらFLAG_IP_RECONFIGフラグを立てて
        再認証を要求します。
        """
        while self.running and self.state == PAC_STATE_OPEN:
            try:
                time.sleep(5)  # 5秒ごとにチェック
                
                new_ip = self._get_current_ip()
                if new_ip and self.current_ip and new_ip != self.current_ip:
                    self.logger.warning(f"IP address changed from {self.current_ip} to {new_ip}")
                    self.current_ip = new_ip
                    
                    # FLAG_IP_RECONFIGを送信
                    self._send_ip_reconfig_notification()
                    
            except Exception as e:
                self.logger.error(f"Error in IP monitor: {e}")
    
    def _send_ip_reconfig_notification(self):
        """
        IPアドレス変更通知を送信
        
        【説明】
        FLAG_IP_RECONFIGフラグを立てたPANA-Notificationメッセージを送信し、
        IPアドレスが変更されたことをPAAに通知します。
        """
        notification = PANAMessage()
        notification.flags = FLAG_IP_RECONFIG  # IP再設定フラグ
        notification.msg_type = PANA_NOTIFICATION
        notification.session_id = self.session_id
        notification.seq_number = self.seq_number
        
        # 新しいIPアドレスでソケットを再作成
        try:
            old_socket = self.socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.current_ip, 0))
            old_socket.close()
            
            # retransmit_mgrのソケットも更新
            self.retransmit_mgr.socket = self.socket
            
            self.logger.info(f"Socket rebound to new IP: {self.current_ip}")
        except Exception as e:
            self.logger.error(f"Failed to rebind socket: {e}")
            return
        
        # 通知を送信
        self._prepare_and_send_message(notification)
        
        # 再認証を待つ状態に遷移
        prev_state = self.state
        self.state = PAC_STATE_WAIT_PAN_OR_PAR
        self.logger.info(f"State transition: {prev_state} -> {PAC_STATE_WAIT_PAN_OR_PAR} (IP reconfigured)")