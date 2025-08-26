#!/usr/bin/env python3
"""
PANA Authentication Agent (PAA) Implementation
RFC5191 compliant PANA server

【概要】
このモジュールはPANA (Protocol for carrying Authentication for Network Access) の
サーバー側実装です。RFC5191およびRFC6786（暗号化拡張）に準拠しています。

【主な機能】
- PANA-Client-Initiation (PCI) の受信と処理
- EAP-TLS認証の実行（直接またはRADIUSプロキシ経由）
- 複数セッションの同時管理
- メッセージの再送信管理
- セッションライフサイクル管理
- RFC6786準拠のAVP暗号化サポート
- RADIUSサーバーとの統合（オプション）
"""

import socket
import struct
import select
import logging
import time

from pana_constants import (
    # Message types
    PANA_CLIENT_INITIATION, PANA_AUTH, PANA_TERMINATION, PANA_NOTIFICATION,
    # Flags
    FLAG_REQUEST, FLAG_START, FLAG_COMPLETE, FLAG_PING, FLAG_REAUTH,
    FLAG_IP_RECONFIG,
    # AVP codes
    AVP_RESULT_CODE, AVP_EAP_PAYLOAD, AVP_NONCE, AVP_PRF_ALGORITHM,
    AVP_INTEGRITY_ALGORITHM, AVP_KEY_ID, AVP_AUTH, AVP_SESSION_LIFETIME,
    AVP_ENCRYPTION_ALGORITHM, AVP_ENCRYPTION_ENCAP,
    # Result codes
    RESULT_CODE_SUCCESS, RESULT_CODE_FAILURE,
    # State constants
    PAA_STATE_WAIT_EAP_MSG, PAA_STATE_WAIT_SUCC_PAN, PAA_STATE_OPEN, 
    PAA_STATE_WAIT_FAIL_PAN, PAA_STATE_WAIT_PAN_OR_PAR,
    # Algorithm constants
    PRF_HMAC_SHA1, PRF_HMAC_SHA2_256,
    AUTH_HMAC_SHA1_160, AUTH_HMAC_SHA2_256_128,
    AES128_CTR,
    # Other constants
    AUTHENTICATED_SESSION_CLEANUP_DELAY, DEFAULT_SESSION_LIFETIME,
    EAP_REQUEST, EAP_TYPE_IDENTITY
)
from pana_messages import PANAMessage, AVP, create_avp_uint32, extract_avp_uint32
from pana_session import SessionManager
from pana_retransmission import RetransmissionManager
from eap_tls_factory import create_eap_tls_handler
from pana_error_recovery import ErrorRecovery, ErrorType, RecoveryAction, create_error_context
from pana_server_encryption import ServerEncryptionHelper
# from pana_fragmentation import MessageFragmenter  # Removed: RFC 5191 forbids fragmentation
from pana_statistics import PANAStatistics
from pana_monitor import PANAMonitor


class PANAAuthAgent:
    """PANA Authentication Agent (PAA) Implementation - RFC5191 Compliant with RFC6786 Encryption
    
    【クラス説明】
    PANAプロトコルの認証エージェント（PAA: PANA Authentication Agent）を実装するメインクラス。
    ネットワークアクセス認証のサーバーとして動作し、複数のクライアントを同時に処理できます。
    
    【状態遷移】
    INITIAL -> WAIT_EAP_MSG -> WAIT_SUCC_PAN -> OPEN
    各状態の詳細はRFC5191のセクション4.2を参照。
    
    【動作モード】
    1. スタンドアロンモード: EAP-TLS認証を直接処理
    2. RADIUSプロキシモード: 認証をRADIUSサーバーに委譲
    """
    def __init__(self, bind_addr='0.0.0.0', bind_port=716,
                 radius_server=None, radius_port=1812, radius_secret=None,
                 encryption_policy=None):
        """
        PANA認証エージェントの初期化
        
        引数:
            bind_addr: バインドするIPアドレス（デフォルト: 0.0.0.0 = 全インターフェース）
            bind_port: バインドするポート番号（デフォルト: 716）
            radius_server: RADIUSサーバーのIPアドレス（オプション）
            radius_port: RADIUSサーバーのポート番号（デフォルト: 1812）
            radius_secret: RADIUS共有シークレット
            encryption_policy: RFC6786暗号化ポリシー（オプション）
        """
        # サーバー設定の保存
        self.bind_addr = bind_addr
        self.bind_port = bind_port
        self.radius_server = radius_server
        self.radius_port = radius_port
        self.radius_secret = radius_secret
        self.logger = logging.getLogger('PANA-AuthAgent')
        
        # UDPソケットの作成とバインド
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((bind_addr, bind_port))
        except OSError as e:
            self.logger.error(f"Failed to bind to {bind_addr}:{bind_port}: {e}")
            raise
            
        # 各種マネージャーの初期化
        self.logger.info("Initializing SessionManager...")
        self.session_mgr = SessionManager(encryption_policy)  # セッション管理
        self.logger.info("SessionManager initialized")
        self.retransmit_mgr = RetransmissionManager(self.socket)  # 再送信管理
        self.running = True  # 実行フラグ
        
        # RFC 6786 暗号化サポートの初期化
        self.encryption_helper = ServerEncryptionHelper(encryption_policy)
        
        # エラーリカバリマネージャー
        self.error_recovery = ErrorRecovery(
            session_manager=self.session_mgr,
            retransmit_manager=self.retransmit_mgr
        )
        
        # DoS攻撃対策の初期化
        # Temporarily disable rate limiter to avoid initialization issues
        self.rate_limiter = None
        self.logger.info("RateLimiter disabled temporarily")
            
        # RFC 5191 Section 5.1: PANA does not provide fragmentation
        # Fragmentation removed for RFC compliance
        
        # 統計情報収集の初期化
        try:
            self.statistics = PANAStatistics()
            self.monitor = PANAMonitor(self.statistics)
            # self.monitor.start()  # 一時的に無効化
            self.logger.info("Statistics and monitoring initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize statistics: {e}", exc_info=True)
            self.statistics = None
            self.monitor = None

        # RADIUSクライアントの初期化（オプション）
        self.radius_client = None
        if self.radius_server:
            try:
                from pyrad.client import Client
                from pyrad.dictionary import Dictionary
                self.radius_client = Client(server=self.radius_server,
                                           secret=(self.radius_secret or '').encode(),
                                           dict=Dictionary())
                self.radius_client.authport = self.radius_port
                self.logger.info(f"RADIUSプロキシモード: {self.radius_server}:{self.radius_port}")
            except Exception as e:
                self.logger.error(f"Failed to initialize RADIUS client: {e}")
        
    def handle_pci(self, msg, addr):
        """
        PANA-Client-Initiation (PCI) メッセージの処理
        
        【説明】
        クライアントからのセッション開始要求を処理します。
        新しいセッションを作成し、EAP認証を開始します。
        
        引数:
            msg: 受信したPCIメッセージ
            addr: クライアントのアドレスタプル (IP, port)
        
        【処理フロー】
        1. 新しいセッションの作成
        2. クライアントのnonceとアルゴリズムの抽出
        3. RFC6786暗号化アルゴリズムのネゴシエーション
        4. EAP-Request/Identityを含むPANA-Auth-Requestの送信
        """
        self.logger.info(f"Processing PCI from {addr}")
        # RFC 5191: PCI has session_id=0, PAA generates new session ID
        import random
        session_id = random.randint(1, 0xFFFFFFFF)
        self.logger.debug(f"Generated session ID: {session_id:08x}")
        
        # Check for existing authenticated session from this IP
        client_ip = addr[0]
        for (sid, ip), session in self.session_mgr.sessions.items():
            if ip == client_ip and session.state == PAA_STATE_OPEN:
                self.logger.warning(f"Ignoring PCI from already authenticated client {client_ip} (session {sid:08x})")
                return

        # DoS攻撃対策: セッション数制限チェック
        if self.rate_limiter:
            allowed, reason = self.rate_limiter.check_new_session(addr[0])
            if not allowed:
                self.logger.warning(f"New session denied for {addr[0]}: {reason}")
                return
        
        # 新しいセッションの作成
        # キーは (session_id, クライアントIP) のタプルで、同一IPからの複数セッションを識別
        key = (session_id, addr[0])
        self.logger.debug(f"Creating session with key: {key}")
        try:
            session = self.session_mgr.create_session(key, addr)
            self.logger.debug(f"Session created: {session}")
        except Exception as e:
            self.logger.error(f"Failed to create session: {e}", exc_info=True)
            import traceback
            traceback.print_exc()
            return
        
        # 統計情報: セッション開始
        if self.statistics:
            try:
                session_stats = self.statistics.start_session(session_id)
                session_stats.start_authentication()
            except Exception as e:
                self.logger.error(f"Error in statistics: {e}")
        
        # レート制限にセッションを追加
        if self.rate_limiter:
            self.rate_limiter.add_session(addr[0])
        
        # EAPハンドラの設定
        self.logger.debug(f"Setting up EAP handler. RADIUS client: {self.radius_client is not None}")
        try:
            if self.radius_client is None:
                # スタンドアロンモード: EAP-TLSを直接処理
                self.logger.debug("Creating EAP-TLS handler for standalone mode")
                handler = create_eap_tls_handler(is_server=True)
                # ハンドラーの初期状態を確実にSTARTに設定
                handler.state = 'START'
                session.set_eap_handler(handler)
                self.logger.debug(f"EAP-TLS handler created and set, state: {handler.state}")
            else:
                # RADIUSプロキシモード: EAP処理はRADIUSサーバーに委譲
                self.logger.debug("RADIUS proxy mode - no local EAP handler")
                session.set_eap_handler(None)
        except Exception as e:
            self.logger.error(f"Failed to set up EAP handler: {e}", exc_info=True)
            import traceback
            traceback.print_exc()
            return
        
        # PCI doesn't contain nonce - it will come in the initial PAN response
        
        # EAP-Request/Identityを含むPANA-Auth-Requestの作成
        self.logger.debug("Creating PAR message")
        auth_req = PANAMessage()
        auth_req.flags = FLAG_REQUEST | FLAG_START  # 要求メッセージ + Sフラグ（初期PAR）
        auth_req.msg_type = PANA_AUTH  # 認証メッセージタイプ
        auth_req.session_id = session_id  # セッションIDをコピー
        auth_req.seq_number = session.seq_number  # シーケンス番号
        self.logger.debug(f"PAR: session_id={session_id:08x}, seq={session.seq_number}")
        
        # RFC 5191: Initial PAR with S-bit should NOT contain EAP or nonce
        # EAP-Request/Identity will be sent in first non-initial PAR
        # Initialize EAP handler but don't send EAP yet
        self.logger.debug("Preparing EAP handler for later use")
        if self.radius_client is None and session.eap_handler:
            # Initialize the handler but don't generate EAP-Request yet
            self.logger.debug("EAP handler ready for first non-initial PAR")
        
        # RFC 5191: No nonce in initial PAR with S-bit
        # PAA nonce will be sent in first non-initial PAR
        # Generate nonce now but don't send it yet
        session.crypto_ctx.nonce_paa = session.crypto_ctx.generate_nonce()
        self.logger.debug(f"Generated PAA nonce for later use: {session.crypto_ctx.nonce_paa.hex()}")
        
        # RFC5191準拠: PAAが複数のアルゴリズム候補を提示
        # PRF candidates (SHA1 first for OpenPANA compatibility, per RFC5191)
        auth_req.add_avp(create_avp_uint32(AVP_PRF_ALGORITHM, PRF_HMAC_SHA1))
        auth_req.add_avp(create_avp_uint32(AVP_PRF_ALGORITHM, PRF_HMAC_SHA2_256))
        
        # Integrity candidates (SHA1 first for OpenPANA compatibility)
        auth_req.add_avp(create_avp_uint32(AVP_INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_160))
        auth_req.add_avp(create_avp_uint32(AVP_INTEGRITY_ALGORITHM, AUTH_HMAC_SHA2_256_128))
        
        # RFC 6786: Add encryption algorithm candidates if enabled
        if self.encryption_helper and hasattr(self.encryption_helper, 'is_encryption_enabled') and self.encryption_helper.is_encryption_enabled():
            auth_req.add_avp(create_avp_uint32(AVP_ENCRYPTION_ALGORITHM, AES128_CTR))
        
        # Session-Lifetime AVPは送信しない（RFC5191準拠: Cビット付き最終メッセージのみ）
        
        # Store I_PAR (initial PAR with S-bit) for key derivation (RFC 5191 Section 5.3)
        session.crypto_ctx.i_par = auth_req.pack()
        self.logger.debug(f"Stored I_PAR ({len(session.crypto_ctx.i_par)} bytes) for key derivation")
        
        # Send message
        self.logger.debug(f"Sending PANA-Auth-Request to {addr}")
        self._prepare_and_send_message(auth_req, session, addr)
        self.logger.info(f"PANA-Auth-Request sent to {addr}")
        
    def handle_auth_msg(self, msg, addr):
        """
        PANA-Authメッセージの処理
        
        【説明】
        クライアントからのPANA-Auth-Answerを処理し、EAP認証を進めます。
        RADIUSモードの場合は、EAPメッセージをRADIUSサーバーに転送します。
        
        引数:
            msg: 受信したPANA-Authメッセージ
            addr: クライアントのアドレスタプル
        
        【処理フロー】
        1. セッションの検索と検証
        2. RFC6786暗号化されたAVPの復号
        3. EAPペイロードの処理
        4. 認証結果に基づく応答の送信
        """
        session_id = msg.session_id
        
        # セッションの検索
        # (session_id, クライアントIP) でセッションを特定
        key = (session_id, addr[0])
        session = self.session_mgr.get_session(key)
        if not session:
            self.logger.warning(f"No session found for {session_id:08x} from {addr}")
            return
        
        # RFC 6786: 暗号化されたAVPの処理
        encrypted_avp_codes = []
        if session.is_encryption_active():
            # Check if there's an Encryption-Encap AVP
            encap_avp = msg.get_avp(AVP_ENCRYPTION_ENCAP)
            if encap_avp:
                # Track which AVPs were encrypted
                encrypted_avp_codes = [AVP_ENCRYPTION_ENCAP]  # Mark encap as encrypted
            
            decrypted_avps = self.encryption_helper.process_encrypted_message(msg, session)
            # 復号されたAVPをメッセージに追加して処理を継続
            for avp in decrypted_avps:
                encrypted_avp_codes.append(avp.code)  # Track decrypted AVP codes
                msg.avps.append(avp)
            
            # RFC 6786 Section 3: Validate encryption policy
            if self.encryption_policy:
                valid, errors = self.encryption_policy.validate_encryption_policy(
                    msg.avps, encrypted_avp_codes
                )
                if not valid:
                    self.logger.error(f"Encryption policy violation from {addr}: {errors}")
                    # RFC 6786: Silently discard messages violating policy
                    return

        # クライアントのポートが変更された場合に備えてアドレスを更新
        session.addr = addr
            
        # 応答メッセージの場合、対応する要求を再送信キューから削除
        if not msg.is_request() and session.seq_number > 0:
            self.retransmit_mgr.remove_message(session.seq_number - 1)
            
        # RFC5191: AUTH AVP is mandatory after key establishment (except for PCI and initial exchanges)
        # Don't enforce on initial exchanges (S-bit set) as keys aren't established yet
        if (session.crypto_ctx.pana_auth_key and 
            msg.msg_type != PANA_CLIENT_INITIATION and
            not (msg.flags & FLAG_START)):  # Don't enforce on S-bit messages
            auth_avp = msg.get_avp(AVP_AUTH)
            if not auth_avp:
                self.logger.warning(f"Missing mandatory AUTH AVP after key establishment from {addr}")
                return  # Silently discard message
            
        # AVPの抽出
        eap_payload = None  # EAPペイロード
        auth_avp = None     # 認証タグ
        selected_prf = None  # 選択されたPRFアルゴリズム
        selected_integrity = None  # 選択された完全性アルゴリズム
        
        for avp in msg.avps:
            if avp.code == AVP_EAP_PAYLOAD:
                eap_payload = avp.value  # EAPメッセージを抽出
            elif avp.code == AVP_AUTH:
                auth_avp = avp.value     # HMAC値を抽出
            elif avp.code == AVP_PRF_ALGORITHM:
                selected_prf = extract_avp_uint32(avp)  # 選択されたPRFアルゴリズム
            elif avp.code == AVP_INTEGRITY_ALGORITHM:
                selected_integrity = extract_avp_uint32(avp)  # 選択された完全性アルゴリズム
                
        # 初期PANで選択されたアルゴリズムを保存
        if not msg.is_request() and selected_prf:
            session.crypto_ctx.prf_algorithm = selected_prf
            self.logger.info(f"Client selected PRF algorithm: {selected_prf}")
        if not msg.is_request() and selected_integrity:
            session.crypto_ctx.auth_algorithm = selected_integrity
            self.logger.info(f"Client selected integrity algorithm: {selected_integrity}")
        
        # RFC 5191: Extract client nonce from first non-initial PAN (no S-bit)
        if not msg.is_request() and not (msg.flags & FLAG_START) and not session.crypto_ctx.nonce_pac:
            for avp in msg.avps:
                if avp.code == AVP_NONCE:
                    session.crypto_ctx.nonce_pac = avp.value
                    self.logger.debug(f"Extracted client nonce from first non-initial PAN: {avp.value.hex()}")
            
        # Store I_PAN (initial PAN with S-bit) for key derivation (RFC 5191 Section 5.3)
        if not msg.is_request() and (msg.flags & FLAG_START) and not session.crypto_ctx.i_pan:
            session.crypto_ctx.i_pan = msg.pack()
            self.logger.debug(f"Stored I_PAN ({len(session.crypto_ctx.i_pan)} bytes) for key derivation")
            
            # RFC 5191: Nonce MUST NOT be in initial messages with S-bit
            # Client nonce will come in first non-initial PAN
                
        # Verify AUTH AVP if present and we have keys
        if auth_avp and session.crypto_ctx.pana_auth_key:
            # Reconstruct message without AUTH AVP
            msg_copy = PANAMessage()
            msg_copy.reserved = msg.reserved
            msg_copy.flags = msg.flags
            msg_copy.msg_type = msg.msg_type
            msg_copy.session_id = msg.session_id
            msg_copy.seq_number = msg.seq_number
            
            for avp in msg.avps:
                if avp.code != AVP_AUTH:
                    msg_copy.add_avp(avp)
                    
            if not session.crypto_ctx.verify_auth(msg_copy.pack(), auth_avp):
                self.logger.error("AUTH AVP verification failed")
                return
                
        if eap_payload and self.radius_client:
            # Forward EAP payload to RADIUS server
            try:
                req = self.radius_client.CreateAuthPacket(code=1)
                req['NAS-Identifier'] = 'pyPANA'
                req['EAP-Message'] = eap_payload
                if session.radius_state:
                    req['State'] = session.radius_state
                reply = self.radius_client.SendPacket(req)
                if 'State' in reply:
                    session.radius_state = reply['State'][0]
                eap_response = None
                if 'EAP-Message' in reply:
                    eap_response = reply['EAP-Message'][0]
                radius_code = getattr(reply, 'code', None)
            except Exception as e:
                self.logger.error(f"RADIUS communication failed: {e}")
                return

            if eap_response:
                auth_req = PANAMessage()
                auth_req.flags = FLAG_REQUEST
                auth_req.msg_type = PANA_AUTH
                auth_req.session_id = session_id
                auth_req.seq_number = session.seq_number
                auth_req.add_avp(AVP(AVP_EAP_PAYLOAD, 0, eap_response))

                if radius_code == 2:  # Access-Accept
                    auth_req.flags |= FLAG_COMPLETE
                    auth_req.add_avp(create_avp_uint32(AVP_RESULT_CODE, RESULT_CODE_SUCCESS))
                    session.state = PAA_STATE_WAIT_SUCC_PAN
                    # 統計情報: 認証成功
                    if self.statistics:
                        self.statistics.record_auth_result(session_id, 'success')
                elif radius_code == 3:  # Access-Reject
                    auth_req.flags |= FLAG_COMPLETE
                    auth_req.add_avp(create_avp_uint32(AVP_RESULT_CODE, RESULT_CODE_FAILURE))
                    session.state = PAA_STATE_WAIT_FAIL_PAN
                    # 統計情報: 認証失敗
                    if self.statistics:
                        self.statistics.record_auth_result(session_id, 'failure')
                    
                    # エラーリカバリ: 認証失敗をハンドル
                    context = create_error_context(
                        ErrorType.AUTH_FAILURE,
                        Exception("RADIUS authentication rejected"),
                        session_id=session_id,
                        addr=addr,
                        additional_info={'radius_code': radius_code}
                    )
                    self.error_recovery.handle_error(context)

                message_data = auth_req.pack()
                self.socket.sendto(message_data, addr)
                self.retransmit_mgr.add_message(session.seq_number, message_data, addr)
                # RFC 5191 Section 5.2: Wrap sequence number at 2^32
                session.seq_number = (session.seq_number + 1) % (2**32)
            return

        if eap_payload:
            # Process EAP message
            eap_response = session.eap_handler.process_eap_message(eap_payload)
            
            if eap_response:
                # Check if authentication is complete
                if session.eap_handler.state == 'COMPLETE':
                    # Get MSK and derive keys
                    msk = session.eap_handler.get_msk()
                    emsk = session.eap_handler.get_emsk()
                    if msk:
                        session.crypto_ctx.session_id = session_id  # Pass session_id for key derivation
                        session.crypto_ctx.derive_keys(msk, emsk)
                        
                    # Send final PANA-Auth-Request with EAP-Success
                    final_req = PANAMessage()
                    final_req.flags = FLAG_REQUEST | FLAG_COMPLETE  # RFC 5191: No A-flag here
                    final_req.msg_type = PANA_AUTH
                    final_req.session_id = session_id
                    final_req.seq_number = session.seq_number
                    
                    # Add EAP Success
                    final_req.add_avp(AVP(AVP_EAP_PAYLOAD, 0, eap_response))
                    
                    # Add Result-Code AVP (Success)
                    final_req.add_avp(create_avp_uint32(AVP_RESULT_CODE, RESULT_CODE_SUCCESS))
                    
                    # Add Session-Lifetime AVP
                    final_req.add_avp(create_avp_uint32(AVP_SESSION_LIFETIME, session.lifetime))
                    
                    # Add Key-ID AVP
                    if session.crypto_ctx.key_id:
                        final_req.add_avp(AVP(AVP_KEY_ID, 0, session.crypto_ctx.key_id))
                    
                    # Add AUTH AVP
                    msg_without_auth = final_req.pack()
                    auth_value = session.crypto_ctx.compute_auth(msg_without_auth)
                    final_req.add_avp(AVP(AVP_AUTH, 0, auth_value))
                    
                    message_data = final_req.pack()
                    self.socket.sendto(message_data, addr)
                    self.retransmit_mgr.add_message(session.seq_number, message_data, addr)
                    # RFC 5191 Section 5.2: Wrap sequence number at 2^32
                    session.seq_number = (session.seq_number + 1) % (2**32)
                    
                    # Update state to WAIT_SUCC_PAN
                    session.state = PAA_STATE_WAIT_SUCC_PAN
                    self.logger.info(f"State transition: {PAA_STATE_WAIT_EAP_MSG} -> {PAA_STATE_WAIT_SUCC_PAN}")
                    self.logger.info(f"Authentication successful for session {session_id:08x}")
                else:
                    # Continue EAP exchange
                    auth_req = PANAMessage()
                    auth_req.flags = FLAG_REQUEST
                    auth_req.msg_type = PANA_AUTH
                    auth_req.session_id = session_id
                    auth_req.seq_number = session.seq_number
                    
                    # Add EAP payload
                    auth_req.add_avp(AVP(AVP_EAP_PAYLOAD, 0, eap_response))
                    
                    message_data = auth_req.pack()
                    self.socket.sendto(message_data, addr)
                    self.retransmit_mgr.add_message(session.seq_number, message_data, addr)
                    # RFC 5191 Section 5.2: Wrap sequence number at 2^32
                session.seq_number = (session.seq_number + 1) % (2**32)
                    
        elif msg.flags & FLAG_COMPLETE:
            # Client acknowledged final auth message
            if session.state == PAA_STATE_WAIT_SUCC_PAN:
                session.state = PAA_STATE_OPEN
                self.logger.info(f"State transition: {PAA_STATE_WAIT_SUCC_PAN} -> {PAA_STATE_OPEN}")
                # Clear all pending retransmissions for this client
                self.retransmit_mgr.clear_messages_for_address(addr)
                
                # Mark session as authenticated and schedule cleanup
                session.mark_authenticated()
                # Schedule cleanup after configured delay
                session.schedule_cleanup(
                    self.session_mgr.cleanup_authenticated_session,
                    AUTHENTICATED_SESSION_CLEANUP_DELAY
                )
                self.logger.info(f"Scheduled cleanup for session {session_id:08x} in {AUTHENTICATED_SESSION_CLEANUP_DELAY} seconds")
                
                # Pause retransmission manager for this session as authentication is complete
                # This reduces CPU usage during idle authenticated sessions
                # Note: Will be resumed if re-authentication is needed
                
            self.logger.info(f"Client acknowledged authentication for session {session_id:08x}")
        else:
            # Handle initial PAN with S-bit - send first non-initial PAR with nonce and EAP-Request/Identity
            # RFC 5191 Section 4.1: "A Nonce AVP MUST be included in the first PANA-Auth-Request
            # and PANA-Auth-Answer messages following the initial messages (with 'S' bit set)"
            if not msg.is_request() and (msg.flags & FLAG_START):
                self.logger.info("Received initial PAN with S-bit, sending first non-initial PAR with PAA nonce and EAP-Request/Identity")
                
                # Generate EAP Request/Identity
                eap_response = session.eap_handler.process_eap_message(b'')
                
                # Create first non-initial PAR with nonce and EAP-Request/Identity
                auth_req = PANAMessage()
                auth_req.flags = FLAG_REQUEST  # No S-bit for non-initial message
                auth_req.msg_type = PANA_AUTH
                auth_req.session_id = session_id
                auth_req.seq_number = session.seq_number
                
                # Add PAA nonce (RFC 5191 requirement)
                if not session.crypto_ctx.nonce_paa:
                    session.crypto_ctx.nonce_paa = session.crypto_ctx.generate_nonce()
                auth_req.add_avp(AVP(AVP_NONCE, 0, session.crypto_ctx.nonce_paa))
                self.logger.debug(f"Added PAA nonce to first non-initial PAR: {session.crypto_ctx.nonce_paa.hex()}")
                
                # Add EAP-Request/Identity
                if eap_response:
                    auth_req.add_avp(AVP(AVP_EAP_PAYLOAD, 0, eap_response))
                    self.logger.debug(f"Added EAP-Request/Identity to first non-initial PAR")
                
                # Send message
                message_data = auth_req.pack()
                self.socket.sendto(message_data, addr)
                self.retransmit_mgr.add_message(session.seq_number, message_data, addr)
                # RFC 5191 Section 5.2: Wrap sequence number at 2^32
                session.seq_number = (session.seq_number + 1) % (2**32)
                
                # Update state
                session.state = PAA_STATE_WAIT_EAP_MSG
                self.logger.info(f"State transition: {PAA_STATE_WAIT_PAN_OR_PAR} -> {PAA_STATE_WAIT_EAP_MSG}")
            
        
    def handle_notification_msg(self, msg, addr):
        """Handle PANA-Notification message (including Ping and Re-authentication per RFC 5191)"""
        session_id = msg.session_id
        key = (session_id, addr[0])
        session = self.session_mgr.get_session(key)
        
        # Special handling for IP reconfiguration
        if not session and (msg.flags & FLAG_IP_RECONFIG):
            # IP has changed, look for session with old IP
            for existing_key, existing_session in list(self.session_mgr.sessions.items()):
                if existing_key[0] == session_id:
                    session = existing_session
                    break
        
        if not session:
            return

        # Update address in case port changed
        session.addr = addr
        
        # Handle re-authentication request (RFC 5191 Section 4.3)
        if msg.flags & FLAG_REAUTH:
            if msg.is_request():
                self.logger.info(f"Re-authentication request received for session {session_id:08x}")
                
                # Verify AUTH AVP if present
                auth_avp = None
                for avp in msg.avps:
                    if avp.code == AVP_AUTH:
                        auth_avp = avp.value
                        break
                        
                if auth_avp and session.crypto_ctx.pana_auth_key:
                    # Verify message authentication
                    msg_copy = PANAMessage()
                    msg_copy.reserved = msg.reserved
                    msg_copy.flags = msg.flags
                    msg_copy.msg_type = msg.msg_type
                    msg_copy.session_id = msg.session_id
                    msg_copy.seq_number = msg.seq_number
                    
                    for avp in msg.avps:
                        if avp.code != AVP_AUTH:
                            msg_copy.add_avp(avp)
                            
                    if not session.crypto_ctx.verify_auth(msg_copy.pack(), auth_avp):
                        self.logger.error("AUTH AVP verification failed for re-auth request")
                        return
                        
                # Extend session lifetime
                session.lifetime = DEFAULT_SESSION_LIFETIME
                session.created_time = time.time()
                
                # Cancel existing cleanup and reschedule
                session.cancel_cleanup()
                session.mark_authenticated()
                session.schedule_cleanup(
                    self.session_mgr.cleanup_authenticated_session,
                    AUTHENTICATED_SESSION_CLEANUP_DELAY
                )
                self.logger.info(f"Rescheduled cleanup for re-authenticated session {session_id:08x}")
                
                # Send PANA-Notification answer with 'A' flag
                answer = PANAMessage()
                answer.flags = FLAG_REAUTH  # Answer with AUTH flag
                answer.msg_type = PANA_NOTIFICATION
                answer.session_id = session_id
                answer.seq_number = msg.seq_number  # RFC 5191 Section 5.2: Answer uses request's seq number
                
                # Add Session-Lifetime AVP
                answer.add_avp(create_avp_uint32(AVP_SESSION_LIFETIME, session.lifetime))
                
                # Add AUTH AVP
                msg_without_auth = answer.pack()
                auth_value = session.crypto_ctx.compute_auth(msg_without_auth)
                answer.add_avp(AVP(AVP_AUTH, 0, auth_value))
                
                self.socket.sendto(answer.pack(), addr)
                # RFC 5191 Section 5.2: Wrap sequence number at 2^32
                session.seq_number = (session.seq_number + 1) % (2**32)
                
                self.logger.info(f"Session {session_id:08x} re-authenticated")
            return
        
        # Check for IP reconfiguration flag
        if msg.flags & FLAG_IP_RECONFIG:
            self.logger.info(f"IP reconfiguration notification received from {addr}")
            
            # Find the old key for this session
            old_key = None
            for existing_key in list(self.session_mgr.sessions.keys()):
                if existing_key[0] == session_id:
                    old_key = existing_key
                    break
            
            new_key = (session_id, addr[0])
            
            if old_key and old_key != new_key:
                # IP address has changed, update session mapping
                self.session_mgr.sessions[new_key] = session
                del self.session_mgr.sessions[old_key]
                self.logger.info(f"Session {session_id} migrated from {old_key[1]} to {addr[0]}")
            
            # 統計情報: IPアドレス変更
            if self.statistics:
                self.statistics.record_error(session_id, 'ip_reconfig', f'IP changed to {addr[0]}')
            
            # Send re-authentication request using PANA-Notification with 'A' flag (RFC 5191 Section 4.3)
            reauth_req = PANAMessage()
            reauth_req.flags = FLAG_REQUEST | FLAG_REAUTH  # Set R and A flags
            reauth_req.msg_type = PANA_NOTIFICATION
            reauth_req.session_id = session_id
            reauth_req.seq_number = session.seq_number
            
            # Start re-authentication
            session.state = PAA_STATE_WAIT_EAP_MSG
            session.start_reauth()
            
            # Send the re-auth request
            self._prepare_and_send_message(reauth_req, session, addr)
            
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
                
                if session.crypto_ctx.pana_auth_key:
                    # RFC 5191: No A-flag needed when adding AUTH AVP
                    msg_without_auth = answer.pack()
                    auth_value = session.crypto_ctx.compute_auth(msg_without_auth)
                    answer.add_avp(AVP(AVP_AUTH, 0, auth_value))
                    
                self.socket.sendto(answer.pack(), addr)
                # RFC 5191 Section 5.2: Wrap sequence number at 2^32
                session.seq_number = (session.seq_number + 1) % (2**32)
            else:
                # Ping response received
                self.retransmit_mgr.remove_message(session.seq_number - 1)
                self.logger.debug(f"Ping response received for session {session_id:08x}")
                
    def handle_termination_msg(self, msg, addr):
        """Handle PANA-Termination message"""
        session_id = msg.session_id
        key = (session_id, addr[0])
        session = self.session_mgr.get_session(key)
        if not session:
            return

        # Update address in case port changed
        session.addr = addr
            
        if msg.is_request():
            # Send termination answer
            answer = PANAMessage()
            answer.flags = 0  # Answer
            answer.msg_type = PANA_TERMINATION
            answer.session_id = session_id
            answer.seq_number = msg.seq_number  # RFC 5191 Section 5.2: Answer uses request's seq number
            
            if session.crypto_ctx.pana_auth_key:
                # RFC 5191: No A-flag needed when adding AUTH AVP
                msg_without_auth = answer.pack()
                auth_value = session.crypto_ctx.compute_auth(msg_without_auth)
                answer.add_avp(AVP(AVP_AUTH, 0, auth_value))
                
            self.socket.sendto(answer.pack(), addr)
            session.seq_number += 1
            
        # Remove session
        self.session_mgr.remove_session(key)
        
        # レート制限からセッションを削除
        if self.rate_limiter:
            self.rate_limiter.remove_session(addr[0])
        
        self.logger.info(f"Session {session_id:08x} terminated")
        
    def run(self):
        """
        PANA認証エージェントのメイン実行ループ
        
        【説明】
        PANAサーバーのメイン処理を実行します。
        UDPポート716（または指定されたポート）でクライアントからの
        メッセージを待機し、適切に処理します。
        
        【メッセージタイプ別の処理】
        - PANA_CLIENT_INITIATION: 新規セッションの開始
        - PANA_AUTH: 認証メッセージの処理
        - PANA_TERMINATION: セッションの終了
        - PANA_NOTIFICATION: Ping/Pongメッセージ
        
        【エラー処理】
        メッセージのパースエラーやネットワークエラーは
        ログに記録して処理を継続します。
        """
        self.logger.info(f"Starting PANA Authentication Agent on {self.bind_addr}:{self.bind_port}")
        
        while self.running:
            try:
                # Use select for timeout handling
                ready = select.select([self.socket], [], [], 1.0)
                if not ready[0]:
                    continue
                    
                data, addr = self.socket.recvfrom(65536)  # 最大フラグメントサイズ対応
                if not data:
                    continue
                
                # DoS攻撃対策: レート制限チェック
                if self.rate_limiter:
                    allowed, reason = self.rate_limiter.check_request(addr[0])
                    if not allowed:
                        self.logger.warning(f"Rate limit exceeded for {addr[0]}: {reason}")
                        continue
                    
                msg = PANAMessage()
                try:
                    msg.unpack(data)
                except ValueError as e:
                    self.logger.error(f"Failed to parse PANA message from {addr}: {e}")
                    continue
                
                # RFC 5191 Section 5.1: PANA does not provide fragmentation
                # Fragmentation support removed for RFC compliance
                # Messages larger than MTU should be handled by IP layer or EAP methods
                
                self.logger.info(f"Received message: type={msg.msg_type}, flags=0x{msg.flags:04x}, seq={msg.seq_number} from {addr}")
                
                # 統計情報: パケット受信
                if self.statistics:
                    self.statistics.record_packet(msg.session_id, 'received', len(data), msg.msg_type)
                
                # リプレイ攻撃のチェック（PCI以外の要求メッセージ）
                if msg.is_request() and msg.msg_type != PANA_CLIENT_INITIATION:
                    key = (msg.session_id, addr[0])
                    session = self.session_mgr.get_session(key)
                    if session:
                        if not session.anti_replay.check_and_update(msg.seq_number):
                            self.logger.warning(f"Replay attack detected! Dropping message with seq={msg.seq_number} from {addr}")
                            continue
                
                if msg.msg_type == PANA_CLIENT_INITIATION:
                    self.handle_pci(msg, addr)
                elif msg.msg_type == PANA_AUTH:
                    self.handle_auth_msg(msg, addr)
                elif msg.msg_type == PANA_TERMINATION:
                    self.handle_termination_msg(msg, addr)
                elif msg.msg_type == PANA_NOTIFICATION:
                    self.handle_notification_msg(msg, addr)
                    
            except socket.error as e:
                # ソケットエラーのハンドリング
                context = create_error_context(
                    ErrorType.SOCKET_ERROR,
                    e,
                    addr=addr if 'addr' in locals() else None
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
                    additional_info={'location': 'main_loop'}
                )
                self.error_recovery.handle_error(context)
                
    def _prepare_and_send_message(self, msg, session, addr):
        """
        メッセージの準備（暗号化含む）と送信
        
        【説明】
        PANAメッセージに必要な暗号化処理とAUTH AVPの追加を行い、
        指定されたクライアントに送信します。
        大きなメッセージは自動的にフラグメント化されます。
        
        引数:
            msg: 送信するPANAMessageオブジェクト
            session: このメッセージに関連するセッション
            addr: 送信先アドレスタプル
        
        【処理フロー】
        1. RFC 6786暗号化が有効な場合、メッセージを暗号化
        2. AUTH AVPが必要かつ未追加の場合、HMAC認証タグを計算して追加
        3. メッセージサイズをチェックし、必要に応じてフラグメント化
        4. メッセージをパックして送信
        5. 要求メッセージの場合は再送信キューに追加
        """
        # RFC 6786: Apply encryption if active
        if session.is_encryption_active():
            self.encryption_helper.prepare_message_with_encryption(msg, session)
        
        # RFC 5191: 鍵が利用可能な場合は常にAUTH AVPを追加
        if session.crypto_ctx.pana_auth_key and not msg.get_avp(AVP_AUTH):
            msg_without_auth = msg.pack()
            auth_value = session.crypto_ctx.compute_auth(msg_without_auth)
            msg.add_avp(AVP(AVP_AUTH, 0, auth_value))
        
        # RFC 5191: Send message without fragmentation
        message_data = msg.pack()
        self.socket.sendto(message_data, addr)
        
        # 統計情報: パケット送信
        if self.statistics:
            self.statistics.record_packet(msg.session_id, 'sent', len(message_data), msg.msg_type)
        
        # 再送信キューに追加
        self.retransmit_mgr.add_message(msg.seq_number, message_data, addr)
        
        # RFC 5191 Section 5.2: Wrap sequence number at 2^32
        session.seq_number = (session.seq_number + 1) % (2**32)
    
    def stop(self):
        """Stop PAA"""
        self.running = False
        self.retransmit_mgr.stop()
        self.session_mgr.stop()
        if self.rate_limiter:
            self.rate_limiter.stop()
        if self.monitor:
            self.monitor.stop()
        if self.statistics:
            self.statistics.stop()
        self.socket.close()