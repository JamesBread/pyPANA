#!/usr/bin/env python3
"""
PANA Session Management
Session lifecycle and state management

【概要】
このモジュールはPANAプロトコルのセッション管理機能を提供します。
セッションの生成、ライフサイクル管理、状態管理を行います。

【主な機能】
- セッションの作成と管理
- セッション有効期限の管理
- 状態遷移の追跡
- 暗号化コンテキストの管理
- 期限切れセッションの自動クリーンアップ
"""

import time
import threading
import logging
import secrets
from pana_constants import DEFAULT_SESSION_LIFETIME, SESSION_CLEANUP_INTERVAL, PAA_STATE_INITIAL
from pana_crypto import CryptoContext
from eap_tls import EAPTLSHandler
from pana_encryption_policy import EncryptionContext
from pana_antireplay import AntiReplay


class PANASession:
    """PANA Session with lifetime management
    
    【クラス説明】
    PANAセッションを表現するクラス。各セッションはクライアントとの
    認証状態、暗号化コンテキスト、有効期限などを管理します。
    
    【ライフサイクル】
    作成 -> 認証中 -> アクティブ -> 期限切れ/終了
    """
    def __init__(self, session_id, addr, encryption_policy=None):
        """
        セッションの初期化
        
        引数:
            session_id: セッション識別子（32ビット）
            addr: クライアントのアドレスタプル (IP, port)
            encryption_policy: RFC6786暗号化ポリシー（オプション）
        """
        self.session_id = session_id  # セッションID
        self.addr = addr              # クライアントアドレス
        self.crypto_ctx = CryptoContext()  # 暗号化コンテキスト
        self.eap_handler = None       # EAPハンドラ
        # RFC 5191 Section 5.2: Random initial sequence number
        self.seq_number = secrets.randbelow(2**32)  # Random ISN
        self.created_time = time.time()    # 作成時刻
        self.last_activity = time.time()   # 最終アクティビティ時刻
        self.lifetime = DEFAULT_SESSION_LIFETIME  # セッション有効期間（秒）
        self.state = PAA_STATE_INITIAL  # 初期状態（RFC5191ステートマシン）
        self.lock = threading.Lock()    # スレッドセーフ用ロック
        self.radius_state = None        # RADIUSサーバー用の状態
        self.eap_identifier = 0         # EAP識別子
        
        # RFC 6786 暗号化サポート
        self.encryption_context = EncryptionContext(encryption_policy)
        
        # リプレイ攻撃対策
        self.anti_replay = AntiReplay(window_size=32)
        
        # 認証後のクリーンアップ用タイマー
        self.cleanup_timer = None
        self.authenticated_time = None  # 認証完了時刻
        
    def update_activity(self):
        """
        最終アクティビティ時刻を更新
        
        【説明】
        セッションの最終アクティビティ時刻を現在時刻に更新します。
        これにより、セッションがアクティブであることを示します。
        """
        self.last_activity = time.time()
        
    def is_expired(self):
        """
        セッションが期限切れかどうかをチェック
        
        戻り値:
            True: 期限切れ
            False: 有効
        """
        return (time.time() - self.created_time) > self.lifetime
        
    def remaining_lifetime(self):
        """
        残りのセッション有効時間を取得（秒単位）
        
        戻り値:
            残り時間（秒）。すでに期限切れの場合は0
        """
        elapsed = time.time() - self.created_time
        return max(0, self.lifetime - elapsed)
        
    def set_eap_handler(self, handler):
        """
        EAPハンドラを設定
        
        引数:
            handler: EAPTLSHandlerインスタンスまたはNone（RADIUSモードの場合）
        """
        self.eap_handler = handler
        
    def cleanup(self):
        """
        セッションリソースのクリーンアップ
        
        【説明】
        セッションが使用していたリソースを解放します。
        特にEAPハンドラのTLS接続などをクリーンアップします。
        """
        if self.eap_handler:
            self.eap_handler.cleanup()
        
        # クリーンアップタイマーをキャンセル
        self.cancel_cleanup()
    
    def negotiate_encryption(self, peer_algorithm):
        """Negotiate encryption algorithm with peer
        
        【説明】
        ピアが提案した暗号化アルゴリズムとのネゴシエーションを行います。
        RFC6786に基づいて、両端でサポートされるアルゴリズムを選択します。
        
        Args:
            peer_algorithm: Algorithm ID proposed by peer
            
        Returns:
            bool: True if negotiation successful
            
        引数:
            peer_algorithm: ピアが提案するアルゴリズムID（例: 1 = AES128_CTR）
            
        戻り値:
            True: ネゴシエーション成功（アルゴリズムが合意された）
            False: ネゴシエーション失敗（サポートされないアルゴリズム）
        """
        return self.encryption_context.negotiate_encryption(peer_algorithm)
    
    def is_encryption_active(self):
        """Check if encryption is active for this session
        
        【説明】
        このセッションで暗号化が有効かどうかを確認します。
        暗号化アルゴリズムがネゴシエーションされ、合意された場合にTrueを返します。
        
        戻り値:
            True: 暗号化が有効
            False: 暗号化が無効（平文通信）
        """
        return self.encryption_context.is_encryption_active()
    
    def start_reauth(self):
        """
        再認証プロセスを開始
        
        【説明】
        IPアドレス変更や定期的な再認証のためのプロセスを開始します。
        EAPハンドラをリセットし、新しい認証ラウンドを準備します。
        """
        if self.eap_handler:
            # EAPハンドラをリセット
            self.eap_handler.cleanup()
            self.eap_handler = None
            
        # 新しいEAPハンドラを作成
        if hasattr(self, 'is_standalone') and self.is_standalone:
            from eap_tls import EAPTLSHandler
            self.eap_handler = EAPTLSHandler(is_server=True)
    
    def get_encryption_algorithm(self):
        """Get negotiated encryption algorithm
        
        【説明】
        ネゴシエーションで合意された暗号化アルゴリズムIDを取得します。
        
        戻り値:
            アルゴリズムID（整数）またはNone（暗号化なしの場合）
            例: 1 = AES128_CTR
        """
        return self.encryption_context.get_negotiated_algorithm()
    
    def mark_authenticated(self):
        """
        セッションを認証済みとしてマーク
        
        【説明】
        認証が成功した際に呼び出され、認証完了時刻を記録します。
        この時刻は後のクリーンアップ処理で使用されます。
        """
        self.authenticated_time = time.time()
        self.update_activity()
    
    def schedule_cleanup(self, cleanup_callback, cleanup_delay=None):
        """
        認証後のセッションクリーンアップをスケジュール
        
        【説明】
        認証が完了したセッションを一定時間後に自動的にクリーンアップします。
        これにより、アイドル状態の認証済みセッションが蓄積されることを防ぎます。
        
        引数:
            cleanup_callback: クリーンアップ時に呼び出されるコールバック関数
            cleanup_delay: クリーンアップまでの遅延時間（秒）。Noneの場合はlifetimeを使用
        """
        if self.cleanup_timer:
            self.cleanup_timer.cancel()
        
        delay = cleanup_delay if cleanup_delay is not None else self.lifetime
        self.cleanup_timer = threading.Timer(delay, cleanup_callback, args=[self])
        self.cleanup_timer.daemon = True
        self.cleanup_timer.start()
    
    def cancel_cleanup(self):
        """
        スケジュールされたクリーンアップをキャンセル
        
        【説明】
        再認証やセッション延長時に、既存のクリーンアップタイマーを
        キャンセルします。
        """
        if self.cleanup_timer:
            self.cleanup_timer.cancel()
            self.cleanup_timer = None


class SessionManager:
    """Manages PANA sessions with lifetime control
    
    【クラス説明】
    複数のPANAセッションを管理するマネージャークラス。
    セッションの作成、検索、削除、有効期限管理を行います。
    
    【主な機能】
    - セッションの一元管理（セッションID + IPアドレスでの識別）
    - 期限切れセッションの自動クリーンアップ
    - スレッドセーフな操作
    - RFC6786暗号化ポリシーの適用
    """
    def __init__(self, encryption_policy=None):
        """
        セッションマネージャーの初期化
        
        引数:
            encryption_policy: RFC6786暗号化ポリシー（オプション）
        """
        # セッションの格納用辞書
        # キー: (session_id, ip) のタプル
        # 値: PANASessionインスタンス
        self.sessions = {}
        self.lock = threading.Lock()  # スレッドセーフ用ロック
        self.running = True           # 実行フラグ
        
        # バックグラウンドでの期限切れセッションクリーンアップスレッド
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop)
        self.cleanup_thread.daemon = True  # デーモンスレッドとして実行
        self.cleanup_thread.start()
        
        self.logger = logging.getLogger('SessionManager')
        
        # RFC 6786 暗号化ポリシー
        self.encryption_policy = encryption_policy

    def create_session(self, key, addr):
        """Create new session
        
        【説明】
        新しいPANAセッションを作成し、管理下に追加します。
        同じキーのセッションが既に存在する場合は上書きされます。
        
        Parameters
        ----------
        key : tuple
            Tuple of (session_id, ip)
        addr : tuple
            Full client address (ip, port)
            
        引数:
            key: (session_id, ip) のタプル。セッションの一意識別子
            addr: クライアントの完全なアドレス (ip, port)
            
        戻り値:
            作成されたPANASessionインスタンス
        """
        session_id, _ = key
        with self.lock:
            # 新しいセッションを作成（暗号化ポリシーを継承）
            session = PANASession(session_id, addr, self.encryption_policy)
            self.sessions[key] = session
            self.logger.info(f"Created session {session_id:08x} for {addr}")
            return session

    def get_session(self, key):
        """Get session by ID and IP
        
        【説明】
        指定されたキーに対応するセッションを取得します。
        セッションが存在し、有効期限内の場合のみ返されます。
        取得時に最終アクティビティ時刻が更新されます。
        
        引数:
            key: (session_id, ip) のタプル
            
        戻り値:
            PANASessionインスタンス（有効な場合）
            None（セッションが存在しないか期限切れの場合）
        """
        with self.lock:
            session = self.sessions.get(key)
            if session and not session.is_expired():
                session.update_activity()  # アクティビティを更新
                return session
            return None

    def remove_session(self, key):
        """Remove session
        
        【説明】
        指定されたセッションを管理から削除します。
        削除前にセッションのクリーンアップを実行します。
        
        引数:
            key: (session_id, ip) のタプル
        """
        with self.lock:
            if key in self.sessions:
                session = self.sessions[key]
                session.cleanup()  # リソースをクリーンアップ
                del self.sessions[key]
                session_id, _ = key
                self.logger.info(f"Removed session {session_id:08x}")
                
    def update_session_address(self, key, new_addr):
        """Update session address (for port changes)
        
        【説明】
        セッションのクライアントアドレスを更新します。
        クライアントのポート番号が変更された場合に使用されます。
        （NATトラバーサルやポート再割り当て時など）
        
        引数:
            key: (session_id, ip) のタプル
            new_addr: 新しいクライアントアドレス (ip, port)
        """
        with self.lock:
            session = self.sessions.get(key)
            if session:
                session.addr = new_addr
                session.update_activity()  # アクティビティも更新
                
    def get_all_sessions(self):
        """Get all active sessions
        
        【説明】
        現在管理されているすべてのセッションのリストを取得します。
        デバッグや統計情報の取得に使用されます。
        
        戻り値:
            PANASessionインスタンスのリスト
        """
        with self.lock:
            return list(self.sessions.values())
            
    def get_session_count(self):
        """Get count of active sessions
        
        【説明】
        現在管理されているセッション数を取得します。
        
        戻り値:
            アクティブなセッション数（整数）
        """
        with self.lock:
            return len(self.sessions)
                
    def _cleanup_loop(self):
        """Background thread to clean up expired sessions
        
        【説明】
        バックグラウンドスレッドで期限切れセッションを定期的にクリーンアップします。
        SESSION_CLEANUP_INTERVAL（デフォルト60秒）ごとにチェックを実行します。
        
        【処理フロー】
        1. 一定間隔でセッションリストをチェック
        2. 期限切れセッションを特定
        3. 期限切れセッションのクリーンアップと削除
        """
        while self.running:
            time.sleep(SESSION_CLEANUP_INTERVAL)  # 60秒ごとにチェック
            with self.lock:
                # 期限切れセッションを収集
                expired_sessions = []
                for key, session in self.sessions.items():
                    if session.is_expired():
                        expired_sessions.append(key)

                # 期限切れセッションを削除
                for key in expired_sessions:
                    session_id, _ = key
                    self.logger.info(f"Removing expired session {session_id:08x}")
                    session = self.sessions[key]
                    session.cleanup()  # リソースをクリーンアップ
                    del self.sessions[key]
                    
    def cleanup_authenticated_session(self, session):
        """
        認証済みセッションのクリーンアップコールバック
        
        【説明】
        認証後の一定時間が経過したセッションを自動的にクリーンアップします。
        このメソッドはタイマーから呼び出されます。
        
        引数:
            session: クリーンアップ対象のPANASessionインスタンス
        """
        # セッションキーを構築
        key = (session.session_id, session.addr[0])
        
        with self.lock:
            if key in self.sessions:
                # セッションがまだ存在し、認証済みの場合のみクリーンアップ
                if session.authenticated_time:
                    elapsed = time.time() - session.authenticated_time
                    self.logger.info(f"Cleaning up authenticated session {session.session_id:08x} "
                                   f"after {elapsed:.1f} seconds")
                    session.cleanup()
                    del self.sessions[key]
    
    def stop(self):
        """Stop session manager
        
        【説明】
        セッションマネージャーを停止し、すべてのリソースを解放します。
        
        【処理内容】
        1. クリーンアップスレッドの停止
        2. すべてのセッションのクリーンアップ
        3. セッションリストのクリア
        """
        self.running = False  # 実行フラグをクリア
        self.cleanup_thread.join()  # クリーンアップスレッドの終了を待機
        
        # すべてのセッションをクリーンアップ
        with self.lock:
            for session in self.sessions.values():
                session.cleanup()  # 各セッションのリソースを解放
            self.sessions.clear()  # セッションリストをクリア
            self.logger.info("Session manager stopped, all sessions cleared")