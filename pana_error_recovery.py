#!/usr/bin/env python3
"""
PANA Error Recovery Module
Centralized error handling and recovery mechanisms

【概要】
このモジュールはPANAプロトコルの実装で発生する様々なエラーに対して、
統一的なエラーハンドリングとリカバリ機能を提供します。

【主な機能】
- ソケットエラーのハンドリング
- 認証失敗時のクリーンアップ
- TLSハンドシェイクエラーのリカバリ
- セッション状態の一貫性維持
- エラー統計の収集
"""

import socket
import ssl
import logging
import time
import threading
from enum import Enum
from typing import Optional, Callable, Dict, Any


class ErrorType(Enum):
    """エラータイプの定義"""
    SOCKET_ERROR = "socket_error"
    AUTH_FAILURE = "auth_failure"
    TLS_ERROR = "tls_error"
    SESSION_ERROR = "session_error"
    TIMEOUT_ERROR = "timeout_error"
    PROTOCOL_ERROR = "protocol_error"
    RESOURCE_ERROR = "resource_error"


class RecoveryAction(Enum):
    """リカバリアクションの定義"""
    RETRY = "retry"
    CLEANUP = "cleanup"
    RESET = "reset"
    IGNORE = "ignore"
    ESCALATE = "escalate"


class ErrorContext:
    """エラーコンテキスト情報"""
    def __init__(self, error_type: ErrorType, error: Exception, 
                 session_id: Optional[int] = None, addr: Optional[tuple] = None,
                 additional_info: Optional[Dict[str, Any]] = None):
        self.error_type = error_type
        self.error = error
        self.session_id = session_id
        self.addr = addr
        self.timestamp = time.time()
        self.additional_info = additional_info or {}
        self.retry_count = 0


class ErrorRecovery:
    """
    集中エラーリカバリメカニズム
    
    【クラス説明】
    PANAプロトコル実装全体で発生するエラーを統一的に処理し、
    適切なリカバリアクションを実行します。
    """
    
    def __init__(self, session_manager=None, retransmit_manager=None):
        """
        エラーリカバリの初期化
        
        Args:
            session_manager: SessionManagerインスタンス（オプション）
            retransmit_manager: RetransmissionManagerインスタンス（オプション）
        """
        self.session_mgr = session_manager
        self.retransmit_mgr = retransmit_manager
        self.logger = logging.getLogger('ErrorRecovery')
        
        # エラー統計
        self.error_stats = {error_type: 0 for error_type in ErrorType}
        self.recovery_stats = {action: 0 for action in RecoveryAction}
        
        # エラーハンドラのレジストリ
        self.error_handlers: Dict[ErrorType, Callable] = {
            ErrorType.SOCKET_ERROR: self._handle_socket_error,
            ErrorType.AUTH_FAILURE: self._handle_auth_failure,
            ErrorType.TLS_ERROR: self._handle_tls_error,
            ErrorType.SESSION_ERROR: self._handle_session_error,
            ErrorType.TIMEOUT_ERROR: self._handle_timeout_error,
            ErrorType.PROTOCOL_ERROR: self._handle_protocol_error,
            ErrorType.RESOURCE_ERROR: self._handle_resource_error,
        }
        
        # リトライポリシー
        self.max_retries = 3
        self.retry_delay = 1.0  # 初期リトライ遅延（秒）
        self.retry_backoff = 2.0  # 指数バックオフ係数
        
        self.lock = threading.Lock()
    
    def handle_error(self, context: ErrorContext) -> RecoveryAction:
        """
        エラーを処理し、適切なリカバリアクションを決定
        
        Args:
            context: エラーコンテキスト情報
            
        Returns:
            実行すべきリカバリアクション
        """
        with self.lock:
            # エラー統計を更新
            self.error_stats[context.error_type] += 1
            
            # エラータイプに応じたハンドラを呼び出し
            handler = self.error_handlers.get(context.error_type)
            if handler:
                action = handler(context)
            else:
                self.logger.error(f"No handler for error type: {context.error_type}")
                action = RecoveryAction.ESCALATE
            
            # リカバリアクション統計を更新
            self.recovery_stats[action] += 1
            
            self.logger.info(f"Error handled: {context.error_type.value} -> {action.value}")
            return action
    
    def _handle_socket_error(self, context: ErrorContext) -> RecoveryAction:
        """
        ソケット関連エラーのハンドリング
        
        【処理内容】
        - タイムアウト: リトライ
        - 接続拒否: クリーンアップ
        - その他: エスカレーション
        """
        error = context.error
        
        if isinstance(error, socket.timeout):
            # タイムアウトの場合はリトライ
            if context.retry_count < self.max_retries:
                context.retry_count += 1
                self.logger.info(f"Socket timeout, retry {context.retry_count}/{self.max_retries}")
                return RecoveryAction.RETRY
            else:
                self.logger.warning("Max retries reached for socket timeout")
                return RecoveryAction.CLEANUP
                
        elif isinstance(error, ConnectionRefusedError):
            # 接続拒否の場合はクリーンアップ
            self.logger.error("Connection refused, cleaning up")
            return RecoveryAction.CLEANUP
            
        elif isinstance(error, OSError):
            # その他のOSエラー
            if error.errno == 48:  # Address already in use
                self.logger.error("Address already in use")
                return RecoveryAction.ESCALATE
            else:
                self.logger.error(f"OS error: {error}")
                return RecoveryAction.CLEANUP
                
        else:
            # 未知のソケットエラー
            self.logger.error(f"Unknown socket error: {error}")
            return RecoveryAction.ESCALATE
    
    def _handle_auth_failure(self, context: ErrorContext) -> RecoveryAction:
        """
        認証失敗時のハンドリング
        
        【処理内容】
        - セッションのクリーンアップ
        - リソースの解放
        - 統計情報の記録
        """
        self.logger.warning(f"Authentication failed for session {context.session_id}")
        
        # セッションをクリーンアップ
        if self.session_mgr and context.session_id:
            key = (context.session_id, context.addr[0] if context.addr else None)
            self.session_mgr.remove_session(key)
        
        # 再送信キューをクリア
        if self.retransmit_mgr and context.addr:
            self.retransmit_mgr.clear_messages_for_address(context.addr)
        
        return RecoveryAction.CLEANUP
    
    def _handle_tls_error(self, context: ErrorContext) -> RecoveryAction:
        """
        TLSエラーのハンドリング
        
        【処理内容】
        - ハンドシェイクエラー: リセット
        - 証明書エラー: エスカレーション
        - その他: クリーンアップ
        """
        error = context.error
        
        if isinstance(error, ssl.SSLError):
            error_str = str(error).lower()
            
            if "handshake" in error_str:
                # ハンドシェイクエラーはリセット
                self.logger.error("TLS handshake error, resetting")
                return RecoveryAction.RESET
                
            elif "certificate" in error_str:
                # 証明書エラーはエスカレーション
                self.logger.error("TLS certificate error")
                return RecoveryAction.ESCALATE
                
            else:
                # その他のSSLエラー
                self.logger.error(f"TLS error: {error}")
                return RecoveryAction.CLEANUP
        else:
            # SSL以外のTLS関連エラー
            self.logger.error(f"Non-SSL TLS error: {error}")
            return RecoveryAction.CLEANUP
    
    def _handle_session_error(self, context: ErrorContext) -> RecoveryAction:
        """
        セッションエラーのハンドリング
        
        【処理内容】
        - 不正な状態遷移: リセット
        - セッション期限切れ: クリーンアップ
        - その他: ログして継続
        """
        error_info = context.additional_info
        
        if error_info.get('type') == 'invalid_state':
            # 不正な状態遷移
            self.logger.error(f"Invalid state transition for session {context.session_id}")
            return RecoveryAction.RESET
            
        elif error_info.get('type') == 'expired':
            # セッション期限切れ
            self.logger.info(f"Session {context.session_id} expired")
            return RecoveryAction.CLEANUP
            
        else:
            # その他のセッションエラー
            self.logger.warning(f"Session error: {context.error}")
            return RecoveryAction.IGNORE
    
    def _handle_timeout_error(self, context: ErrorContext) -> RecoveryAction:
        """
        タイムアウトエラーのハンドリング
        
        【処理内容】
        - リトライ可能な場合: リトライ
        - リトライ上限到達: クリーンアップ
        """
        if context.retry_count < self.max_retries:
            context.retry_count += 1
            delay = self.retry_delay * (self.retry_backoff ** (context.retry_count - 1))
            self.logger.info(f"Timeout, retry {context.retry_count}/{self.max_retries} after {delay:.1f}s")
            time.sleep(delay)
            return RecoveryAction.RETRY
        else:
            self.logger.warning("Max retries reached for timeout")
            return RecoveryAction.CLEANUP
    
    def _handle_protocol_error(self, context: ErrorContext) -> RecoveryAction:
        """
        プロトコルエラーのハンドリング
        
        【処理内容】
        - 不正なメッセージ: ログして無視
        - プロトコル違反: エスカレーション
        """
        error_info = context.additional_info
        
        if error_info.get('type') == 'invalid_message':
            # 不正なメッセージは無視
            self.logger.warning(f"Invalid message from {context.addr}")
            return RecoveryAction.IGNORE
            
        elif error_info.get('type') == 'protocol_violation':
            # プロトコル違反はエスカレーション
            self.logger.error(f"Protocol violation: {context.error}")
            return RecoveryAction.ESCALATE
            
        else:
            # その他のプロトコルエラー
            self.logger.error(f"Protocol error: {context.error}")
            return RecoveryAction.CLEANUP
    
    def _handle_resource_error(self, context: ErrorContext) -> RecoveryAction:
        """
        リソースエラーのハンドリング
        
        【処理内容】
        - メモリ不足: エスカレーション
        - ファイルハンドル枯渇: クリーンアップ後リトライ
        """
        error = context.error
        
        if isinstance(error, MemoryError):
            # メモリ不足は深刻
            self.logger.critical("Memory exhausted")
            return RecoveryAction.ESCALATE
            
        elif isinstance(error, OSError) and "Too many open files" in str(error):
            # ファイルハンドル枯渇
            self.logger.error("Too many open files, cleaning up")
            return RecoveryAction.CLEANUP
            
        else:
            # その他のリソースエラー
            self.logger.error(f"Resource error: {error}")
            return RecoveryAction.CLEANUP
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        エラーとリカバリの統計情報を取得
        
        Returns:
            統計情報の辞書
        """
        with self.lock:
            return {
                'error_counts': dict(self.error_stats),
                'recovery_counts': dict(self.recovery_stats),
                'total_errors': sum(self.error_stats.values()),
                'total_recoveries': sum(self.recovery_stats.values())
            }
    
    def reset_statistics(self):
        """統計情報をリセット"""
        with self.lock:
            self.error_stats = {error_type: 0 for error_type in ErrorType}
            self.recovery_stats = {action: 0 for action in RecoveryAction}
            self.logger.info("Error recovery statistics reset")


def create_error_context(error_type: ErrorType, error: Exception, **kwargs) -> ErrorContext:
    """
    エラーコンテキストを作成するヘルパー関数
    
    Args:
        error_type: エラータイプ
        error: 発生した例外
        **kwargs: 追加のコンテキスト情報
        
    Returns:
        ErrorContextインスタンス
    """
    return ErrorContext(
        error_type=error_type,
        error=error,
        session_id=kwargs.get('session_id'),
        addr=kwargs.get('addr'),
        additional_info=kwargs.get('additional_info', {})
    )