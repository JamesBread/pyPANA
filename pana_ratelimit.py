#!/usr/bin/env python3
"""
PANA Rate Limiting and DoS Protection Module
Implements rate limiting and resource protection mechanisms

【概要】
PANAサーバーをDoS攻撃から保護するためのレート制限モジュール。
クライアントIPごとの接続レート制限、同時セッション数制限、
メモリ使用量監視などの機能を提供します。

【主な機能】
- IPアドレスごとのレート制限
- 同時セッション数の制限
- メモリ使用量の監視
- 自動ブラックリスト管理
"""

import time
import threading
import logging
from collections import defaultdict, deque
from typing import Dict, Optional, Tuple
try:
    import psutil  # メモリ使用量監視用
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class RateLimiter:
    """DoS攻撃から保護するためのレート制限実装
    
    【クラス説明】
    クライアントIPごとの接続レートを制限し、システムリソースを保護します。
    トークンバケット方式を使用してレート制限を実装しています。
    
    Attributes:
        max_requests_per_second: IPあたりの最大リクエスト数/秒
        max_concurrent_sessions: 最大同時セッション数
        memory_threshold: メモリ使用率の閾値（パーセント）
        blacklist_duration: ブラックリスト期間（秒）
    """
    
    def __init__(self, 
                 max_requests_per_second: int = 10,
                 max_concurrent_sessions: int = 1000,
                 memory_threshold: int = 80,
                 blacklist_duration: int = 300):
        """
        レート制限インスタンスを初期化
        
        Args:
            max_requests_per_second: IPあたりの最大リクエスト数/秒（デフォルト: 10）
            max_concurrent_sessions: 最大同時セッション数（デフォルト: 1000）
            memory_threshold: メモリ使用率の閾値％（デフォルト: 80）
            blacklist_duration: ブラックリスト期間（秒）（デフォルト: 300）
        """
        self.max_requests_per_second = max_requests_per_second
        self.max_concurrent_sessions = max_concurrent_sessions
        self.memory_threshold = memory_threshold
        self.blacklist_duration = blacklist_duration
        
        # IPごとのリクエスト履歴
        self.request_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # 現在のセッション数
        self.current_sessions = 0
        self.session_count_by_ip: Dict[str, int] = defaultdict(int)
        
        # ブラックリスト管理
        self.blacklist: Dict[str, float] = {}  # IP -> ブラックリスト終了時刻
        
        # スレッドセーフ用ロック
        self.lock = threading.Lock()
        
        # 統計情報
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'blocked_by_rate': 0,
            'blocked_by_sessions': 0,
            'blocked_by_memory': 0,
            'blacklisted_ips': 0
        }
        
        self.logger = logging.getLogger('RateLimiter')
        
        # クリーンアップスレッドの制御
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        # スレッドの開始を遅延させる（初期化完了後に開始）
        self._cleanup_started = False
    
    def _ensure_cleanup_started(self):
        """クリーンアップスレッドが開始されていることを確認"""
        if not self._cleanup_started:
            try:
                self.cleanup_thread.start()
                self._cleanup_started = True
            except RuntimeError:
                # Thread already started, ignore
                self._cleanup_started = True
    
    def check_request(self, client_ip: str) -> Tuple[bool, Optional[str]]:
        """
        クライアントからのリクエストをチェック
        
        Args:
            client_ip: クライアントのIPアドレス
            
        Returns:
            tuple: (許可フラグ, 拒否理由メッセージ)
                許可の場合: (True, None)
                拒否の場合: (False, 理由メッセージ)
        """
        self._ensure_cleanup_started()
        with self.lock:
            self.stats['total_requests'] += 1
            
            # ブラックリストチェック
            if self._is_blacklisted(client_ip):
                self.stats['blocked_requests'] += 1
                return False, "IP is blacklisted"
            
            # メモリ使用量チェック
            if self._check_memory_usage():
                self.stats['blocked_requests'] += 1
                self.stats['blocked_by_memory'] += 1
                return False, "Server memory threshold exceeded"
            
            # レート制限チェック
            current_time = time.time()
            request_times = self.request_history[client_ip]
            
            # 1秒以内のリクエスト数をカウント
            recent_count = sum(1 for t in request_times if current_time - t < 1.0)
            
            if recent_count >= self.max_requests_per_second:
                self.stats['blocked_requests'] += 1
                self.stats['blocked_by_rate'] += 1
                self._add_to_blacklist(client_ip)
                return False, f"Rate limit exceeded: {recent_count} requests/sec"
            
            # リクエスト履歴に追加
            request_times.append(current_time)
            
            return True, None
    
    def check_new_session(self, client_ip: str) -> Tuple[bool, Optional[str]]:
        """
        新規セッションの作成をチェック
        
        Args:
            client_ip: クライアントのIPアドレス
            
        Returns:
            tuple: (許可フラグ, 拒否理由メッセージ)
        """
        with self.lock:
            # 基本的なリクエストチェック
            allowed, reason = self.check_request(client_ip)
            if not allowed:
                return False, reason
            
            # セッション数制限チェック
            if self.current_sessions >= self.max_concurrent_sessions:
                self.stats['blocked_requests'] += 1
                self.stats['blocked_by_sessions'] += 1
                return False, f"Session limit exceeded: {self.current_sessions}/{self.max_concurrent_sessions}"
            
            # IPごとのセッション数制限（1IPあたり最大10セッション）
            if self.session_count_by_ip[client_ip] >= 10:
                return False, f"Too many sessions from IP: {client_ip}"
            
            return True, None
    
    def add_session(self, client_ip: str):
        """
        新規セッションを追加
        
        Args:
            client_ip: クライアントのIPアドレス
        """
        with self.lock:
            self.current_sessions += 1
            self.session_count_by_ip[client_ip] += 1
            self.logger.debug(f"Session added for {client_ip}. Total: {self.current_sessions}")
    
    def remove_session(self, client_ip: str):
        """
        セッションを削除
        
        Args:
            client_ip: クライアントのIPアドレス
        """
        with self.lock:
            if self.session_count_by_ip[client_ip] > 0:
                self.current_sessions -= 1
                self.session_count_by_ip[client_ip] -= 1
                if self.session_count_by_ip[client_ip] == 0:
                    del self.session_count_by_ip[client_ip]
                self.logger.debug(f"Session removed for {client_ip}. Total: {self.current_sessions}")
    
    def _is_blacklisted(self, client_ip: str) -> bool:
        """
        IPがブラックリストに載っているかチェック
        
        Args:
            client_ip: チェックするIPアドレス
            
        Returns:
            bool: ブラックリストに載っている場合True
        """
        if client_ip in self.blacklist:
            if time.time() < self.blacklist[client_ip]:
                return True
            else:
                # ブラックリスト期間終了
                del self.blacklist[client_ip]
                self.stats['blacklisted_ips'] = len(self.blacklist)
        return False
    
    def _add_to_blacklist(self, client_ip: str):
        """
        IPをブラックリストに追加
        
        Args:
            client_ip: ブラックリストに追加するIP
        """
        self.blacklist[client_ip] = time.time() + self.blacklist_duration
        self.stats['blacklisted_ips'] = len(self.blacklist)
        self.logger.warning(f"IP {client_ip} added to blacklist for {self.blacklist_duration} seconds")
    
    def _check_memory_usage(self) -> bool:
        """
        メモリ使用量をチェック
        
        Returns:
            bool: 閾値を超えている場合True
        """
        if not PSUTIL_AVAILABLE:
            return False
        try:
            memory_percent = psutil.virtual_memory().percent
            return memory_percent > self.memory_threshold
        except:
            # psutilが利用できない場合は制限しない
            return False
    
    def _cleanup_loop(self):
        """
        定期的なクリーンアップを実行するループ
        """
        while self.running:
            time.sleep(1)  # 1秒ごとに実行（テストのため短縮）
            
            with self.lock:
                # 古いリクエスト履歴をクリーンアップ
                current_time = time.time()
                for ip, times in list(self.request_history.items()):
                    # 10秒以上古いエントリを削除
                    while times and current_time - times[0] > 10:
                        times.popleft()
                    # 空になったらエントリ自体を削除
                    if not times:
                        del self.request_history[ip]
                
                # 期限切れのブラックリストエントリを削除
                expired_ips = [
                    ip for ip, expire_time in self.blacklist.items()
                    if current_time > expire_time
                ]
                for ip in expired_ips:
                    del self.blacklist[ip]
                
                self.stats['blacklisted_ips'] = len(self.blacklist)
    
    def get_stats(self) -> dict:
        """
        統計情報を取得
        
        Returns:
            dict: 統計情報の辞書
        """
        with self.lock:
            return {
                **self.stats,
                'current_sessions': self.current_sessions,
                'unique_ips': len(self.session_count_by_ip),
                'memory_usage': psutil.virtual_memory().percent if PSUTIL_AVAILABLE else 0
            }
    
    def stop(self):
        """
        レート制限を停止（クリーンアップスレッドを終了）
        """
        self.running = False
    
    def reset_stats(self):
        """
        統計情報をリセット
        """
        with self.lock:
            self.stats = {
                'total_requests': 0,
                'blocked_requests': 0,
                'blocked_by_rate': 0,
                'blocked_by_sessions': 0,
                'blocked_by_memory': 0,
                'blacklisted_ips': len(self.blacklist)
            }