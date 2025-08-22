#!/usr/bin/env python3
"""
PANA Statistics Collection
Provides statistics collection and monitoring for PANA protocol

【概要】
このモジュールはPANAプロトコルの統計情報を収集し、
性能分析やデバッグに役立つ情報を提供します。

【主な機能】
- 認証成功/失敗カウンター
- 平均認証時間の計算
- エラー統計の収集
- セッション統計
- パケット統計
"""

import time
import threading
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple


class SessionStatistics:
    """個別セッションの統計情報
    
    【クラス説明】
    1つのPANAセッションに関する統計情報を管理します。
    """
    
    def __init__(self, session_id: int):
        """
        初期化
        
        Args:
            session_id: セッションID
        """
        self.session_id = session_id
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.auth_start_time: Optional[float] = None
        self.auth_end_time: Optional[float] = None
        self.auth_result: Optional[str] = None  # 'success', 'failure', 'timeout'
        self.eap_round_trips = 0
        self.retransmissions = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.packets_sent = 0
        self.packets_received = 0
        self.errors = []
        
    def get_duration(self) -> float:
        """セッション継続時間を取得（秒）"""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
        
    def get_auth_duration(self) -> Optional[float]:
        """認証処理時間を取得（秒）"""
        if self.auth_start_time and self.auth_end_time:
            return self.auth_end_time - self.auth_start_time
        return None
        
    def complete_session(self):
        """セッション終了時の処理"""
        self.end_time = time.time()
        
    def start_authentication(self):
        """認証開始時の処理"""
        self.auth_start_time = time.time()
        
    def complete_authentication(self, result: str):
        """
        認証完了時の処理
        
        Args:
            result: 認証結果 ('success', 'failure', 'timeout')
        """
        self.auth_end_time = time.time()
        self.auth_result = result
        
    def add_packet_sent(self, size: int):
        """送信パケットの記録"""
        self.packets_sent += 1
        self.bytes_sent += size
        
    def add_packet_received(self, size: int):
        """受信パケットの記録"""
        self.packets_received += 1
        self.bytes_received += size
        
    def add_retransmission(self):
        """再送信の記録"""
        self.retransmissions += 1
        
    def add_eap_round_trip(self):
        """EAPラウンドトリップの記録"""
        self.eap_round_trips += 1
        
    def add_error(self, error_type: str, error_msg: str):
        """エラーの記録"""
        self.errors.append({
            'timestamp': time.time(),
            'type': error_type,
            'message': error_msg
        })


class PANAStatistics:
    """PANA統計情報収集クラス
    
    【クラス説明】
    PANAプロトコル全体の統計情報を収集・管理します。
    スレッドセーフな実装で、同時アクセスに対応しています。
    """
    
    def __init__(self, retention_period: int = 3600):
        """
        初期化
        
        Args:
            retention_period: 統計情報の保持期間（秒、デフォルト1時間）
        """
        self.retention_period = retention_period
        self.lock = threading.Lock()
        self.logger = logging.getLogger('PANAStatistics')
        
        # グローバル統計
        self.start_time = time.time()
        self.total_sessions = 0
        self.active_sessions = 0
        self.successful_auths = 0
        self.failed_auths = 0
        self.timeout_auths = 0
        self.total_packets_sent = 0
        self.total_packets_received = 0
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.total_retransmissions = 0
        
        # エラー統計
        self.error_counts = defaultdict(int)
        
        # メッセージタイプ別統計
        self.message_type_counts = defaultdict(int)
        
        # セッション別統計
        self.sessions: Dict[int, SessionStatistics] = {}
        self.completed_sessions: List[SessionStatistics] = []
        
        # 時間帯別統計（1分ごと）
        self.time_series_stats = defaultdict(lambda: {
            'sessions_started': 0,
            'sessions_completed': 0,
            'auth_successes': 0,
            'auth_failures': 0,
            'packets_sent': 0,
            'packets_received': 0
        })
        
        # クリーンアップスレッドの開始
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_old_data)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        
    def start_session(self, session_id: int) -> SessionStatistics:
        """
        新規セッションの開始
        
        Args:
            session_id: セッションID
            
        Returns:
            SessionStatistics: セッション統計オブジェクト
        """
        with self.lock:
            self.total_sessions += 1
            self.active_sessions += 1
            
            session_stats = SessionStatistics(session_id)
            self.sessions[session_id] = session_stats
            
            # 時間帯別統計の更新
            time_bucket = self._get_time_bucket()
            self.time_series_stats[time_bucket]['sessions_started'] += 1
            
            return session_stats
            
    def end_session(self, session_id: int):
        """セッションの終了"""
        with self.lock:
            if session_id in self.sessions:
                session_stats = self.sessions[session_id]
                session_stats.complete_session()
                
                self.active_sessions -= 1
                self.completed_sessions.append(session_stats)
                del self.sessions[session_id]
                
                # 時間帯別統計の更新
                time_bucket = self._get_time_bucket()
                self.time_series_stats[time_bucket]['sessions_completed'] += 1
                
    def record_auth_result(self, session_id: int, result: str):
        """
        認証結果の記録
        
        Args:
            session_id: セッションID
            result: 認証結果 ('success', 'failure', 'timeout')
        """
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id].complete_authentication(result)
                
            # グローバル統計の更新
            if result == 'success':
                self.successful_auths += 1
            elif result == 'failure':
                self.failed_auths += 1
            elif result == 'timeout':
                self.timeout_auths += 1
                
            # 時間帯別統計の更新
            time_bucket = self._get_time_bucket()
            if result == 'success':
                self.time_series_stats[time_bucket]['auth_successes'] += 1
            else:
                self.time_series_stats[time_bucket]['auth_failures'] += 1
                
    def record_packet(self, session_id: int, direction: str, size: int, msg_type: int):
        """
        パケットの記録
        
        Args:
            session_id: セッションID
            direction: 'sent' または 'received'
            size: パケットサイズ（バイト）
            msg_type: メッセージタイプ
        """
        with self.lock:
            # セッション統計の更新
            if session_id in self.sessions:
                if direction == 'sent':
                    self.sessions[session_id].add_packet_sent(size)
                else:
                    self.sessions[session_id].add_packet_received(size)
                    
            # グローバル統計の更新
            if direction == 'sent':
                self.total_packets_sent += 1
                self.total_bytes_sent += size
            else:
                self.total_packets_received += 1
                self.total_bytes_received += size
                
            # メッセージタイプ別統計
            self.message_type_counts[msg_type] += 1
            
            # 時間帯別統計の更新
            time_bucket = self._get_time_bucket()
            if direction == 'sent':
                self.time_series_stats[time_bucket]['packets_sent'] += 1
            else:
                self.time_series_stats[time_bucket]['packets_received'] += 1
                
    def record_retransmission(self, session_id: int):
        """再送信の記録"""
        with self.lock:
            self.total_retransmissions += 1
            if session_id in self.sessions:
                self.sessions[session_id].add_retransmission()
                
    def record_error(self, session_id: Optional[int], error_type: str, error_msg: str):
        """
        エラーの記録
        
        Args:
            session_id: セッションID（Noneの場合はグローバルエラー）
            error_type: エラータイプ
            error_msg: エラーメッセージ
        """
        with self.lock:
            self.error_counts[error_type] += 1
            
            if session_id and session_id in self.sessions:
                self.sessions[session_id].add_error(error_type, error_msg)
                
    def get_summary(self) -> Dict:
        """
        統計サマリーの取得
        
        Returns:
            統計情報の辞書
        """
        with self.lock:
            uptime = time.time() - self.start_time
            
            # 平均認証時間の計算
            auth_times = []
            for session in self.completed_sessions:
                auth_time = session.get_auth_duration()
                if auth_time:
                    auth_times.append(auth_time)
                    
            avg_auth_time = sum(auth_times) / len(auth_times) if auth_times else 0
            
            # 成功率の計算
            total_auths = self.successful_auths + self.failed_auths + self.timeout_auths
            success_rate = (self.successful_auths / total_auths * 100) if total_auths > 0 else 0
            
            return {
                'uptime_seconds': uptime,
                'uptime_str': str(timedelta(seconds=int(uptime))),
                'total_sessions': self.total_sessions,
                'active_sessions': self.active_sessions,
                'authentication': {
                    'total': total_auths,
                    'successful': self.successful_auths,
                    'failed': self.failed_auths,
                    'timeout': self.timeout_auths,
                    'success_rate': success_rate,
                    'average_time': avg_auth_time
                },
                'packets': {
                    'sent': self.total_packets_sent,
                    'received': self.total_packets_received,
                    'retransmissions': self.total_retransmissions
                },
                'bytes': {
                    'sent': self.total_bytes_sent,
                    'received': self.total_bytes_received
                },
                'errors': dict(self.error_counts),
                'message_types': dict(self.message_type_counts)
            }
            
    def get_time_series(self, minutes: int = 60) -> List[Dict]:
        """
        時系列統計の取得
        
        Args:
            minutes: 取得する分数（デフォルト60分）
            
        Returns:
            時系列統計のリスト
        """
        with self.lock:
            current_time = time.time()
            start_time = current_time - (minutes * 60)
            
            result = []
            for bucket, stats in sorted(self.time_series_stats.items()):
                if bucket >= start_time:
                    result.append({
                        'timestamp': bucket,
                        'datetime': datetime.fromtimestamp(bucket).isoformat(),
                        **stats
                    })
                    
            return result
            
    def get_session_details(self, session_id: int) -> Optional[Dict]:
        """
        特定セッションの詳細統計を取得
        
        Args:
            session_id: セッションID
            
        Returns:
            セッション統計の辞書、またはNone
        """
        with self.lock:
            session = None
            
            # アクティブセッションから検索
            if session_id in self.sessions:
                session = self.sessions[session_id]
            else:
                # 完了済みセッションから検索
                for s in self.completed_sessions:
                    if s.session_id == session_id:
                        session = s
                        break
                        
            if not session:
                return None
                
            return {
                'session_id': session.session_id,
                'start_time': session.start_time,
                'duration': session.get_duration(),
                'auth_duration': session.get_auth_duration(),
                'auth_result': session.auth_result,
                'eap_round_trips': session.eap_round_trips,
                'retransmissions': session.retransmissions,
                'packets': {
                    'sent': session.packets_sent,
                    'received': session.packets_received
                },
                'bytes': {
                    'sent': session.bytes_sent,
                    'received': session.bytes_received
                },
                'errors': session.errors
            }
            
    def log_summary(self):
        """統計サマリーをログに出力"""
        summary = self.get_summary()
        
        self.logger.info("=== PANA Statistics Summary ===")
        self.logger.info(f"Uptime: {summary['uptime_str']}")
        self.logger.info(f"Sessions: {summary['total_sessions']} total, {summary['active_sessions']} active")
        self.logger.info(f"Authentication: {summary['authentication']['successful']} success, "
                        f"{summary['authentication']['failed']} failed, "
                        f"{summary['authentication']['timeout']} timeout "
                        f"(Success rate: {summary['authentication']['success_rate']:.1f}%)")
        self.logger.info(f"Average auth time: {summary['authentication']['average_time']:.2f}s")
        self.logger.info(f"Packets: {summary['packets']['sent']} sent, "
                        f"{summary['packets']['received']} received, "
                        f"{summary['packets']['retransmissions']} retransmissions")
        self.logger.info(f"Bytes: {summary['bytes']['sent']} sent, "
                        f"{summary['bytes']['received']} received")
        
        if summary['errors']:
            self.logger.info("Errors:")
            for error_type, count in summary['errors'].items():
                self.logger.info(f"  {error_type}: {count}")
                
    def _get_time_bucket(self) -> float:
        """現在の時刻を1分単位のバケットに変換"""
        current_time = time.time()
        return float(int(current_time / 60) * 60)
        
    def _cleanup_old_data(self):
        """古いデータのクリーンアップ"""
        while self.running:
            try:
                time.sleep(60)  # 1分ごとにチェック
                
                with self.lock:
                    current_time = time.time()
                    cutoff_time = current_time - self.retention_period
                    
                    # 古い完了セッションの削除
                    self.completed_sessions = [
                        s for s in self.completed_sessions
                        if s.end_time and s.end_time > cutoff_time
                    ]
                    
                    # 古い時系列データの削除
                    old_buckets = [
                        bucket for bucket in self.time_series_stats
                        if bucket < cutoff_time
                    ]
                    for bucket in old_buckets:
                        del self.time_series_stats[bucket]
                        
            except Exception as e:
                self.logger.error(f"Error in cleanup thread: {e}")
                
    def stop(self):
        """統計収集の停止"""
        self.running = False
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)