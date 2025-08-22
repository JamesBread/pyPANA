#!/usr/bin/env python3
"""
PANA Message Retransmission Management
RFC5191 compliant retransmission with R flag support

【概要】
PANAメッセージの再送信管理を担当するモジュール。
RFC5191のRフラグ（Requestフラグ）を持つメッセージの再送信処理を実装。

【主な機能】
- タイムアウト後の自動再送信
- 最大再送信回数の管理
- スレッドセーフなメッセージキュー管理
- アドレス別のメッセージ管理
"""

import time
import threading
import logging
from pana_constants import RETRANSMIT_INTERVAL, MAX_RETRANSMISSIONS


class RetransmissionManager:
    """メッセージ再送信を管理するクラス
    
    【クラス説明】
    Rフラグ（Requestフラグ）が設定されたメッセージの再送信を管理。
    バックグラウンドスレッドでタイマーを監視し、必要に応じて再送信を実行。
    """
    def __init__(self, socket_obj):
        """
        再送信マネージャーの初期化
        
        Args:
            socket_obj: メッセージ送信に使用するソケットオブジェクト
        """
        self.socket = socket_obj
        # 保留中のメッセージ: seq_number -> (message, addr, timestamp, retries)
        self.pending_messages = {}
        self.lock = threading.Lock()  # スレッドセーフティ用ロック
        self.running = True
        
        # アダプティブポーリング用の変数
        self.poll_interval = 0.1  # 初期ポーリング間隔（100ms）
        self.min_poll_interval = 0.1  # 最小ポーリング間隔
        self.max_poll_interval = 2.0  # 最大ポーリング間隔（2秒）
        self.empty_cycles = 0  # 空のサイクル数をカウント
        self.has_messages_event = threading.Event()  # メッセージがある場合のイベント
        
        # 一時停止/再開機能
        self.paused = False
        self.pause_event = threading.Event()
        self.pause_event.set()  # 初期状態では実行中
        
        # 再送信監視用バックグラウンドスレッド
        self.thread = threading.Thread(target=self._retransmit_loop)
        self.thread.daemon = True
        self.thread.start()
        self.logger = logging.getLogger('RetransmissionManager')
        
    def add_message(self, seq_number, message, addr):
        """
        再送信管理対象にメッセージを追加
        
        Args:
            seq_number: シーケンス番号
            message: 送信するメッセージデータ（バイト列）
            addr: 送信先アドレス（IP, ポート）のタプル
        """
        with self.lock:
            # 現在時刻と再送信回数（0）を記録
            self.pending_messages[seq_number] = (message, addr, time.time(), 0)
            self.logger.debug(f"Added message seq={seq_number} for retransmission to {addr}")
            
            # ポーリング間隔をリセットし、イベントをセット
            self.poll_interval = self.min_poll_interval
            self.empty_cycles = 0
            self.has_messages_event.set()
            
    def remove_message(self, seq_number):
        """
        再送信キューからメッセージを削除
        
        応答を受信した場合などに呼び出される。
        
        Args:
            seq_number: 削除するメッセージのシーケンス番号
        """
        with self.lock:
            if seq_number in self.pending_messages:
                del self.pending_messages[seq_number]
                self.logger.debug(f"Removed message seq={seq_number} from retransmission queue")
                
    def clear_messages_for_address(self, addr):
        """
        特定のアドレス宛のすべてのメッセージをクリア
        
        セッションが確立した場合など、特定のクライアントへの
        再送信をすべて停止する必要がある場合に使用。
        
        Args:
            addr: クリアするアドレス（IP, ポート）のタプル
        """
        with self.lock:
            to_remove = []
            for seq_number, (msg, msg_addr, _, _) in self.pending_messages.items():
                if msg_addr == addr:
                    to_remove.append(seq_number)
            
            for seq_number in to_remove:
                del self.pending_messages[seq_number]
                
            if to_remove:
                self.logger.debug(f"Cleared {len(to_remove)} messages for address {addr}")
                
    def get_pending_count(self):
        """
        保留中のメッセージ数を取得
        
        Returns:
            int: 再送信待ちのメッセージ数
        """
        with self.lock:
            return len(self.pending_messages)
            
    def _retransmit_loop(self):
        """
        再送信処理を行うバックグラウンドスレッド
        
        アダプティブポーリングを使用して、メッセージがない場合は
        徐々にポーリング間隔を増やしてCPU使用率を削減。
        """
        while self.running:
            # 一時停止中は待機
            self.pause_event.wait()
            
            if not self.running:
                break
                
            current_time = time.time()
            messages_processed = False
            
            with self.lock:
                # list()でコピーを作成し、反復中の辞書変更を避ける
                for seq_number, (message, addr, timestamp, retries) in list(self.pending_messages.items()):
                    # タイムアウトチェック（RETRANSMIT_INTERVAL秒経過）
                    if current_time - timestamp > RETRANSMIT_INTERVAL:
                        messages_processed = True
                        if retries < MAX_RETRANSMISSIONS:
                            # 再送信実行
                            try:
                                self.socket.sendto(message, addr)
                                # タイムスタンプと再送信回数を更新
                                self.pending_messages[seq_number] = (message, addr, current_time, retries + 1)
                                self.logger.info(f"Retransmitting message seq={seq_number} to {addr}, retry={retries + 1}")
                            except Exception as e:
                                self.logger.error(f"Failed to retransmit message seq={seq_number}: {e}")
                                # 送信失敗時はメッセージを削除
                                del self.pending_messages[seq_number]
                        else:
                            # 最大再送信回数に達した場合はキューから削除
                            del self.pending_messages[seq_number]
                            self.logger.warning(f"Max retransmissions reached for seq={seq_number} to {addr}")
                
                # メッセージがない場合はイベントをクリア
                if not self.pending_messages:
                    self.has_messages_event.clear()
            
            # アダプティブポーリング: メッセージがない場合は間隔を増やす
            if not messages_processed and not self.pending_messages:
                self.empty_cycles += 1
                # 指数バックオフ: 空のサイクルごとに間隔を2倍にする（最大値まで）
                if self.empty_cycles > 5:  # 5サイクル後から増加開始
                    self.poll_interval = min(self.poll_interval * 1.5, self.max_poll_interval)
            else:
                # メッセージが処理された場合は間隔をリセット
                self.poll_interval = self.min_poll_interval
                self.empty_cycles = 0
            
            # イベント待機またはタイムアウト
            self.has_messages_event.wait(timeout=self.poll_interval)
            
    def pause(self):
        """
        再送信処理を一時停止
        
        認証完了後など、再送信が不要な期間に使用。
        """
        with self.lock:
            if not self.paused:
                self.paused = True
                self.pause_event.clear()
                self.logger.debug("Retransmission manager paused")
    
    def resume(self):
        """
        再送信処理を再開
        
        新しい認証セッションの開始時などに使用。
        """
        with self.lock:
            if self.paused:
                self.paused = False
                self.pause_event.set()
                self.poll_interval = self.min_poll_interval
                self.empty_cycles = 0
                self.logger.debug("Retransmission manager resumed")
    
    def stop(self):
        """
        再送信スレッドを停止
        
        シャットダウン時に呼び出され、バックグラウンドスレッドを
        正常に終了させる。
        """
        self.running = False
        self.pause_event.set()  # 一時停止中でも終了できるようにする
        self.has_messages_event.set()  # イベント待機を解除
        self.thread.join()  # スレッドの終了を待つ
        self.logger.info("Retransmission manager stopped")