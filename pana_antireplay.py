#!/usr/bin/env python3
"""
PANA Anti-Replay Protection Module
Implements sliding window mechanism to detect and prevent replay attacks

【概要】
PANAプロトコルにおけるリプレイ攻撃を防ぐためのモジュール。
スライディングウィンドウ方式を使用して、シーケンス番号の重複や
古いパケットの再送を検出・拒否します。

【主な機能】
- スライディングウィンドウによるシーケンス番号管理
- 重複パケットの検出
- ウィンドウ外の古いパケットの拒否
- セッション毎の独立した管理
"""

import logging
from typing import Optional, Set


class AntiReplay:
    """リプレイ攻撃を防ぐためのスライディングウィンドウ実装
    
    【クラス説明】
    受信したパケットのシーケンス番号を追跡し、重複や古いパケットを
    検出します。RFC5191準拠のアンチリプレイメカニズムを提供します。
    
    Attributes:
        window_size: スライディングウィンドウのサイズ（デフォルト: 32）
        highest_seq: これまでに受信した最大のシーケンス番号
        window_start: ウィンドウの開始位置
        received_seqs: ウィンドウ内で受信済みのシーケンス番号のセット
    """
    
    def __init__(self, window_size: int = 32):
        """
        アンチリプレイインスタンスを初期化
        
        Args:
            window_size: スライディングウィンドウのサイズ（デフォルト: 32）
        """
        self.window_size = window_size
        self.highest_seq = -1  # まだパケットを受信していない
        self.window_start = 0
        self.received_seqs: Set[int] = set()
        self.logger = logging.getLogger('AntiReplay')
        
    def check_and_update(self, seq_num: int) -> bool:
        """
        シーケンス番号をチェックし、有効な場合はウィンドウを更新
        RFC5191準拠: 32ビット符号なし整数のラップアラウンドを考慮
        
        Args:
            seq_num: チェックするシーケンス番号
            
        Returns:
            bool: パケットが有効な場合True、リプレイや無効な場合False
        """
        # Ensure sequence number is within 32-bit range
        seq_num = seq_num & 0xFFFFFFFF
        
        # 最初のパケットの場合
        if self.highest_seq == -1:
            self.highest_seq = seq_num
            self.window_start = max(0, seq_num - self.window_size + 1) & 0xFFFFFFFF
            self.received_seqs.add(seq_num)
            self.logger.debug(f"First packet received: seq={seq_num}")
            return True
        
        # 既に受信済みの場合（リプレイ攻撃の可能性）
        if seq_num in self.received_seqs:
            self.logger.warning(f"Duplicate packet detected: seq={seq_num}")
            return False
        
        # Calculate difference as 32-bit signed integer (handles wrap-around)
        diff = (seq_num - self.highest_seq) & 0xFFFFFFFF
        if diff > 0x80000000:  # Negative difference in signed 32-bit
            diff = diff - 0x100000000
        
        # Check if sequence number is within acceptable range
        if diff > 0:
            # Sequence number is ahead of highest_seq
            if diff <= self.window_size:
                # Within window advance range
                self._slide_window(seq_num)
                self.received_seqs.add(seq_num)
                self.highest_seq = seq_num
                self.logger.debug(f"Window advanced: seq={seq_num}, new_window_start={self.window_start}")
                return True
            else:
                # Too far ahead - reset window
                self._reset_window(seq_num)
                self.received_seqs.add(seq_num)
                self.highest_seq = seq_num
                self.logger.debug(f"Window reset: seq={seq_num}, jumped too far ahead")
                return True
        else:
            # Sequence number is behind or equal to highest_seq
            # Calculate distance from window start
            start_diff = (seq_num - self.window_start) & 0xFFFFFFFF
            if start_diff > 0x80000000:  # Negative difference
                start_diff = start_diff - 0x100000000
            
            if start_diff >= 0 and start_diff < self.window_size:
                # Within current window
                self.received_seqs.add(seq_num)
                self.logger.debug(f"Packet within window: seq={seq_num}")
                return True
            else:
                # Too old
                self.logger.warning(f"Packet too old: seq={seq_num}, window=[{self.window_start}, {(self.window_start + self.window_size - 1) & 0xFFFFFFFF}]")
                return False
    
    def _slide_window(self, new_seq: int):
        """
        ウィンドウを新しいシーケンス番号に合わせてスライド
        
        Args:
            new_seq: 新しいシーケンス番号
        """
        # 新しいウィンドウの開始位置を計算 (32-bit wrap-around対応)
        new_window_start = (new_seq - self.window_size + 1) & 0xFFFFFFFF
        
        # 古いシーケンス番号をウィンドウから削除 (wrap-around考慮)
        new_received_seqs = set()
        for seq in self.received_seqs:
            # Calculate distance from new window start
            dist = (seq - new_window_start) & 0xFFFFFFFF
            if dist < self.window_size:
                new_received_seqs.add(seq)
        
        self.received_seqs = new_received_seqs
        self.window_start = new_window_start
    
    def _reset_window(self, new_seq: int):
        """
        ウィンドウを完全にリセット（大きなジャンプの場合）
        
        Args:
            new_seq: 新しいシーケンス番号
        """
        self.window_start = (new_seq - self.window_size + 1) & 0xFFFFFFFF
        self.received_seqs.clear()
    
    def reset(self):
        """
        アンチリプレイ状態をリセット
        
        【説明】
        新しいセッションの開始時やエラー回復時に使用します。
        """
        self.highest_seq = -1
        self.window_start = 0
        self.received_seqs.clear()
        self.logger.info("Anti-replay state reset")
    
    def get_window_info(self) -> dict:
        """
        現在のウィンドウ状態を取得（デバッグ用）
        
        Returns:
            dict: ウィンドウの状態情報
        """
        return {
            'window_size': self.window_size,
            'window_start': self.window_start,
            'highest_seq': self.highest_seq,
            'received_count': len(self.received_seqs),
            'window_range': f"[{self.window_start}, {self.window_start + self.window_size - 1}]"
        }