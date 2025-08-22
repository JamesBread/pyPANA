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
        
        Args:
            seq_num: チェックするシーケンス番号
            
        Returns:
            bool: パケットが有効な場合True、リプレイや無効な場合False
        """
        # 最初のパケットの場合
        if self.highest_seq == -1:
            self.highest_seq = seq_num
            self.window_start = max(0, seq_num - self.window_size + 1)
            self.received_seqs.add(seq_num)
            self.logger.debug(f"First packet received: seq={seq_num}")
            return True
        
        # ウィンドウより古いパケット（拒否）
        if seq_num < self.window_start:
            self.logger.warning(f"Packet too old: seq={seq_num}, window_start={self.window_start}")
            return False
        
        # ウィンドウ内のパケット
        if self.window_start <= seq_num <= self.highest_seq:
            # 既に受信済みの場合（リプレイ攻撃の可能性）
            if seq_num in self.received_seqs:
                self.logger.warning(f"Duplicate packet detected: seq={seq_num}")
                return False
            else:
                # 新しいパケット（ウィンドウ内のギャップを埋める）
                self.received_seqs.add(seq_num)
                self.logger.debug(f"Gap filled: seq={seq_num}")
                return True
        
        # 最高シーケンス番号より新しいパケット
        if seq_num > self.highest_seq:
            # ウィンドウをスライドさせる
            self._slide_window(seq_num)
            self.received_seqs.add(seq_num)
            self.highest_seq = seq_num
            self.logger.debug(f"Window advanced: seq={seq_num}, new_window_start={self.window_start}")
            return True
        
        # ここには到達しないはずだが、念のため
        self.logger.error(f"Unexpected state: seq={seq_num}")
        return False
    
    def _slide_window(self, new_seq: int):
        """
        ウィンドウを新しいシーケンス番号に合わせてスライド
        
        Args:
            new_seq: 新しいシーケンス番号
        """
        # 新しいウィンドウの開始位置を計算
        new_window_start = max(self.window_start, new_seq - self.window_size + 1)
        
        # 古いシーケンス番号をウィンドウから削除
        self.received_seqs = {
            seq for seq in self.received_seqs 
            if seq >= new_window_start
        }
        
        self.window_start = new_window_start
    
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