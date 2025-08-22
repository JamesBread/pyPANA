#!/usr/bin/env python3
"""
PANA Configuration Module
Centralized configuration for PANA server and client

【概要】
PANAプロトコルの設定を一元管理するモジュール。
レート制限、セッション管理、暗号化設定などの
パラメータを管理します。

【主な機能】
- レート制限設定
- セッション管理設定
- 暗号化設定
- タイムアウト設定
- ロギング設定
"""

import os
import json
import logging
from typing import Dict, Any, Optional


class PANAConfig:
    """PANA設定管理クラス
    
    【クラス説明】
    PANAサーバーおよびクライアントの設定を管理します。
    環境変数、設定ファイル、デフォルト値の優先順位で
    設定値を決定します。
    """
    
    # デフォルト設定値
    DEFAULT_CONFIG = {
        # ネットワーク設定
        'network': {
            'default_port': 716,
            'buffer_size': 4096,
            'socket_timeout': 5.0,
        },
        
        # レート制限設定（DoS対策）
        'rate_limiting': {
            'enabled': True,  # DoS保護のためデフォルトで有効
            'max_requests_per_second': 100,  # 妥当な上限に増加
            'max_concurrent_sessions': 1000,
            'memory_threshold_percent': 80,
            'blacklist_duration': 300,  # 秒
            'max_sessions_per_ip': 10,
        },
        
        # セッション管理設定
        'session': {
            'default_lifetime': 3600,  # 秒
            'cleanup_interval': 60,    # 秒
            'max_retransmissions': 3,
            'retransmit_interval': 3.0,  # 秒
        },
        
        # 暗号化設定（RFC6786）
        'encryption': {
            'enabled': True,
            'enforce_encryption': False,
            'algorithms': {
                'prf': 'HMAC-SHA256',
                'integrity': 'HMAC-SHA256-128',
                'encryption': 'AES-128-CTR',
            },
        },
        
        # アンチリプレイ設定
        'anti_replay': {
            'enabled': True,
            'window_size': 32,
        },
        
        # EAP-TLS設定
        'eap_tls': {
            'cert_verify': True,
            'timeout': 30.0,
        },
        
        # RADIUS設定
        'radius': {
            'timeout': 5,
            'retries': 3,
            'nas_identifier': 'pana-agent',
        },
        
        # ロギング設定
        'logging': {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'file': None,  # Noneの場合はstdoutのみ
        },
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """
        設定を初期化
        
        Args:
            config_file: 設定ファイルのパス（オプション）
        """
        self.config = self._load_config(config_file)
        self.logger = logging.getLogger('PANAConfig')
        
    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """
        設定をロード（ファイル -> 環境変数 -> デフォルト）
        
        Args:
            config_file: 設定ファイルのパス
            
        Returns:
            dict: マージされた設定辞書
        """
        # デフォルト設定から開始
        config = self._deep_copy_dict(self.DEFAULT_CONFIG)
        
        # 設定ファイルがあれば読み込み
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    file_config = json.load(f)
                    config = self._merge_configs(config, file_config)
            except Exception as e:
                logging.error(f"Failed to load config file {config_file}: {e}")
        
        # 環境変数でオーバーライド
        config = self._apply_env_overrides(config)
        
        return config
    
    def _deep_copy_dict(self, d: dict) -> dict:
        """
        辞書を深くコピー
        
        Args:
            d: コピー元の辞書
            
        Returns:
            dict: コピーされた辞書
        """
        if isinstance(d, dict):
            return {k: self._deep_copy_dict(v) for k, v in d.items()}
        elif isinstance(d, list):
            return [self._deep_copy_dict(item) for item in d]
        else:
            return d
    
    def _merge_configs(self, base: dict, override: dict) -> dict:
        """
        設定辞書をマージ
        
        Args:
            base: ベースとなる設定
            override: 上書きする設定
            
        Returns:
            dict: マージされた設定
        """
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _apply_env_overrides(self, config: dict) -> dict:
        """
        環境変数による設定のオーバーライド
        
        環境変数名の形式: PANA_<SECTION>_<KEY>
        例: PANA_RATE_LIMITING_ENABLED=false
        
        Args:
            config: 現在の設定
            
        Returns:
            dict: 環境変数が適用された設定
        """
        env_mappings = {
            'PANA_PORT': ('network', 'default_port', int),
            'PANA_RATE_LIMIT_ENABLED': ('rate_limiting', 'enabled', lambda x: x.lower() == 'true'),
            'PANA_RATE_LIMIT_MAX_RPS': ('rate_limiting', 'max_requests_per_second', int),
            'PANA_RATE_LIMIT_MAX_SESSIONS': ('rate_limiting', 'max_concurrent_sessions', int),
            'PANA_SESSION_LIFETIME': ('session', 'default_lifetime', int),
            'PANA_ENCRYPTION_ENABLED': ('encryption', 'enabled', lambda x: x.lower() == 'true'),
            'PANA_LOG_LEVEL': ('logging', 'level', str),
        }
        
        for env_var, (section, key, converter) in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                try:
                    config[section][key] = converter(value)
                except:
                    logging.warning(f"Invalid value for {env_var}: {value}")
        
        return config
    
    def get(self, path: str, default: Any = None) -> Any:
        """
        設定値を取得（ドット記法対応）
        
        Args:
            path: 設定のパス（例: "rate_limiting.enabled"）
            default: デフォルト値
            
        Returns:
            設定値またはデフォルト値
        """
        parts = path.split('.')
        value = self.config
        
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
        
        return value
    
    def set(self, path: str, value: Any):
        """
        設定値を設定（実行時のみ、永続化なし）
        
        Args:
            path: 設定のパス
            value: 設定する値
        """
        parts = path.split('.')
        config = self.config
        
        for part in parts[:-1]:
            if part not in config:
                config[part] = {}
            config = config[part]
        
        config[parts[-1]] = value
    
    def save(self, filename: str):
        """
        現在の設定をファイルに保存
        
        Args:
            filename: 保存先ファイル名
        """
        try:
            with open(filename, 'w') as f:
                json.dump(self.config, f, indent=2)
            self.logger.info(f"Configuration saved to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
    
    def validate(self) -> bool:
        """
        設定の妥当性を検証
        
        Returns:
            bool: 設定が妥当な場合True
        """
        # ポート番号の範囲チェック
        port = self.get('network.default_port')
        if not (1 <= port <= 65535):
            self.logger.error(f"Invalid port number: {port}")
            return False
        
        # レート制限値の妥当性
        max_rps = self.get('rate_limiting.max_requests_per_second')
        if max_rps < 1:
            self.logger.error(f"Invalid max_requests_per_second: {max_rps}")
            return False
        
        # セッション数の妥当性
        max_sessions = self.get('rate_limiting.max_concurrent_sessions')
        if max_sessions < 1:
            self.logger.error(f"Invalid max_concurrent_sessions: {max_sessions}")
            return False
        
        # メモリ閾値の範囲
        mem_threshold = self.get('rate_limiting.memory_threshold_percent')
        if not (1 <= mem_threshold <= 100):
            self.logger.error(f"Invalid memory_threshold_percent: {mem_threshold}")
            return False
        
        return True


# グローバル設定インスタンス（シングルトン）
_global_config = None


def get_config(config_file: Optional[str] = None) -> PANAConfig:
    """
    グローバル設定インスタンスを取得
    
    Args:
        config_file: 設定ファイルのパス（初回のみ有効）
        
    Returns:
        PANAConfig: 設定インスタンス
    """
    global _global_config
    
    if _global_config is None:
        _global_config = PANAConfig(config_file)
    
    return _global_config