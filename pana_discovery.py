#!/usr/bin/env python3
"""
PANA PAA Discovery Implementation
RFC 5192 compliant PAA discovery mechanisms

【概要】
このモジュールはPANA認証エージェント（PAA）の自動検出機能を提供します。
マルチキャストとDHCPオプションの両方をサポートします。

【主な機能】
- マルチキャストディスカバリー（224.0.0.246）
- DHCPオプション解析
- 複数PAA候補の管理
- タイムアウト処理
"""

import socket
import struct
import time
import threading
import logging
from typing import List, Tuple, Optional, Dict

from pana_messages import PANAMessage
from pana_constants import PANA_CLIENT_INITIATION, FLAG_REQUEST, FLAG_START


class PANADiscovery:
    """PANA PAA Discovery Implementation
    
    【クラス説明】
    PAA（PANA Authentication Agent）を自動的に検出するための
    ディスカバリー機能を提供します。
    """
    
    # PANA multicast address (RFC 5192)
    PANA_MULTICAST_ADDR = '224.0.0.246'
    PANA_PORT = 716
    
    def __init__(self, timeout: int = 5, max_attempts: int = 3):
        """
        初期化
        
        Args:
            timeout: ディスカバリー応答のタイムアウト（秒）
            max_attempts: 最大試行回数
        """
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.logger = logging.getLogger('PANADiscovery')
        self.discovered_paas: List[Tuple[str, int]] = []
        self.discovery_socket: Optional[socket.socket] = None
        
    def discover_multicast(self, interface_ip: Optional[str] = None) -> List[Tuple[str, int]]:
        """
        マルチキャストによるPAAディスカバリー
        
        【説明】
        RFC 5192に準拠したマルチキャストディスカバリーを実行します。
        PANA-Client-Initiation (PCI) メッセージをマルチキャストアドレス
        224.0.0.246に送信し、応答を待ちます。
        
        Args:
            interface_ip: 使用するインターフェースのIPアドレス（オプション）
            
        Returns:
            発見されたPAAのリスト [(ip, port), ...]
        """
        self.discovered_paas = []
        
        try:
            # マルチキャスト送信用ソケットの作成
            self.discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # TTLを設定（ローカルネットワーク内のみ）
            ttl = struct.pack('b', 1)
            self.discovery_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
            
            # インターフェースの指定
            if interface_ip:
                self.discovery_socket.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_MULTICAST_IF,
                    socket.inet_aton(interface_ip)
                )
            
            # 受信スレッドを開始
            receiver_thread = threading.Thread(target=self._receive_responses)
            receiver_thread.daemon = True
            receiver_thread.start()
            
            # PCIメッセージを送信
            start_time = time.time()
            for attempt in range(self.max_attempts):
                self.logger.info(f"Sending multicast discovery (attempt {attempt + 1}/{self.max_attempts})")
                self._send_multicast_pci()
                
                # 応答を待つ
                sleep_time = min(self.timeout / self.max_attempts, 
                                self.timeout - (time.time() - start_time))
                if sleep_time > 0:
                    time.sleep(sleep_time)
                
                if self.discovered_paas or (time.time() - start_time) >= self.timeout:
                    break
                    
            # 受信スレッドの終了を待つ (短時間のみ)
            remaining_time = max(0, self.timeout - (time.time() - start_time))
            time.sleep(min(0.5, remaining_time))
            
        except Exception as e:
            self.logger.error(f"Multicast discovery failed: {e}")
            
        finally:
            if self.discovery_socket:
                self.discovery_socket.close()
                
        self.logger.info(f"Discovered {len(self.discovered_paas)} PAA(s)")
        return self.discovered_paas
        
    def _send_multicast_pci(self):
        """マルチキャストPCIメッセージを送信"""
        # PANA-Client-Initiation メッセージの作成
        pci = PANAMessage()
        pci.flags = FLAG_REQUEST | FLAG_START
        pci.msg_type = PANA_CLIENT_INITIATION
        pci.session_id = 0  # RFC 5191: PCI must have session_id = 0
        pci.seq_number = 0  # RFC 5191: PCI must have seq_number = 0
        
        # メッセージを送信
        message_data = pci.pack()
        self.discovery_socket.sendto(
            message_data,
            (self.PANA_MULTICAST_ADDR, self.PANA_PORT)
        )
        
    def _receive_responses(self):
        """ディスカバリー応答を受信"""
        # 受信用ソケットの作成
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        recv_socket.settimeout(0.5)  # ショートタイムアウト
        
        try:
            # 任意のポートでバインド
            recv_socket.bind(('', 0))
            local_port = recv_socket.getsockname()[1]
            self.logger.debug(f"Listening for responses on port {local_port}")
            
            end_time = time.time() + self.timeout
            
            while time.time() < end_time:
                try:
                    data, addr = recv_socket.recvfrom(4096)
                    
                    # PANAメッセージとして解析
                    try:
                        msg = PANAMessage()
                        msg.unpack(data)
                        
                        # PANA-Auth-Requestの場合、PAAとして記録
                        if msg.msg_type == 2:  # PANA_AUTH
                            paa_addr = (addr[0], addr[1])
                            if paa_addr not in self.discovered_paas:
                                self.discovered_paas.append(paa_addr)
                                self.logger.info(f"Discovered PAA at {paa_addr}")
                                
                    except Exception as e:
                        self.logger.debug(f"Failed to parse response from {addr}: {e}")
                        
                except socket.timeout:
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error receiving responses: {e}")
            
        finally:
            recv_socket.close()
            
    def discover_dhcp(self, dhcp_server: str, dhcp_option: int = 136) -> List[Tuple[str, int]]:
        """
        DHCPオプションによるPAAディスカバリー
        
        【説明】
        DHCPサーバーから提供されるPANAオプション（デフォルト: Option 136）
        を解析してPAAアドレスを取得します。
        
        Args:
            dhcp_server: DHCPサーバーのアドレス
            dhcp_option: PANAオプション番号（デフォルト: 136）
            
        Returns:
            発見されたPAAのリスト [(ip, port), ...]
        """
        # 注: 実際のDHCP実装は環境依存のため、
        # ここでは基本的な構造のみを提供
        self.logger.warning("DHCP discovery is not fully implemented")
        
        # DHCPクライアントライブラリを使用して
        # オプション136を取得する必要があります
        
        return []
        
    def select_best_paa(self, discovered_paas: List[Tuple[str, int]]) -> Optional[Tuple[str, int]]:
        """
        最適なPAAを選択
        
        【説明】
        発見された複数のPAAから最適なものを選択します。
        現在の実装では、最初に発見されたPAAを選択します。
        
        Args:
            discovered_paas: 発見されたPAAのリスト
            
        Returns:
            選択されたPAAのアドレス、または None
        """
        if not discovered_paas:
            return None
            
        # TODO: より高度な選択ロジックの実装
        # - 応答時間
        # - ロードバランシング
        # - 地理的な近さ
        
        return discovered_paas[0]
        
    def test_paa_connectivity(self, paa_addr: Tuple[str, int]) -> bool:
        """
        PAAへの接続性をテスト
        
        【説明】
        指定されたPAAアドレスへの接続性を確認します。
        
        Args:
            paa_addr: PAAのアドレス (ip, port)
            
        Returns:
            接続可能な場合 True
        """
        try:
            # テスト用ソケットの作成
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_socket.settimeout(2.0)
            
            # PCIメッセージを送信
            pci = PANAMessage()
            pci.flags = FLAG_REQUEST | FLAG_START
            pci.msg_type = PANA_CLIENT_INITIATION
            pci.session_id = 0
            pci.seq_number = 0
            
            test_socket.sendto(pci.pack(), paa_addr)
            
            # 応答を待つ
            data, addr = test_socket.recvfrom(4096)
            
            # 応答が来れば接続可能
            return True
            
        except socket.timeout:
            self.logger.warning(f"PAA at {paa_addr} did not respond")
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to test PAA connectivity: {e}")
            return False
            
        finally:
            if 'test_socket' in locals():
                test_socket.close()


class DiscoveryCache:
    """PAAディスカバリー結果のキャッシュ
    
    【クラス説明】
    ディスカバリー結果をキャッシュし、
    不要なディスカバリー処理を削減します。
    """
    
    def __init__(self, cache_timeout: int = 300):
        """
        初期化
        
        Args:
            cache_timeout: キャッシュの有効期限（秒）
        """
        self.cache_timeout = cache_timeout
        self.cache: Dict[str, Tuple[List[Tuple[str, int]], float]] = {}
        self.lock = threading.Lock()
        
    def get(self, key: str) -> Optional[List[Tuple[str, int]]]:
        """
        キャッシュから取得
        
        Args:
            key: キャッシュキー（例: "multicast"）
            
        Returns:
            キャッシュされたPAAリスト、または None
        """
        with self.lock:
            if key in self.cache:
                paas, timestamp = self.cache[key]
                if time.time() - timestamp < self.cache_timeout:
                    return paas
                else:
                    # 期限切れ
                    del self.cache[key]
                    
        return None
        
    def set(self, key: str, paas: List[Tuple[str, int]]):
        """
        キャッシュに保存
        
        Args:
            key: キャッシュキー
            paas: PAAリスト
        """
        with self.lock:
            self.cache[key] = (paas, time.time())
            
    def clear(self):
        """キャッシュをクリア"""
        with self.lock:
            self.cache.clear()