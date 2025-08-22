#!/usr/bin/env python3
"""
PANA Statistics Monitor
Real-time monitoring and visualization of PANA statistics

【概要】
このモジュールはPANA統計情報のリアルタイム監視と
可視化機能を提供します。

【主な機能】
- リアルタイム統計表示
- JSON形式でのエクスポート
- 定期的なログ出力
- Webダッシュボード（オプション）
"""

import json
import time
import threading
import logging
from datetime import datetime
from typing import Optional

from pana_statistics import PANAStatistics


class PANAMonitor:
    """PANA統計モニタークラス
    
    【クラス説明】
    PANA統計情報をモニタリングし、様々な形式で出力します。
    """
    
    def __init__(self, statistics: PANAStatistics, log_interval: int = 300):
        """
        初期化
        
        Args:
            statistics: PANAStatisticsインスタンス
            log_interval: ログ出力間隔（秒、デフォルト5分）
        """
        self.statistics = statistics
        self.log_interval = log_interval
        self.logger = logging.getLogger('PANAMonitor')
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        
    def start(self):
        """モニタリングの開始"""
        if self.running:
            return
            
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        self.logger.info("PANA Monitor started")
        
    def stop(self):
        """モニタリングの停止"""
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        self.logger.info("PANA Monitor stopped")
        
    def get_current_stats(self) -> dict:
        """
        現在の統計情報を取得
        
        Returns:
            統計情報の辞書
        """
        summary = self.statistics.get_summary()
        time_series = self.statistics.get_time_series(minutes=60)
        
        return {
            'timestamp': time.time(),
            'datetime': datetime.now().isoformat(),
            'summary': summary,
            'time_series': time_series
        }
        
    def export_json(self, filename: str):
        """
        統計情報をJSON形式でエクスポート
        
        Args:
            filename: 出力ファイル名
        """
        stats = self.get_current_stats()
        
        with open(filename, 'w') as f:
            json.dump(stats, f, indent=2)
            
        self.logger.info(f"Statistics exported to {filename}")
        
    def print_summary(self):
        """統計サマリーをコンソールに出力"""
        summary = self.statistics.get_summary()
        
        print("\n" + "="*60)
        print("PANA Statistics Summary")
        print("="*60)
        print(f"Uptime: {summary['uptime_str']}")
        print(f"Total Sessions: {summary['total_sessions']} ({summary['active_sessions']} active)")
        print(f"\nAuthentication Statistics:")
        print(f"  Success: {summary['authentication']['successful']}")
        print(f"  Failed: {summary['authentication']['failed']}")
        print(f"  Timeout: {summary['authentication']['timeout']}")
        print(f"  Success Rate: {summary['authentication']['success_rate']:.1f}%")
        print(f"  Average Time: {summary['authentication']['average_time']:.2f}s")
        print(f"\nPacket Statistics:")
        print(f"  Sent: {summary['packets']['sent']}")
        print(f"  Received: {summary['packets']['received']}")
        print(f"  Retransmissions: {summary['packets']['retransmissions']}")
        print(f"\nData Transfer:")
        print(f"  Sent: {self._format_bytes(summary['bytes']['sent'])}")
        print(f"  Received: {self._format_bytes(summary['bytes']['received'])}")
        
        if summary['errors']:
            print(f"\nError Summary:")
            for error_type, count in summary['errors'].items():
                print(f"  {error_type}: {count}")
                
        print(f"\nMessage Type Distribution:")
        for msg_type, count in sorted(summary['message_types'].items()):
            print(f"  Type {msg_type}: {count}")
            
        print("="*60 + "\n")
        
    def generate_html_report(self, filename: str):
        """
        HTML形式のレポートを生成
        
        Args:
            filename: 出力ファイル名
        """
        stats = self.get_current_stats()
        summary = stats['summary']
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>PANA Statistics Report</title>
    <meta charset="utf-8">
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1, h2 {{
            color: #333;
        }}
        .metric {{
            display: inline-block;
            margin: 10px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 4px;
            min-width: 200px;
        }}
        .metric-value {{
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }}
        .metric-label {{
            color: #666;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: bold;
        }}
        .success {{
            color: #28a745;
        }}
        .failure {{
            color: #dc3545;
        }}
        .timestamp {{
            color: #666;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>PANA Statistics Report</h1>
        <p class="timestamp">Generated at: {stats['datetime']}</p>
        
        <h2>Overview</h2>
        <div>
            <div class="metric">
                <div class="metric-value">{summary['uptime_str']}</div>
                <div class="metric-label">Uptime</div>
            </div>
            <div class="metric">
                <div class="metric-value">{summary['total_sessions']}</div>
                <div class="metric-label">Total Sessions</div>
            </div>
            <div class="metric">
                <div class="metric-value">{summary['active_sessions']}</div>
                <div class="metric-label">Active Sessions</div>
            </div>
        </div>
        
        <h2>Authentication Statistics</h2>
        <div>
            <div class="metric">
                <div class="metric-value class="success"">{summary['authentication']['successful']}</div>
                <div class="metric-label">Successful</div>
            </div>
            <div class="metric">
                <div class="metric-value class="failure"">{summary['authentication']['failed']}</div>
                <div class="metric-label">Failed</div>
            </div>
            <div class="metric">
                <div class="metric-value">{summary['authentication']['timeout']}</div>
                <div class="metric-label">Timeout</div>
            </div>
            <div class="metric">
                <div class="metric-value">{summary['authentication']['success_rate']:.1f}%</div>
                <div class="metric-label">Success Rate</div>
            </div>
            <div class="metric">
                <div class="metric-value">{summary['authentication']['average_time']:.2f}s</div>
                <div class="metric-label">Avg Auth Time</div>
            </div>
        </div>
        
        <h2>Network Statistics</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Packets Sent</td>
                <td>{summary['packets']['sent']:,}</td>
            </tr>
            <tr>
                <td>Packets Received</td>
                <td>{summary['packets']['received']:,}</td>
            </tr>
            <tr>
                <td>Retransmissions</td>
                <td>{summary['packets']['retransmissions']:,}</td>
            </tr>
            <tr>
                <td>Bytes Sent</td>
                <td>{self._format_bytes(summary['bytes']['sent'])}</td>
            </tr>
            <tr>
                <td>Bytes Received</td>
                <td>{self._format_bytes(summary['bytes']['received'])}</td>
            </tr>
        </table>
        """
        
        if summary['errors']:
            html_content += """
        <h2>Error Summary</h2>
        <table>
            <tr>
                <th>Error Type</th>
                <th>Count</th>
            </tr>
        """
            for error_type, count in sorted(summary['errors'].items()):
                html_content += f"""
            <tr>
                <td>{error_type}</td>
                <td>{count}</td>
            </tr>
        """
            html_content += "</table>"
            
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(filename, 'w') as f:
            f.write(html_content)
            
        self.logger.info(f"HTML report generated: {filename}")
        
    def _monitor_loop(self):
        """モニタリングループ"""
        while self.running:
            try:
                # 定期的に統計サマリーをログ出力
                self.statistics.log_summary()
                
                # 次のログ出力まで待機
                for _ in range(self.log_interval):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}")
                
    def _format_bytes(self, bytes_value: int) -> str:
        """バイト数を人間が読みやすい形式に変換"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"


def create_console_dashboard(statistics: PANAStatistics):
    """
    コンソールダッシュボードを作成（簡易版）
    
    Args:
        statistics: PANAStatisticsインスタンス
    """
    import os
    
    try:
        while True:
            # 画面クリア
            os.system('clear' if os.name == 'posix' else 'cls')
            
            # 統計情報の取得と表示
            summary = statistics.get_summary()
            
            print("╔══════════════════════════════════════════════════════════╗")
            print("║                PANA Statistics Dashboard                 ║")
            print("╠══════════════════════════════════════════════════════════╣")
            print(f"║ Uptime: {summary['uptime_str']:<48}║")
            print(f"║ Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<47}║")
            print("╠══════════════════════════════════════════════════════════╣")
            print("║ Sessions                                                 ║")
            print(f"║   Total: {summary['total_sessions']:<8} Active: {summary['active_sessions']:<31}║")
            print("╠══════════════════════════════════════════════════════════╣")
            print("║ Authentication                                           ║")
            print(f"║   Success: {summary['authentication']['successful']:<6} "
                  f"Failed: {summary['authentication']['failed']:<6} "
                  f"Timeout: {summary['authentication']['timeout']:<17}║")
            print(f"║   Success Rate: {summary['authentication']['success_rate']:.1f}% "
                  f"Avg Time: {summary['authentication']['average_time']:.2f}s{' '*19}║")
            print("╠══════════════════════════════════════════════════════════╣")
            print("║ Network Traffic                                          ║")
            print(f"║   Packets - Sent: {summary['packets']['sent']:<10} "
                  f"Received: {summary['packets']['received']:<19}║")
            print(f"║   Retransmissions: {summary['packets']['retransmissions']:<37}║")
            print("╚══════════════════════════════════════════════════════════╝")
            print("\nPress Ctrl+C to exit...")
            
            time.sleep(5)  # 5秒ごとに更新
            
    except KeyboardInterrupt:
        print("\nDashboard closed.")