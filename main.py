#!/usr/bin/env python3
"""
Main entry point for pyPANA - RFC5191 PANA Implementation
Command-line interface for both PANA Client and Authentication Agent

pyPANAのメインエントリーポイント - RFC5191 PANA実装
PANAクライアントと認証エージェントの両方のコマンドラインインターフェース
"""

import sys
import signal
import logging
from pana_client import PANAClient
from pana_server import PANAAuthAgent


def signal_handler(sig, frame):
    """Handle shutdown signals
    
    シャットダウンシグナルを処理する
    Ctrl+Cなどの割り込みシグナルを受信した際に、
    サーバーまたはクライアントを適切に停止する
    """
    print("\nShutting down...")
    if 'server' in globals():
        server.stop()
    if 'client' in globals():
        client.running = False
    sys.exit(0)


def setup_logging(debug=False):
    """Configure logging
    
    ロギングの設定を行う
    デバッグモードが有効な場合はDEBUGレベル、
    それ以外の場合はINFOレベルでログを出力する
    
    Args:
        debug: デバッグモードのフラグ
    """
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def print_usage():
    """Print usage information
    
    使用方法の情報を表示する
    PANAサーバー（PAA）とクライアント（PaC）の
    起動方法と主要機能を説明する
    """
    print("RFC5191 PANA Implementation")
    print("===========================")
    print("Usage: python main.py [paa|pac] [options]")
    print("")
    print("Modes:")
    print("  paa [--port PORT] [--bind ADDR] [--debug]")
    print("      Run as PANA Authentication Agent (server)")
    print("  pac <addr> [--port PORT] [--debug]")
    print("      Run as PANA Client (connect to server)")
    print("")
    print("Example:")
    print("  Terminal 1: python main.py paa --port 5555")
    print("  Terminal 2: python main.py pac 127.0.0.1 --port 5555")
    print("")
    print("Features:")
    print("  - RFC5191 compliant PANA protocol")
    print("  - Complete EAP-TLS authentication (RFC5216)")
    print("  - PRF_HMAC_SHA2_256, AUTH_HMAC_SHA2_256_128, AES128_CTR")
    print("  - Message retransmission with R-bit support")
    print("  - Session lifetime management")
    print("  - Re-authentication support")
    print("  - OpenSSL 3.x support")


def run_paa(port=716, bind_addr='0.0.0.0', debug=False):
    """Run PANA Authentication Agent
    
    PANA認証エージェント（PAA）を起動する
    サーバーモードでPANAプロトコルを実行し、
    クライアントからの認証要求を待ち受ける
    
    Args:
        port: リスニングポート番号（デフォルト: 716）
        bind_addr: バインドするIPアドレス（デフォルト: 全インターフェース）
        debug: デバッグモードのフラグ
    """
    setup_logging(debug)
    
    print("Starting PANA Authentication Agent (PAA)...")
    print(f"Listening on {bind_addr}:{port}")
    print("Press Ctrl+C to stop")
    print("")
    
    global server
    server = PANAAuthAgent(bind_addr=bind_addr, bind_port=port)
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nStopping PAA...")
        server.stop()
        print("PAA stopped.")


def run_pac(server_addr, port=716, debug=False):
    """Run PANA Client
    
    PANAクライアント（PaC）を起動する
    指定されたPAAサーバーに接続し、
    EAP-TLS認証を実行する
    
    Args:
        server_addr: PAAサーバーのIPアドレス
        port: PAAサーバーのポート番号（デフォルト: 716）
        debug: デバッグモードのフラグ
    """
    setup_logging(debug)
    
    print(f"Starting PANA Client (PaC)...")
    print(f"Connecting to PAA at {server_addr}:{port}")
    print("Press Ctrl+C to stop")
    print("")
    
    global client
    client = PANAClient(server_addr, server_port=port)
    try:
        client.run()
    except KeyboardInterrupt:
        print("\nStopping PaC...")
        client.running = False
        print("PaC stopped.")


def main():
    """Main entry point
    
    メインエントリーポイント
    コマンドライン引数を解析し、PAAまたはPaCモードで
    アプリケーションを起動する
    """
    # シグナルハンドラーを登録（適切なシャットダウンのため）
    signal.signal(signal.SIGINT, signal_handler)
    
    # コマンドライン引数を解析
    import argparse
    
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
        
    mode = sys.argv[1].lower()
    
    if mode == 'paa':
        # PAAモード: PANA認証エージェント（サーバー）として動作
        parser = argparse.ArgumentParser(prog='main.py paa')
        parser.add_argument('mode', help='Mode (paa)')
        parser.add_argument('--port', type=int, default=716, help='UDP port to listen on')
        parser.add_argument('--bind', default='0.0.0.0', help='IP address to bind to')
        parser.add_argument('--debug', action='store_true', help='Enable debug logging')
        args = parser.parse_args()
        run_paa(port=args.port, bind_addr=args.bind, debug=args.debug)
        
    elif mode == 'pac':
        # PaCモード: PANAクライアントとして動作
        parser = argparse.ArgumentParser(prog='main.py pac')
        parser.add_argument('mode', help='Mode (pac)')
        parser.add_argument('server', help='PAA server address')
        parser.add_argument('--port', type=int, default=716, help='PAA server port')
        parser.add_argument('--debug', action='store_true', help='Enable debug logging')
        args = parser.parse_args()
        run_pac(args.server, port=args.port, debug=args.debug)
    else:
        print(f"Error: Invalid mode '{mode}'. Use 'paa' or 'pac'")
        sys.exit(1)


if __name__ == "__main__":
    main()