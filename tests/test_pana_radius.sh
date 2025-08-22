#!/bin/bash
# PAC-PAA-RADIUS 統合自動テストスクリプト

echo "=== PAC-PAA-RADIUS 統合テスト ==="
echo "開始時刻: $(date)"

# 色定義
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# テスト結果
PASSED=0
FAILED=0

# タイムアウト設定
TIMEOUT=30

# ログディレクトリ
LOG_DIR="./test_logs_$(date +%Y%m%d_%H%M%S)"
mkdir -p $LOG_DIR

# PIDファイル
PID_FILE="$LOG_DIR/pids.txt"

# クリーンアップ関数
cleanup() {
    echo -e "\n${YELLOW}クリーンアップ中...${NC}"
    
    # PIDファイルから全プロセスを終了
    if [ -f "$PID_FILE" ]; then
        while read pid; do
            if kill -0 $pid 2>/dev/null; then
                sudo kill $pid 2>/dev/null
            fi
        done < "$PID_FILE"
        rm -f "$PID_FILE"
    fi
    
    # 残っているプロセスを確認
    pkill -f "python3.*pyPANA.py" 2>/dev/null
}

# エラーハンドラー
trap cleanup EXIT INT TERM

# テスト関数
run_test() {
    local test_name=$1
    local expected_log=$2
    local log_file=$3
    local timeout=${4:-10}
    
    echo -n "  $test_name ... "
    
    # タイムアウト付きでログを監視
    local count=0
    while [ $count -lt $timeout ]; do
        if grep -q "$expected_log" "$log_file" 2>/dev/null; then
            echo -e "${GREEN}PASS${NC}"
            ((PASSED++))
            return 0
        fi
        sleep 1
        ((count++))
    done
    
    echo -e "${RED}FAIL${NC} (タイムアウト)"
    echo "    期待されたログ: $expected_log"
    echo "    ログファイル: $log_file"
    ((FAILED++))
    return 1
}

# 前提条件チェック
check_prerequisites() {
    echo -e "\n${YELLOW}前提条件チェック${NC}"
    
    # Python3チェック
    if ! command -v python3 &> /dev/null; then
        echo -e "  ${RED}✗${NC} Python3がインストールされていません"
        return 1
    else
        echo -e "  ${GREEN}✓${NC} Python3: $(python3 --version)"
    fi
    
    # pyPANA.pyの存在チェック
    if [ ! -f "pyPANA.py" ]; then
        echo -e "  ${RED}✗${NC} pyPANA.pyが見つかりません"
        return 1
    else
        echo -e "  ${GREEN}✓${NC} pyPANA.py が存在します"
    fi
    
    # sudoアクセスチェック
    if ! sudo -n true 2>/dev/null; then
        echo -e "  ${YELLOW}!${NC} sudo権限が必要です。パスワードを入力してください。"
        sudo true
    fi
    
    return 0
}

# FreeRADIUSチェック（オプション）
check_freeradius() {
    echo -e "\n${YELLOW}FreeRADIUSチェック${NC}"
    
    if pgrep -x "freeradius" > /dev/null || pgrep -x "radiusd" > /dev/null; then
        echo -e "  ${GREEN}✓${NC} FreeRADIUSが実行中です"
        return 0
    else
        echo -e "  ${YELLOW}!${NC} FreeRADIUSが実行されていません"
        echo "    RADIUSプロキシテストはスキップされます"
        return 1
    fi
}

# テスト1: 基本的なPAC-PAA認証（RADIUSなし）
test_basic_authentication() {
    echo -e "\n${YELLOW}テスト1: 基本的なPAC-PAA認証（スタンドアロン）${NC}"
    
    # PAAを起動
    echo "  PAAを起動中..."
    sudo python3 pyPANA.py paa --debug > "$LOG_DIR/test1_paa.log" 2>&1 &
    local PAA_PID=$!
    echo $PAA_PID >> "$PID_FILE"
    sleep 3
    
    # PaCを起動
    echo "  PaCを起動中..."
    python3 pyPANA.py pac 127.0.0.1 --debug > "$LOG_DIR/test1_pac.log" 2>&1 &
    local PAC_PID=$!
    echo $PAC_PID >> "$PID_FILE"
    
    # テスト実行
    echo "  認証フローをテスト中..."
    
    run_test "PaC: 初期接続" "State transition: INITIAL -> WAIT_PAN_OR_PAR" "$LOG_DIR/test1_pac.log"
    run_test "PAA: PCI受信" "Received message: type=1" "$LOG_DIR/test1_paa.log"
    run_test "PaC: EAP開始" "Processing EAP message" "$LOG_DIR/test1_pac.log"
    run_test "PaC: 認証成功" "PANA authentication successful" "$LOG_DIR/test1_pac.log"
    run_test "PaC: OPEN状態" "State transition: WAIT_EAP_MSG -> OPEN" "$LOG_DIR/test1_pac.log"
    run_test "PAA: OPEN状態" "State transition: WAIT_SUCC_PAN -> OPEN" "$LOG_DIR/test1_paa.log"
    run_test "再送信クリア" "Cleared.*messages for address" "$LOG_DIR/test1_pac.log"
    
    # プロセス終了
    sleep 2
    sudo kill $PAA_PID 2>/dev/null
    kill $PAC_PID 2>/dev/null
    
    echo -e "  ${GREEN}テスト1完了${NC}"
}

# テスト2: RADIUS統合テスト
test_radius_integration() {
    echo -e "\n${YELLOW}テスト2: PAC-PAA-RADIUS統合認証${NC}"
    
    if ! check_freeradius; then
        echo "  FreeRADIUSが実行されていないため、このテストをスキップします"
        return
    fi
    
    # PAAをRADIUSプロキシモードで起動
    echo "  PAA（RADIUSプロキシ）を起動中..."
    sudo python3 pyPANA.py paa --radius-server 127.0.0.1 --radius-secret testing123 --debug > "$LOG_DIR/test2_paa.log" 2>&1 &
    local PAA_PID=$!
    echo $PAA_PID >> "$PID_FILE"
    sleep 3
    
    # PaCを起動
    echo "  PaCを起動中..."
    python3 pyPANA.py pac 127.0.0.1 --debug > "$LOG_DIR/test2_pac.log" 2>&1 &
    local PAC_PID=$!
    echo $PAC_PID >> "$PID_FILE"
    
    # テスト実行
    echo "  RADIUS統合認証フローをテスト中..."
    
    run_test "PAA: RADIUS設定" "radius_server.*127.0.0.1" "$LOG_DIR/test2_paa.log"
    run_test "PaC: 認証成功" "PANA authentication successful" "$LOG_DIR/test2_pac.log" 15
    run_test "両方向認証完了" "State transition.*OPEN" "$LOG_DIR/test2_paa.log"
    
    # プロセス終了
    sleep 2
    sudo kill $PAA_PID 2>/dev/null
    kill $PAC_PID 2>/dev/null
    
    echo -e "  ${GREEN}テスト2完了${NC}"
}

# テスト3: RFC6786暗号化テスト
test_encryption() {
    echo -e "\n${YELLOW}テスト3: RFC6786暗号化テスト${NC}"
    
    # PAAを暗号化有効で起動
    echo "  PAA（暗号化有効）を起動中..."
    sudo python3 pyPANA.py paa --enable-encryption --debug > "$LOG_DIR/test3_paa.log" 2>&1 &
    local PAA_PID=$!
    echo $PAA_PID >> "$PID_FILE"
    sleep 3
    
    # PaCを暗号化有効で起動
    echo "  PaC（暗号化有効）を起動中..."
    python3 pyPANA.py pac 127.0.0.1 --enable-encryption --debug > "$LOG_DIR/test3_pac.log" 2>&1 &
    local PAC_PID=$!
    echo $PAC_PID >> "$PID_FILE"
    
    # テスト実行
    echo "  暗号化認証フローをテスト中..."
    
    run_test "暗号化ネゴシエーション" "Encryption-Algorithm" "$LOG_DIR/test3_pac.log"
    run_test "PaC: 認証成功" "PANA authentication successful" "$LOG_DIR/test3_pac.log"
    run_test "暗号化セッション確立" "encryption.*enabled" "$LOG_DIR/test3_paa.log" 15
    
    # プロセス終了
    sleep 2
    sudo kill $PAA_PID 2>/dev/null
    kill $PAC_PID 2>/dev/null
    
    echo -e "  ${GREEN}テスト3完了${NC}"
}

# メイン実行
main() {
    # 前提条件チェック
    if ! check_prerequisites; then
        echo -e "${RED}前提条件を満たしていません。終了します。${NC}"
        exit 1
    fi
    
    # テスト実行
    test_basic_authentication
    test_radius_integration
    test_encryption
    
    # 結果サマリー
    echo -e "\n${YELLOW}=== テスト結果サマリー ===${NC}"
    echo -e "成功: ${GREEN}$PASSED${NC}"
    echo -e "失敗: ${RED}$FAILED${NC}"
    
    if [ $FAILED -eq 0 ]; then
        echo -e "\n${GREEN}すべてのテストが成功しました！${NC}"
        exit 0
    else
        echo -e "\n${RED}一部のテストが失敗しました。${NC}"
        echo "詳細はログファイルを確認してください: $LOG_DIR/"
        exit 1
    fi
}

# 実行
main