#!/bin/bash
# FreeRADIUS設定セットアップスクリプト

echo "=== FreeRADIUS設定セットアップ ==="

# 色定義
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# 設定ディレクトリ
CERT_DIR="$HOME/pana-radius-certs"
CONFIG_DIR="./freeradius-config"

# 証明書生成
generate_certificates() {
    echo -e "\n${YELLOW}証明書を生成中...${NC}"
    
    mkdir -p "$CERT_DIR"
    cd "$CERT_DIR"
    
    # CA証明書の生成
    echo "  CA証明書を生成中..."
    openssl genrsa -out ca.key 2048
    openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
        -subj "/C=JP/ST=Tokyo/L=Tokyo/O=PANA Test/CN=PANA Test CA"
    
    # サーバー証明書の生成
    echo "  サーバー証明書を生成中..."
    openssl genrsa -out server.key 2048
    openssl req -new -key server.key -out server.csr \
        -subj "/C=JP/ST=Tokyo/L=Tokyo/O=PANA Test/CN=radius.example.com"
    openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out server.crt
    
    # クライアント証明書の生成
    echo "  クライアント証明書を生成中..."
    openssl genrsa -out client.key 2048
    openssl req -new -key client.key -out client.csr \
        -subj "/C=JP/ST=Tokyo/L=Tokyo/O=PANA Test/CN=user@example.com"
    openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out client.crt
    
    # DHパラメータの生成
    echo "  DHパラメータを生成中（時間がかかります）..."
    openssl dhparam -out dh 2048
    
    # 証明書の検証
    echo -e "\n  証明書を検証中..."
    openssl verify -CAfile ca.crt server.crt
    openssl verify -CAfile ca.crt client.crt
    
    echo -e "${GREEN}証明書の生成が完了しました: $CERT_DIR${NC}"
    
    cd - > /dev/null
}

# FreeRADIUS設定ファイルの生成
generate_config_files() {
    echo -e "\n${YELLOW}FreeRADIUS設定ファイルを生成中...${NC}"
    
    mkdir -p "$CONFIG_DIR"
    
    # clients.conf
    cat > "$CONFIG_DIR/clients.conf" << 'EOF'
# PANA PAA用クライアント設定
client pana-paa {
    ipaddr = 127.0.0.1
    secret = testing123
    require_message_authenticator = no
    shortname = pana-paa
}

# ローカルホスト（テスト用）
client localhost {
    ipaddr = 127.0.0.1
    secret = testing123
    require_message_authenticator = no
    nas_type = other
}
EOF
    
    # users
    cat > "$CONFIG_DIR/users" << 'EOF'
# EAP-TLS用ユーザー
user@example.com    Cleartext-Password := "unused"
                    Reply-Message := "Welcome PANA User",
                    Session-Timeout := 3600

# テスト用ユーザー（PAP）
testuser    Cleartext-Password := "testpass"
            Reply-Message := "Test User"
EOF
    
    # eap設定
    cat > "$CONFIG_DIR/eap" << EOF
eap {
    default_eap_type = tls
    timer_expire = 60
    ignore_unknown_eap_types = no
    cisco_accounting_username_bug = no
    max_sessions = \${max_requests}

    # TLS設定
    tls-config tls-common {
        private_key_password = 
        private_key_file = $CERT_DIR/server.key
        certificate_file = $CERT_DIR/server.crt
        ca_file = $CERT_DIR/ca.crt
        dh_file = $CERT_DIR/dh
        ca_path = \${cadir}
        
        cipher_list = "DEFAULT"
        cipher_server_preference = no
        
        # TLSバージョン設定
        tls_min_version = "1.2"
        tls_max_version = "1.2"
        
        ecdh_curve = "prime256v1"
        
        cache {
            enable = no
            lifetime = 24
            max_entries = 255
        }
        
        verify {
            # クライアント証明書の検証をスキップ（テスト用）
            # 本番環境では適切に設定すること
        }
        
        ocsp {
            enable = no
            override_cert_url = yes
            url = "http://127.0.0.1/ocsp/"
        }
    }

    # EAP-TLS
    tls {
        tls = tls-common
        # MSKを適切に生成
        virtual_server = default
    }
}
EOF
    
    echo -e "${GREEN}設定ファイルの生成が完了しました: $CONFIG_DIR${NC}"
}

# インストール手順の表示
show_installation_instructions() {
    echo -e "\n${YELLOW}=== FreeRADIUSインストール手順 ===${NC}"
    
    echo -e "\n${YELLOW}macOS:${NC}"
    echo "  brew install freeradius-server"
    
    echo -e "\n${YELLOW}Ubuntu/Debian:${NC}"
    echo "  sudo apt-get update"
    echo "  sudo apt-get install freeradius freeradius-utils"
    
    echo -e "\n${YELLOW}CentOS/RHEL:${NC}"
    echo "  sudo yum install freeradius freeradius-utils"
    
    echo -e "\n${YELLOW}設定ファイルのコピー:${NC}"
    echo "  設定ファイルの場所は環境により異なります："
    echo "  - /etc/freeradius/3.0/ (Debian/Ubuntu)"
    echo "  - /etc/raddb/ (CentOS/RHEL)"
    echo "  - /usr/local/etc/raddb/ (macOS/Homebrew)"
    
    echo -e "\n  ${YELLOW}例（Ubuntu）:${NC}"
    echo "  sudo cp $CONFIG_DIR/clients.conf /etc/freeradius/3.0/"
    echo "  sudo cp $CONFIG_DIR/users /etc/freeradius/3.0/"
    echo "  sudo cp $CONFIG_DIR/eap /etc/freeradius/3.0/mods-available/"
    echo "  sudo ln -s ../mods-available/eap /etc/freeradius/3.0/mods-enabled/"
    
    echo -e "\n${YELLOW}FreeRADIUSの起動:${NC}"
    echo "  デバッグモード: sudo freeradius -X"
    echo "  サービス起動: sudo systemctl start freeradius"
}

# メイン処理
main() {
    echo "このスクリプトはFreeRADIUS用の証明書と設定ファイルを生成します。"
    echo -n "続行しますか？ (y/n): "
    read -r response
    
    if [[ "$response" != "y" && "$response" != "Y" ]]; then
        echo "キャンセルしました。"
        exit 0
    fi
    
    # 証明書の生成
    if [ -d "$CERT_DIR" ]; then
        echo -e "${YELLOW}証明書ディレクトリが既に存在します: $CERT_DIR${NC}"
        echo -n "再生成しますか？ (y/n): "
        read -r response
        if [[ "$response" == "y" || "$response" == "Y" ]]; then
            rm -rf "$CERT_DIR"
            generate_certificates
        fi
    else
        generate_certificates
    fi
    
    # 設定ファイルの生成
    generate_config_files
    
    # インストール手順の表示
    show_installation_instructions
    
    echo -e "\n${GREEN}セットアップが完了しました！${NC}"
    echo "生成されたファイル:"
    echo "  - 証明書: $CERT_DIR/"
    echo "  - 設定ファイル: $CONFIG_DIR/"
}

# 実行
main