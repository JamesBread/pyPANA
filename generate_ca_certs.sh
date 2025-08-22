#!/bin/bash
# Generate proper CA and certificates for EAP-TLS testing
# This creates a CA, server cert, and client cert with proper extensions

set -e

CERT_DIR="certs"
mkdir -p "$CERT_DIR"

echo "========================================"
echo "  Generating CA and Certificates"
echo "========================================"

# 1. Generate CA private key
echo -e "\n1. Generating CA private key..."
openssl genrsa -out "$CERT_DIR/ca.key" 2048

# 2. Generate CA certificate with proper extensions
echo -e "\n2. Generating CA certificate..."
cat > "$CERT_DIR/ca.conf" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = US
ST = Test State
L = Test City
O = PANA Test CA
CN = PANA Test Root CA

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.pem" -config "$CERT_DIR/ca.conf"

echo "CA Certificate:"
openssl x509 -in "$CERT_DIR/ca.pem" -noout -subject

# 3. Generate server private key
echo -e "\n3. Generating server private key..."
openssl genrsa -out "$CERT_DIR/server.key" 2048

# 4. Generate server CSR
echo -e "\n4. Generating server certificate request..."
cat > "$CERT_DIR/server.conf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Test State
L = Test City
O = PANA Test
CN = pana-server.local

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = pana-server.local
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -new -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" -config "$CERT_DIR/server.conf"

# 5. Sign server certificate with CA
echo -e "\n5. Signing server certificate with CA..."
cat > "$CERT_DIR/server_sign.conf" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:pana-server.local,DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/server.pem" \
    -days 365 -extfile "$CERT_DIR/server_sign.conf"

echo "Server Certificate:"
openssl x509 -in "$CERT_DIR/server.pem" -noout -subject

# 6. Generate client private key
echo -e "\n6. Generating client private key..."
openssl genrsa -out "$CERT_DIR/client.key" 2048

# 7. Generate client CSR
echo -e "\n7. Generating client certificate request..."
cat > "$CERT_DIR/client.conf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Test State
L = Test City
O = PANA Test
CN = pana-client@example.com

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl req -new -key "$CERT_DIR/client.key" \
    -out "$CERT_DIR/client.csr" -config "$CERT_DIR/client.conf"

# 8. Sign client certificate with CA
echo -e "\n8. Signing client certificate with CA..."
cat > "$CERT_DIR/client_sign.conf" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl x509 -req -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/client.pem" \
    -days 365 -extfile "$CERT_DIR/client_sign.conf"

echo "Client Certificate:"
openssl x509 -in "$CERT_DIR/client.pem" -noout -subject

# 9. Verify certificates
echo -e "\n9. Verifying certificate chain..."
echo -n "Server certificate: "
openssl verify -CAfile "$CERT_DIR/ca.pem" "$CERT_DIR/server.pem"

echo -n "Client certificate: "
openssl verify -CAfile "$CERT_DIR/ca.pem" "$CERT_DIR/client.pem"

# 10. Display certificate details
echo -e "\n10. Certificate Details:"
echo "========================================"
echo "CA Certificate:"
openssl x509 -in "$CERT_DIR/ca.pem" -noout -text | grep -E "Subject:|Issuer:|Not Before|Not After|CA:TRUE|keyUsage" | head -10

echo -e "\nServer Certificate:"
openssl x509 -in "$CERT_DIR/server.pem" -noout -text | grep -E "Subject:|Issuer:|Not Before|Not After|CA:FALSE|keyUsage|DNS:|IP:" | head -10

echo -e "\nClient Certificate:"
openssl x509 -in "$CERT_DIR/client.pem" -noout -text | grep -E "Subject:|Issuer:|Not Before|Not After|CA:FALSE|keyUsage" | head -10

echo -e "\n========================================"
echo "  Certificate Generation Complete!"
echo "========================================"
echo "Generated files in $CERT_DIR/:"
echo "  ca.pem     - Root CA certificate"
echo "  ca.key     - Root CA private key"
echo "  server.pem - Server certificate (signed by CA)"
echo "  server.key - Server private key"
echo "  client.pem - Client certificate (signed by CA)"
echo "  client.key - Client private key"
echo ""
echo "These certificates are now ready for production-mode testing!"