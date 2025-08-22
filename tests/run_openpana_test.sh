#!/bin/bash

# OpenPANA Interoperability Test Runner
# This script runs the pyPANA PaC client against OpenPANA PAA

echo "============================================"
echo "OpenPANA Interoperability Test"
echo "============================================"
echo ""
echo "This script will test pyPANA PaC against OpenPANA PAA"
echo "Make sure OpenPANA PAA is running at 127.0.0.1:5555"
echo ""

# Default configuration
SERVER_ADDR="127.0.0.1"
SERVER_PORT="5555"
TLS_VERSION="1.0"
DEBUG=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --server)
            SERVER_ADDR="$2"
            shift 2
            ;;
        --port)
            SERVER_PORT="$2"
            shift 2
            ;;
        --debug)
            DEBUG="--debug"
            shift
            ;;
        --ca-cert)
            CA_CERT="--ca-cert $2"
            shift 2
            ;;
        --client-cert)
            CLIENT_CERT="--client-cert $2"
            shift 2
            ;;
        --client-key)
            CLIENT_KEY="--client-key $2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--server ADDR] [--port PORT] [--debug] [--ca-cert FILE] [--client-cert FILE] [--client-key FILE]"
            exit 1
            ;;
    esac
done

echo "Configuration:"
echo "  PAA Server: ${SERVER_ADDR}:${SERVER_PORT}"
echo "  TLS Version: ${TLS_VERSION}"
if [ ! -z "$CA_CERT" ]; then
    echo "  CA Certificate: Provided"
fi
if [ ! -z "$CLIENT_CERT" ]; then
    echo "  Client Certificate: Provided"
fi
echo ""
echo "Starting pyPANA PaC client..."
echo "Press Ctrl+C to stop"
echo "--------------------------------------------"
echo ""

# Run the test
python3 test_openpana_interop.py \
    --server-addr "$SERVER_ADDR" \
    --server-port "$SERVER_PORT" \
    --tls-version "$TLS_VERSION" \
    $DEBUG \
    $CA_CERT \
    $CLIENT_CERT \
    $CLIENT_KEY