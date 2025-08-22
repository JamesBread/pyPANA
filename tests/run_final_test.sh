#!/bin/bash

echo "=== Final OpenPANA Interoperability Test ==="
echo "Testing pyPANA PAA with OpenPANA PaC"
echo "============================================"

# Clean up
pkill -f test_final_openpana 2>/dev/null
pkill -f openpac 2>/dev/null
sleep 1

# Start PAA
echo -e "\n1. Starting pyPANA PAA (OpenPANA-compatible)..."
python3 test_final_openpana.py --bind 127.0.0.1 --port 5555 &
PAA_PID=$!
sleep 2

if kill -0 $PAA_PID 2>/dev/null; then
    echo "   PAA started successfully (PID: $PAA_PID)"
else
    echo "   PAA failed to start"
    exit 1
fi

# Run OpenPANA PaC
echo -e "\n2. Running OpenPANA PaC..."
timeout 10 openpac -i 127.0.0.1 -p 5555 -t eap-tls 2>&1 | tee openpac_final.log | grep -E "Tx|Rx|state:" &
OPENPAC_PID=$!

# Wait a bit
sleep 8

# Kill processes
kill $PAA_PID $OPENPAC_PID 2>/dev/null

echo -e "\n3. Test Results:"
echo "   Check openpac_final.log for full output"
echo "============================================"