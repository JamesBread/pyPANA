#!/bin/bash

echo "========================================"
echo "pyPANA - OpenPANA Interoperability Test"
echo "========================================"
echo ""

# Clean up
pkill -f "python3.*555" 2>/dev/null
pkill -f openpac 2>/dev/null
sleep 1

echo "1. Starting pyPANA PAA on port 5555..."
python3 test_interop_simple.py 5555 > paa_interop.log 2>&1 &
PAA_PID=$!
echo "   PAA PID: $PAA_PID"
sleep 2

echo ""
echo "2. Running OpenPANA PaC..."
echo "   (OpenPANA seems to ignore -p flag and uses 5555)"
echo ""

# Run OpenPANA and capture everything
timeout 10 openpac -i 127.0.0.1 -p 5555 -t eap-tls > openpac_full.log 2>&1 &
OPENPAC_PID=$!

# Monitor for a bit
sleep 8

# Kill processes
kill $PAA_PID 2>/dev/null
kill $OPENPAC_PID 2>/dev/null

echo "3. Results:"
echo ""
echo "=== OpenPANA PaC Summary ==="
grep -E "Tx PCI|Rx PAR|Rx PAN|Session ID:|state changed|SUCCESS|FAILED" openpac_full.log | head -20 || echo "No relevant messages found"

echo ""
echo "=== pyPANA PAA Activity ==="
cat paa_interop.log 2>/dev/null || echo "No PAA log found"

echo ""
echo "========================================"
echo "Test Complete"
echo "========================================"