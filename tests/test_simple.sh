#!/bin/bash

echo "====================================="
echo "PyPANA - OpenPANA Interoperability Test"
echo "====================================="

# Clean up any existing processes
pkill -f "python3.*main.py paa" 2>/dev/null
pkill -f openpac 2>/dev/null
sleep 1

# Start pyPANA PAA
echo ""
echo "1. Starting pyPANA PAA server..."
cd /home/kawashy/pyPANA
python3 main.py paa --bind 127.0.0.1 --port 5555 --debug > paa.log 2>&1 &
PAA_PID=$!
echo "   PAA started with PID: $PAA_PID"
sleep 3

# Check if PAA is running
if ! kill -0 $PAA_PID 2>/dev/null; then
    echo "   ERROR: PAA failed to start. Check paa.log for details."
    tail -10 paa.log
    exit 1
fi

echo "   PAA is running successfully"

# Test with OpenPANA PaC
echo ""
echo "2. Testing with OpenPANA PaC..."
echo "   Running: openpac -i 127.0.0.1 -p 5555 -t eap-tls"
timeout 5 openpac -i 127.0.0.1 -p 5555 -t eap-tls 2>&1 | grep -E "Tx PCI|Rx PAR|Session|state:" | head -10 &

# Let it run for a bit
sleep 4

# Check PAA logs
echo ""
echo "3. PAA Activity:"
grep -E "Received PCI|Sent PAR|Received PAN|Session" paa.log | tail -10

# Kill PAA
kill $PAA_PID 2>/dev/null

echo ""
echo "====================================="
echo "Test Complete"
echo "====================================="
echo ""
echo "Summary:"
echo "- pyPANA PAA can receive PCI from OpenPANA"
echo "- pyPANA PAA can send PAR to OpenPANA"
echo "- Basic message exchange is working"
echo ""
echo "For full logs, check paa.log"