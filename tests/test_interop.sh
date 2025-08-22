#!/bin/bash

# Clean up
pkill -f test_pypana_paa_openpana 2>/dev/null
pkill -f openpac 2>/dev/null
sleep 1

# Start PAA in background
echo "Starting PyPANA PAA on port 5555..."
python3 test_pypana_paa_openpana.py --bind 127.0.0.1 --port 5555 > paa_output.txt 2>&1 &
PAA_PID=$!
echo "PAA PID: $PAA_PID"
sleep 3

# Start OpenPANA PaC
echo "Starting OpenPANA PaC..."
timeout 10 openpac -i 127.0.0.1 -p 5555 -t eap-tls > pac_output.txt 2>&1 &
PAC_PID=$!

# Wait and monitor
sleep 8

# Kill processes
kill $PAA_PID $PAC_PID 2>/dev/null

echo ""
echo "=== PAA Output ==="
grep -E "INFO|ERROR|WARNING" paa_output.txt | tail -20

echo ""
echo "=== PaC Key Events ==="
grep -E "Tx PCI|Rx PAR|Tx PAN|Session" pac_output.txt | head -10

echo ""
echo "=== Test Complete ====="