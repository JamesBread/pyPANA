#!/bin/bash
#
# Test script to run pyPANA PAA with OpenPANA PaC
#

echo "================================================"
echo "PyPANA PAA - OpenPANA PaC Interoperability Test"
echo "================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
PAA_PORT=5555
PAA_BIND="0.0.0.0"
PAC_SERVER="127.0.0.1"

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    
    # Kill PAA if running
    if [ ! -z "$PAA_PID" ]; then
        echo "Stopping PyPANA PAA (PID: $PAA_PID)"
        kill $PAA_PID 2>/dev/null
    fi
    
    # Kill any openpac processes
    pkill -f openpac 2>/dev/null
    
    echo -e "${GREEN}Cleanup complete${NC}"
}

# Set trap for cleanup
trap cleanup EXIT

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --port)
            PAA_PORT="$2"
            shift 2
            ;;
        --bind)
            PAA_BIND="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --port PORT    PAA listening port (default: 5555)"
            echo "  --bind ADDR    PAA bind address (default: 0.0.0.0)"
            echo "  --help         Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "Configuration:"
echo "  PAA Bind Address: $PAA_BIND"
echo "  PAA Port: $PAA_PORT"
echo "  OpenPANA PaC will connect to: $PAC_SERVER:$PAA_PORT"
echo ""

# Check if FreeRADIUS is running
echo -n "Checking FreeRADIUS status... "
if systemctl is-active --quiet freeradius; then
    echo -e "${GREEN}Running${NC}"
else
    echo -e "${YELLOW}Not running${NC}"
    echo "Note: Authentication may fail without RADIUS backend"
fi

# Start PyPANA PAA
echo ""
echo -e "${GREEN}Starting PyPANA PAA...${NC}"
python3 test_pypana_paa_openpana.py --bind "$PAA_BIND" --port "$PAA_PORT" &
PAA_PID=$!

# Wait for PAA to start
sleep 2

# Check if PAA is running
if ! kill -0 $PAA_PID 2>/dev/null; then
    echo -e "${RED}Failed to start PyPANA PAA${NC}"
    exit 1
fi

echo -e "${GREEN}PyPANA PAA started (PID: $PAA_PID)${NC}"
echo ""

# Give user time to see PAA started
sleep 1

# Start OpenPANA PaC
echo -e "${GREEN}Starting OpenPANA PaC...${NC}"
echo "Command: openpac -i $PAC_SERVER -p $PAA_PORT -t eap-tls"
echo ""

# Create a timeout wrapper for openpac
timeout 30 openpac -i "$PAC_SERVER" -p "$PAA_PORT" -t eap-tls 2>&1 | while IFS= read -r line; do
    # Filter and color the output
    if [[ "$line" == *"Tx PCI"* ]]; then
        echo -e "${GREEN}[PaC → PAA] Sent PCI${NC}"
    elif [[ "$line" == *"Rx PAR"* ]]; then
        echo -e "${YELLOW}[PaC ← PAA] Received PAR${NC}"
    elif [[ "$line" == *"Tx PAN"* ]]; then
        echo -e "${GREEN}[PaC → PAA] Sent PAN${NC}"
    elif [[ "$line" == *"OPEN state"* ]] || [[ "$line" == *"EAP Success"* ]]; then
        echo -e "${GREEN}✓ Authentication Successful!${NC}"
    elif [[ "$line" == *"ERROR"* ]] || [[ "$line" == *"FAILED"* ]]; then
        echo -e "${RED}✗ $line${NC}"
    elif [[ "$line" == *"Session Id"* ]]; then
        echo -e "${YELLOW}$line${NC}"
    else
        # Show debug lines in dim text
        echo "$line"
    fi
done

PAC_EXIT=$?

echo ""
echo "================================================"
echo "Test Results:"
echo "================================================"

if [ $PAC_EXIT -eq 0 ]; then
    echo -e "${GREEN}✓ OpenPANA PaC completed successfully${NC}"
else
    echo -e "${YELLOW}⚠ OpenPANA PaC exited with code: $PAC_EXIT${NC}"
fi

# Wait a moment to see final PAA logs
sleep 2

# Show PAA statistics
echo ""
echo "Fetching PAA statistics..."
kill -USR1 $PAA_PID 2>/dev/null || true
sleep 1

echo ""
echo -e "${GREEN}Test complete!${NC}"
echo ""
echo "Notes:"
echo "1. Check the PAA output above for session statistics"
echo "2. If authentication failed, verify FreeRADIUS configuration"
echo "3. OpenPANA PaC expects EAP-TLS authentication"
echo ""