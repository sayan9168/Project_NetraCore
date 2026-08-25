#!/bin/bash
# Project Netra-Core Production Startup Script
# Version: 6.1.2

set -e

cd ~/Project_NetraCore

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

LOG_FILE="logs/server.log"
PID_FILE="logs/server.pid"

# Create logs directory
mkdir -p logs

# Check if server is already running
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo -e "${YELLOW}⚠ Server already running (PID: $PID)${NC}"
        echo "Use './stop_server.sh' to stop it first"
        exit 1
    else
        rm -f "$PID_FILE"
    fi
fi

echo -e "${GREEN}🚀 Starting Project Netra-Core v6.1.2...${NC}"
echo "Log file: $LOG_FILE"
echo ""

# Start server in background
PYTHONPATH=. ./venv/bin/python -m uvicorn src.api.main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --log-level info \
    >> "$LOG_FILE" 2>&1 &

# Save PID
SERVER_PID=$!
echo $SERVER_PID > "$PID_FILE"

echo -e "${GREEN}✓ Server started (PID: $SERVER_PID)${NC}"
echo "Waiting for startup..."

# Wait for server to be ready
MAX_WAIT=10
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if curl -s http://127.0.0.1:8000/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Server is ready!${NC}"
        echo ""
        echo "═══════════════════════════════════════════════════"
        echo "  Project Netra-Core v6.1.2 - OPERATIONAL"
        echo "═══════════════════════════════════════════════════"
        echo "  PID: $SERVER_PID"
        echo "  URL: http://127.0.0.1:8000"
        echo "  Logs: tail -f $LOG_FILE"
        echo "  Stop: ./stop_server.sh"
        echo "═══════════════════════════════════════════════════"
        exit 0
    fi
    sleep 1
    WAITED=$((WAITED + 1))
    echo "Waiting... ($WAITED/$MAX_WAIT)"
done

echo -e "${RED}✗ Server failed to start within ${MAX_WAIT} seconds${NC}"
echo "Check logs: tail -50 $LOG_FILE"
exit 1
