#!/bin/bash
# Project Netra-Core Graceful Shutdown Script

cd ~/Project_NetraCore

PID_FILE="logs/server.pid"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ ! -f "$PID_FILE" ]; then
    echo -e "${YELLOW}⚠ No PID file found. Server may not be running.${NC}"
    exit 0
fi

PID=$(cat "$PID_FILE")

if ! ps -p "$PID" > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠ Process $PID not found. Cleaning up PID file.${NC}"
    rm -f "$PID_FILE"
    exit 0
fi

echo -e "${YELLOW}⏹ Stopping server (PID: $PID)...${NC}"

# Graceful shutdown (SIGTERM)
kill -TERM "$PID" 2>/dev/null

# Wait for process to stop
MAX_WAIT=10
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if ! ps -p "$PID" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Server stopped gracefully${NC}"
        rm -f "$PID_FILE"
        exit 0
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done

# Force kill if still running
echo -e "${RED}⚠ Force killing server...${NC}"
kill -9 "$PID" 2>/dev/null
rm -f "$PID_FILE"
echo -e "${GREEN}✓ Server stopped${NC}"
