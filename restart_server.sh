#!/bin/bash
# Project Netra-Core Restart Script

echo "Restarting Project Netra-Core..."
./stop_server.sh
sleep 2
./start_server.sh
