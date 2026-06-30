#!/usr/bin/env bash
# Cyber Brand Monitoring Agent — one-command launcher.
set -u
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
    echo "[run] No .venv found — creating one..."
    python3 -m venv .venv
fi

source .venv/bin/activate

echo "[run] Running scan against PROTECTED_DOMAIN (see brand_monitor/config.py)..."
python3 -m brand_monitor.agent
