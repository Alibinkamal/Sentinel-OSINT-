#!/usr/bin/env bash
# Sentinel OSINT launcher (macOS / Linux)
set -e
cd "$(dirname "$0")"
echo "Installing dependencies..."
pip install -r backend/requirements.txt
echo "Starting Sentinel OSINT on http://127.0.0.1:8000"
echo "(the first-run admin password is printed once in this terminal)"
python run.py
