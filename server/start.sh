#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python3 -m pip install flask flask-limiter werkzeug -q
echo "[*] Starting C3PO NODE SERVER on http://0.0.0.0:9000"
python3 c3po_server.py
