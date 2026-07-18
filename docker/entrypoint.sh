#!/bin/sh
set -eu

mkdir -p "${VPNGATE_DATA_DIR}"

exec python3 /app/vpngate_manager.py
